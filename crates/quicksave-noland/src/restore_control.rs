// SPDX-License-Identifier: GPL-3.0-only
//! Native consent/vault adapter for the full No Land restore pipeline.
//!
//! New code; engine integration derives from No Land
//! e81238a7536aae201540956ce76981364fd36595. This module does not read a vault,
//! source application state, production provider, or repository key by itself.
use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use anyhow::{ensure, Context, Result};
use noland_restore::{
    NativeConflictMode, NativeExpectedGate, NativeObjectId, NativeRecoveryAuthority,
    NativeRestoreControl, NativeRestorePreview,
};
use noland_state_agent::{
    native_host::{validate_native_relative, NativeFileKey},
    StateAgent,
};
use noland_state_core::native_layout::{
    logical_root_map, native_restore_layout, native_root_layouts, project_native_root_layouts,
};
use noland_state_core::{BundleManifest, RestoreMode, StateError};
use quicksave_platform::SafeRoot;
use quicksave_state::ProviderAccess;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use uuid::Uuid;

/// The callback stays native-private and is supplied by the state/vault owner.
/// It must use the device state secret, not the cloud repository master key.
pub type DeviceRecoveryMac = Arc<dyn Fn(&[u8]) -> Result<[u8; 32]> + Send + Sync>;
pub type RestoreConsentGate = Arc<dyn Fn() -> Result<()> + Send + Sync>;

struct VaultAuthority(DeviceRecoveryMac);

impl NativeRecoveryAuthority for VaultAuthority {
    fn mac(&self, bytes: &[u8]) -> noland_state_core::Result<[u8; 32]> {
        self.0(bytes).map_err(|_| {
            StateError::Conflict("device-vault restore recovery authority is unavailable".into())
        })
    }
}

/// Persist only in native state, never as an incoming UI authorization. The
/// complete typed plan is MAC-bound; a checksum/digest alone is not authority.
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AuthenticatedRestorePlan {
    pub preview: NativeRestorePreview,
    pub device_mac: [u8; 32],
}

pub struct NativeRestoreController {
    authority: Arc<dyn NativeRecoveryAuthority>,
    previews: Mutex<BTreeMap<Uuid, Arc<FrozenPreview>>>,
}

const PREVIEW_TTL: Duration = Duration::from_secs(600);
const MAX_PREVIEWS: usize = 64;

struct FrozenPreview {
    preview: Arc<NativeRestorePreview>,
    provider_id: String,
    created: Instant,
    fingerprint: String,
    summary: Value,
    requires_overwrite_acknowledgement: bool,
    metadata_bytes: usize,
}

#[derive(Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct RestorePreviewRoot {
    pub path: PathBuf,
}

#[derive(Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct FrozenRestorePreviewScope {
    pub preview_id: Uuid,
    pub summary: Value,
    pub requires_overwrite_acknowledgement: bool,
    pub roots: Vec<RestorePreviewRoot>,
    pub provider_id: String,
    pub app_id: String,
    pub bundle_id: Uuid,
    pub frozen_plan_fingerprint: String,
}

/// Native-only return value; never deserialize this capability from IPC.
pub struct ApprovedNativeRestore {
    pub preview_id: Uuid,
    pub provider_id: String,
    pub job_id: Uuid,
    pub app_id: String,
    pub bundle_id: Uuid,
    pub destination: PathBuf,
    pub destination_identity: NativeObjectId,
    pub file_keys: Vec<NativeFileKey>,
    pub frozen_plan_fingerprint: String,
    pub control: Arc<NativeRestoreControl>,
}

#[derive(Serialize)]
#[serde(deny_unknown_fields)]
pub struct AuthenticatedRestorePlanRef<'a> {
    pub preview: &'a NativeRestorePreview,
    pub device_mac: [u8; 32],
}

impl NativeRestoreController {
    pub fn new(mac: DeviceRecoveryMac) -> Self {
        Self {
            authority: Arc::new(VaultAuthority(mac)),
            previews: Mutex::new(BTreeMap::new()),
        }
    }

    pub fn conflict_mode(mode: &str) -> Result<NativeConflictMode> {
        Ok(match mode {
            "create_new" => NativeConflictMode::CreateOnly,
            "merge" => NativeConflictMode::Merge,
            "replace" => NativeConflictMode::Overwrite,
            _ => anyhow::bail!("restore mode must be create_new, merge, or replace"),
        })
    }

    /// `preview.job_id` is the frozen source operation ID. NativeEngine must
    /// submit that ID as client_operation_id, not allocate a different job at
    /// download time. No credentials or mutable mappings are accepted here.
    pub fn freeze_preview(
        &self,
        provider_id: &str,
        preview: NativeRestorePreview,
    ) -> Result<FrozenRestorePreviewScope> {
        ensure!(
            !provider_id.is_empty() && provider_id.len() <= 128,
            "invalid restore provider identity"
        );
        preview
            .validate_native_destination()
            .map_err(source_error)?;
        let preview_id = Uuid::new_v4();
        let (digest, metadata_bytes) = preview.digest_and_size().map_err(source_error)?;
        let mut hasher = blake3::Hasher::new();
        hasher.update(b"QuickSave frozen native restore ticket v1\0");
        hasher.update(&(provider_id.len() as u64).to_le_bytes());
        hasher.update(provider_id.as_bytes());
        hasher.update(preview_id.as_bytes());
        hasher.update(digest.as_bytes());
        let requires_overwrite_acknowledgement = preview
            .entries
            .iter()
            .chain(&preview.tombstones)
            .any(|entry| {
                matches!(
                    entry.action,
                    noland_restore::NativeRestoreAction::Replace
                        | noland_restore::NativeRestoreAction::Remove
                        | noland_restore::NativeRestoreAction::Metadata
                )
            })
            || preview
                .root_entries
                .iter()
                .any(|entry| entry.action == noland_restore::NativeRestoreAction::Metadata);
        let logical_bytes = preview.entries.iter().try_fold(0u64, |sum, entry| {
            sum.checked_add(entry.size)
                .ok_or_else(|| anyhow::anyhow!("restore logical byte count overflow"))
        })?;
        let summary = json!({
            "operationId":preview.job_id,"fileCount":preview.entries.len(),
            "logicalBytes":logical_bytes,"tombstoneCount":preview.tombstones.len(),
            "conflictCount":preview.entries.iter().chain(&preview.tombstones).chain(&preview.root_entries).filter(|entry| entry.action == noland_restore::NativeRestoreAction::Conflict).count(),
            "replacementCount":preview.entries.iter().filter(|entry| entry.action == noland_restore::NativeRestoreAction::Replace).count(),
            "metadataChangeCount":preview.entries.iter().chain(&preview.root_entries).filter(|entry| entry.action == noland_restore::NativeRestoreAction::Metadata).count(),
            "rootChanges":preview.root_entries.iter().map(|entry| json!({
                "destinationRelative":entry.destination_relative,"kind":"directory",
                "action":entry.action,"requestedMode":entry.mode,"requestedMtimeNs":entry.mtime_ns,
                "requestedUid":entry.uid,"requestedGid":entry.gid,
            })).collect::<Vec<_>>(),
            "mode":match preview.conflict_mode { NativeConflictMode::CreateOnly=>"create_new",NativeConflictMode::Merge=>"merge",NativeConflictMode::Overwrite=>"replace" },
            "expiresInSeconds":PREVIEW_TTL.as_secs(),
            "selectionKind":if preview.entire_manifest {"full_manifest"} else {"selected_files"},
            "sourceFullScope":preview.source_full_scope,
            "sourceAppName":preview.source_app_name,
            "rootMappingFingerprint":preview.root_mapping_digest().map_err(source_error)?,
            "reconstruction":if preview.root_layout.is_some() {"authenticated_native_layout"} else {"legacy_files_only"},
            "sourcePlatform":preview.root_layout.as_ref().map(|layout| layout.platform),
            "platformCompatible":preview.root_layout.as_ref().is_some_and(|layout| layout.platform.is_current()),
            "readiness":if preview.reconstruction_eligible() {
                "reconstruction_unverified"
            } else {"files_only"},
        });
        let frozen = Arc::new(FrozenPreview {
            preview: Arc::new(preview),
            provider_id: provider_id.into(),
            created: Instant::now(),
            fingerprint: hasher.finalize().to_hex().to_string(),
            summary,
            requires_overwrite_acknowledgement,
            metadata_bytes,
        });
        let scope = Self::scope(preview_id, &frozen);
        let mut previews = self
            .previews
            .lock()
            .map_err(|_| anyhow::anyhow!("native restore preview lock poisoned"))?;
        previews.retain(|_, preview| preview.created.elapsed() < PREVIEW_TTL);
        ensure!(
            previews.len() < MAX_PREVIEWS,
            "native restore preview capacity reached"
        );
        let total_metadata = previews
            .values()
            .try_fold(metadata_bytes, |total, preview| {
                total.checked_add(preview.metadata_bytes).ok_or_else(|| {
                    anyhow::anyhow!("native restore preview metadata accounting overflow")
                })
            })?;
        ensure!(
            total_metadata <= noland_restore::MAX_NATIVE_RESTORE_METADATA,
            "native restore preview cache exceeds its aggregate 512 MiB metadata budget"
        );
        previews.insert(preview_id, frozen);
        Ok(scope)
    }

    fn retained_preview(&self, preview_id: Uuid) -> Result<Arc<FrozenPreview>> {
        let preview = self
            .previews
            .lock()
            .map_err(|_| anyhow::anyhow!("native restore preview lock poisoned"))?
            .get(&preview_id)
            .cloned()
            .ok_or_else(|| anyhow::anyhow!("restore preview is unavailable; preview again"))?;
        ensure!(
            preview.created.elapsed() < PREVIEW_TTL,
            "restore preview expired; preview again"
        );
        Ok(preview)
    }

    fn scope(preview_id: Uuid, frozen: &FrozenPreview) -> FrozenRestorePreviewScope {
        FrozenRestorePreviewScope {
            preview_id,
            summary: frozen.summary.clone(),
            requires_overwrite_acknowledgement: frozen.requires_overwrite_acknowledgement,
            roots: vec![RestorePreviewRoot {
                path: frozen.preview.destination.clone(),
            }],
            provider_id: frozen.provider_id.clone(),
            app_id: frozen.preview.app_id.as_str().into(),
            bundle_id: frozen.preview.bundle_id,
            frozen_plan_fingerprint: frozen.fingerprint.clone(),
        }
    }

    /// Approval-scope query: TTL + pinned native identities only. No vault,
    /// repository, credential, rclone or provider I/O is performed.
    pub fn preview_scope(&self, preview_id: Uuid) -> Result<FrozenRestorePreviewScope> {
        let frozen = self.retained_preview(preview_id)?;
        frozen
            .preview
            .validate_native_destination()
            .map_err(source_error)?;
        Ok(Self::scope(preview_id, &frozen))
    }

    pub fn frozen_preview_page(
        &self,
        preview_id: Uuid,
        offset: usize,
        limit: usize,
    ) -> Result<Value> {
        let frozen = self.retained_preview(preview_id)?;
        Self::preview_page(preview_id, &frozen.preview, offset, limit)
    }

    pub fn approve_preview(
        &self,
        preview_id: Uuid,
        overwrite_acknowledgement: bool,
        gate: RestoreConsentGate,
    ) -> Result<ApprovedNativeRestore> {
        let frozen = self.retained_preview(preview_id)?;
        frozen
            .preview
            .validate_native_destination()
            .map_err(source_error)?;
        ensure!(
            !frozen.requires_overwrite_acknowledgement || overwrite_acknowledgement,
            "this exact restore preview requires overwrite acknowledgement"
        );
        let expected_gate: NativeExpectedGate = Arc::new(move || {
            gate().map_err(|_| {
                StateError::Conflict("native restore consent/state/provider binding changed".into())
            })
        });
        let control = Arc::new(
            NativeRestoreControl::approve_shared(
                Arc::clone(&frozen.preview),
                Arc::clone(&self.authority),
                expected_gate,
            )
            .map_err(source_error)?,
        );
        Ok(ApprovedNativeRestore {
            preview_id,
            provider_id: frozen.provider_id.clone(),
            job_id: frozen.preview.job_id,
            app_id: frozen.preview.app_id.as_str().into(),
            bundle_id: frozen.preview.bundle_id,
            destination: frozen.preview.destination.clone(),
            destination_identity: frozen.preview.destination_identity,
            file_keys: frozen
                .preview
                .entries
                .iter()
                .map(|entry| NativeFileKey {
                    logical_root: entry.logical_root.clone(),
                    relative_path: entry.relative_path.clone(),
                })
                .collect(),
            frozen_plan_fingerprint: frozen.fingerprint.clone(),
            control,
        })
    }

    pub fn authenticated_plan_ref<'a>(
        &self,
        control: &'a NativeRestoreControl,
    ) -> Result<AuthenticatedRestorePlanRef<'a>> {
        Ok(AuthenticatedRestorePlanRef {
            preview: control.preview(),
            device_mac: self
                .authority
                .mac(&plan_message(control.preview())?)
                .map_err(source_error)?,
        })
    }

    pub fn recover_authenticated(
        &self,
        agent: &StateAgent,
        plan: AuthenticatedRestorePlan,
        gate: RestoreConsentGate,
    ) -> Result<Vec<noland_restore::NativeRestoreRecoveryReport>> {
        let control = self.reattach(plan, gate)?;
        let job_id = control.preview().job_id;
        self.install(agent, control)?;
        agent.native_recover_restore(job_id).map_err(source_error)
    }

    /// Freeze the already-authenticated source manifest in place. Whole-app and
    /// subset restores both use exact entry keys, never a retry-time wildcard.
    /// Native download is additive: tombstones are not local deletion consent.
    pub fn select_manifest(
        manifest: &mut BundleManifest,
        selected: Option<&[NativeFileKey]>,
    ) -> Result<Vec<NativeFileKey>> {
        native_root_layouts(manifest).map_err(source_error)?;
        let original_file_count = manifest.files.len();
        let mut present = BTreeSet::new();
        ensure!(
            manifest.files.len() <= 250_000,
            "native restore exceeds its bounded entry limit"
        );
        for file in &manifest.files {
            validate_native_relative(&file.relative_path)?;
            ensure!(
                present.insert((file.logical_root.as_str(), file.relative_path.as_str())),
                "authenticated manifest has duplicate native entry identities"
            );
            ensure!(
                matches!(file.file_type.as_str(), "file" | "directory" | "symlink"),
                "authenticated manifest contains an unsupported special entry"
            );
        }
        let selected_set = selected.map(|keys| {
            keys.iter()
                .map(|key| (key.logical_root.as_str(), key.relative_path.as_str()))
                .collect::<BTreeSet<_>>()
        });
        if let Some(keys) = selected {
            ensure!(
                !keys.is_empty() && keys.len() <= 250_000,
                "select 1–250000 restore entries"
            );
            let set = selected_set.as_ref().expect("selection initialized");
            ensure!(
                set.len() == keys.len(),
                "duplicate native restore selection"
            );
            ensure!(
                set.iter().all(|key| present.contains(key)),
                "selected native entry is not in the authenticated manifest"
            );
        }
        // Release the borrowed inventory before retaining the selected entries.
        drop(present);
        if let Some(selected) = selected_set {
            manifest.files.retain(|file| {
                selected.contains(&(file.logical_root.as_str(), file.relative_path.as_str()))
            });
        }
        manifest.tombstones.clear();
        manifest.environment["quicksave_native_download"] = json!({
            "whole_bundle":manifest.files.len() == original_file_count,
        });
        project_native_root_layouts(manifest).map_err(source_error)?;
        let mut keys = manifest
            .files
            .iter()
            .map(|file| NativeFileKey {
                logical_root: file.logical_root.clone(),
                relative_path: file.relative_path.clone(),
            })
            .collect::<Vec<_>>();
        keys.sort();
        ensure!(
            !keys.is_empty(),
            "native restore selection contains no entries"
        );
        Ok(keys)
    }

    pub fn preview(
        &self,
        job_id: Uuid,
        manifest: &BundleManifest,
        destination: &Path,
        identity: NativeObjectId,
        conflict_mode: NativeConflictMode,
    ) -> Result<NativeRestorePreview> {
        let layout = native_restore_layout(manifest, destination).map_err(source_error)?;
        let roots = logical_root_map(&layout.roots).map_err(source_error)?;
        NativeRestorePreview::prepare_for_mode(
            job_id,
            manifest,
            &roots,
            destination,
            identity,
            conflict_mode,
            RestoreMode::CompleteApplication,
        )
        .map_err(source_error)
    }

    /// Seal a native-private durable plan for restart. The caller should stream
    /// it to its checked native state writer, not return this inventory over IPC.
    pub fn authenticate_plan(
        &self,
        preview: NativeRestorePreview,
    ) -> Result<AuthenticatedRestorePlan> {
        let message = plan_message(&preview)?;
        let device_mac = self.authority.mac(&message).map_err(source_error)?;
        Ok(AuthenticatedRestorePlan {
            preview,
            device_mac,
        })
    }

    pub fn reattach(
        &self,
        plan: AuthenticatedRestorePlan,
        gate: RestoreConsentGate,
    ) -> Result<Arc<NativeRestoreControl>> {
        let expected = self
            .authority
            .mac(&plan_message(&plan.preview)?)
            .map_err(source_error)?;
        let difference = expected
            .iter()
            .zip(plan.device_mac)
            .fold(0u8, |difference, (left, right)| difference | (left ^ right));
        ensure!(
            difference == 0,
            "native restore plan device authentication failed"
        );
        self.approve(plan.preview, gate)
    }

    pub fn approve(
        &self,
        preview: NativeRestorePreview,
        gate: RestoreConsentGate,
    ) -> Result<Arc<NativeRestoreControl>> {
        let expected_gate: NativeExpectedGate = Arc::new(move || {
            gate().map_err(|_| {
                StateError::Conflict("native restore consent/state/provider binding changed".into())
            })
        });
        Ok(Arc::new(
            NativeRestoreControl::approve(preview, Arc::clone(&self.authority), expected_gate)
                .map_err(source_error)?,
        ))
    }

    pub fn install(&self, agent: &StateAgent, control: Arc<NativeRestoreControl>) -> Result<()> {
        agent
            .native_install_restore_control(control.preview().job_id, control)
            .map_err(source_error)
    }

    /// Public conflict inventory is bounded and contains no native ID/authority
    /// proof. Cursor is an offset only within the caller's retained preview ID.
    pub fn preview_page(
        preview_id: Uuid,
        preview: &NativeRestorePreview,
        offset: usize,
        limit: usize,
    ) -> Result<Value> {
        ensure!(
            limit > 0 && limit <= 200,
            "restore preview page limit is 1–200"
        );
        let total = preview.entries.len() + preview.tombstones.len();
        ensure!(
            offset <= total,
            "restore preview cursor is outside its revision"
        );
        let mut bytes = 0usize;
        let mut items = Vec::new();
        for entry in preview
            .entries
            .iter()
            .chain(&preview.tombstones)
            .skip(offset)
            .take(limit)
        {
            let item = json!({
                "path":entry.relative_path,
                "rootId":format!("native-root-{}", blake3::hash(entry.logical_root.as_bytes()).to_hex()),
                "destinationRelative":entry.destination_relative,
                "kind":entry.kind, "action":entry.action, "size":entry.size,
                "id":noland_state_agent::native_host::native_file_id(&entry.logical_root,&entry.relative_path),
                "directory":entry.kind == noland_restore::NativeEntryKind::Directory,
                "requestedMode":entry.mode,"requestedMtimeNs":entry.mtime_ns,
                "requestedUid":entry.uid,"requestedGid":entry.gid,
                "existingKind":entry.expected.as_ref().map(|prior| prior.kind),
                "existingSize":entry.expected.as_ref().map(|prior| prior.size),
                "existingMode":entry.expected.as_ref().map(|prior| prior.mode),
            });
            let item_bytes = serde_json::to_vec(&item)?.len();
            if !items.is_empty() && bytes.saturating_add(item_bytes) > 1024 * 1024 {
                break;
            }
            ensure!(
                item_bytes <= 1024 * 1024,
                "restore preview entry exceeds IPC bound"
            );
            bytes += item_bytes;
            items.push(item);
        }
        let next = offset + items.len();
        Ok(json!({
            "previewId":preview_id, "jobId":preview.job_id,
            "bundleId":preview.bundle_id,"conflictMode":preview.conflict_mode,
            "fileCount":preview.entries.len(),"tombstoneCount":preview.tombstones.len(),
            "conflictCount":preview.entries.iter().chain(&preview.tombstones)
                .filter(|entry| entry.action == noland_restore::NativeRestoreAction::Conflict).count(),
            "replacementCount":preview.entries.iter()
                .filter(|entry| entry.action == noland_restore::NativeRestoreAction::Replace).count(),
            "items":items, "nextCursor":(next < total).then_some(next),
        }))
    }
}

fn plan_message(preview: &NativeRestorePreview) -> Result<Vec<u8>> {
    let mut bytes = b"QuickSave native restore frozen plan v1\0".to_vec();
    bytes.extend_from_slice(preview.job_id.as_bytes());
    bytes.extend_from_slice(preview.digest().map_err(source_error)?.as_bytes());
    Ok(bytes)
}

fn source_error(error: StateError) -> anyhow::Error {
    anyhow::anyhow!("native restore control: {error}")
}

// The parent native module declares this file as a child. These methods reuse
// its private authenticated manifest/session/RPC bridge, never another storage
// implementation, public RPC endpoint, or per-file transfer loop.
#[derive(Default)]
pub(super) struct EngineRestoreState {
    controller: Option<Arc<NativeRestoreController>>,
    bindings: BTreeMap<Uuid, EnginePreviewBinding>,
}

struct EnginePreviewBinding {
    storage_fingerprint: String,
    created: Instant,
}

#[derive(Serialize)]
#[serde(deny_unknown_fields)]
struct DurableEnginePlanRef<'a> {
    version: u32,
    provider_id: &'a str,
    preview_id: Uuid,
    frozen_plan_fingerprint: &'a str,
    storage_fingerprint: &'a str,
    plan: AuthenticatedRestorePlanRef<'a>,
    binding_mac: [u8; 32],
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct DurableEnginePlan {
    version: u32,
    provider_id: String,
    preview_id: Uuid,
    frozen_plan_fingerprint: String,
    storage_fingerprint: String,
    plan: AuthenticatedRestorePlan,
    binding_mac: [u8; 32],
}

impl super::NativeEngine {
    /// The callback must retain/cache a native vault-authorized state MAC key;
    /// it is not a callback to fetch provider credentials for every record.
    pub fn install_restore_authority(&self, mac: DeviceRecoveryMac) -> Result<()> {
        let mut state = self
            .restore
            .lock()
            .map_err(|_| anyhow::anyhow!("native restore state lock poisoned"))?;
        ensure!(
            state.controller.is_none(),
            "native restore authority is already installed"
        );
        state.controller = Some(Arc::new(NativeRestoreController::new(mac)));
        Ok(())
    }

    fn restore_controller(&self) -> Result<Arc<NativeRestoreController>> {
        self.restore
            .lock()
            .map_err(|_| anyhow::anyhow!("native restore state lock poisoned"))?
            .controller
            .as_ref()
            .cloned()
            .context("native restore requires the QuickSave device-vault recovery authority")
    }

    pub async fn preview_restore(&self, access: ProviderAccess, selection: Value) -> Result<Value> {
        let controller = self.restore_controller()?;
        self.preflight().await?;
        let _submission = self.submission.lock().await;
        let _slot = self
            .reads
            .try_acquire()
            .context("native metadata reader is at capacity")?;
        let job_id = Uuid::new_v4();
        let private = self.private_access(&access, Some(job_id))?;
        let destination = PathBuf::from(
            selection["destination"]
                .as_str()
                .context("native restore preview requires its approved destination")?,
        );
        ensure!(
            destination.is_absolute(),
            "native restore destination must be absolute"
        );
        ensure!(
            !self.agent.config.paths.is_internal(&destination)
                && !self.agent.config.capture_exclusions.iter().any(|excluded| {
                    destination.starts_with(excluded) || excluded.starts_with(&destination)
                }),
            "native restore destination overlaps QuickSave private state"
        );
        let root = SafeRoot::open(&destination)?;
        let native_identity = root.identity()?;
        let expected =
            super::approved_destination_identity(&selection, &destination, &native_identity)?;
        ensure!(
            native_identity.file_id[1] == 0
                && expected == (native_identity.device, native_identity.file_id[0]),
            "native restore destination identity changed"
        );
        let mode = NativeRestoreController::conflict_mode(
            selection["mode"].as_str().unwrap_or("create_new"),
        )?;
        let mut manifest = self.manifest(&private, &selection).await?;
        let keys = selected_manifest_keys(&manifest, &selection)?;
        NativeRestoreController::select_manifest(&mut manifest, keys.as_deref())?;
        let preview = controller.preview(
            job_id,
            &manifest,
            &destination,
            NativeObjectId {
                device: native_identity.device,
                file_id: native_identity.file_id,
            },
            mode,
        )?;
        // The provider identity is frozen too; credentials themselves are not
        // retained in previews or written to the durable recovery plan.
        let storage_fingerprint = provider_fingerprint(&private)?;
        let scope = controller.freeze_preview(&access.provider_id, preview)?;
        {
            let mut state = self
                .restore
                .lock()
                .map_err(|_| anyhow::anyhow!("native restore state lock poisoned"))?;
            state
                .bindings
                .retain(|_, binding| binding.created.elapsed() < PREVIEW_TTL);
            ensure!(
                state.bindings.len() < MAX_PREVIEWS,
                "native restore preview capacity reached"
            );
            state.bindings.insert(
                scope.preview_id,
                EnginePreviewBinding {
                    storage_fingerprint,
                    created: Instant::now(),
                },
            );
        }
        let page = controller.frozen_preview_page(scope.preview_id, 0, 200)?;
        let summary = &scope.summary;
        Ok(json!({
            "previewId":scope.preview_id,"operationId":job_id,
            "fileCount":summary["fileCount"],"logicalBytes":summary["logicalBytes"],
            "conflictCount":summary["conflictCount"],"replacementCount":summary["replacementCount"],
            "metadataChangeCount":summary["metadataChangeCount"],
            "selectionKind":summary["selectionKind"],"sourceFullScope":summary["sourceFullScope"],
            "sourceAppName":summary["sourceAppName"],
            "rootMappingFingerprint":summary["rootMappingFingerprint"],
            "reconstruction":summary["reconstruction"],"readiness":summary["readiness"],
            "rootChanges":summary["rootChanges"],"sourcePlatform":summary["sourcePlatform"],
            "platformCompatible":summary["platformCompatible"],
            "requiresOverwriteAcknowledgement":scope.requires_overwrite_acknowledgement,
            "roots":[{"id":format!("restore-destination-{}",scope.preview_id),"path":destination}],
            "providerId":scope.provider_id,"appId":scope.app_id,"bundleId":scope.bundle_id,
            "frozenPlanFingerprint":scope.frozen_plan_fingerprint,
            "mode":summary["mode"],"expiresInSeconds":PREVIEW_TTL.as_secs(),
            "files":page["items"],"nextCursor":page["nextCursor"],
        }))
    }

    /// Pure/native metadata scope query. No runtime discovery, credentials,
    /// vault fetch, manifest retrieval, or provider call is made here.
    pub fn restore_preview_scope(&self, id: &str) -> Result<Value> {
        let id = Uuid::parse_str(id).context("invalid native restore preview ID")?;
        let controller = self.restore_controller()?;
        Ok(serde_json::to_value(controller.preview_scope(id)?)?)
    }

    /// Cheap UI hint, not cleanup authority. Reads only the small operation
    /// projection and the fixed private plan filename's native metadata. Never
    /// deserializes an inventory, opens a vault/provider or walks the destination.
    /// A missing, non-private, linked, oversized or unstable plan is not offered.
    pub fn restore_recovery_available(&self, id: Uuid) -> Result<bool> {
        if self.agent.operations.is_running(id) {
            return Ok(false);
        }
        let Some(operation) = self
            .agent
            .db
            .projected_operation(id, false)
            .map_err(source_error)?
        else {
            return Ok(false);
        };
        if operation.kind != "restore"
            || !matches!(
                operation.state.as_str(),
                "FAILED" | "CANCELLED" | "INTERRUPTED"
            )
        {
            return Ok(false);
        }
        let path = restore_plan_path(id);
        let Ok((file, stamp)) = self._data.read_file(&path) else {
            return Ok(false);
        };
        if stamp.size == 0
            || stamp.size > noland_restore::MAX_NATIVE_RESTORE_METADATA as u64
            || quicksave_platform::verify_private_file(&file).is_err()
        {
            return Ok(false);
        }
        Ok(self._data.verify_file(&path, &stamp).is_ok() && !self.agent.operations.is_running(id))
    }

    /// Descriptive approval scope only. The device MAC is deliberately verified
    /// at spend, not here: this reads bounded native-private metadata and its
    /// file stamp, without vault/provider/rclone/account I/O.
    pub fn restore_recovery_scope(&self, original_native_job_id: &str) -> Result<Value> {
        let job_id = Uuid::parse_str(original_native_job_id)
            .context("invalid original native restore job ID")?;
        let persisted = self.read_local_restore_plan(job_id)?;
        validate_local_plan_description(&persisted, job_id)?;
        let digest = durable_file_plan_digest(&persisted)?;
        Ok(json!({
            "operationId":job_id,"providerId":persisted.provider_id,
            "appId":persisted.plan.preview.app_id.as_str(),
            "bundleId":persisted.plan.preview.bundle_id,
            "roots":[{"path":persisted.plan.preview.destination}],
            "frozenPlanFingerprint":persisted.frozen_plan_fingerprint,
            "filePlanDigest":digest,
            "summary":format!("Recover the original local restore ({} selected entries); no cloud transfer or retry.",persisted.plan.preview.entries.len()),
        }))
    }

    fn read_local_restore_plan(&self, job_id: Uuid) -> Result<DurableEnginePlan> {
        let path = restore_plan_path(job_id);
        let (file, stamp) = self._data.read_file(&path)?;
        quicksave_platform::verify_private_file(&file)?;
        let persisted = read_durable_plan(file)?;
        self._data.verify_file(&path, &stamp)?;
        Ok(persisted)
    }

    /// Fresh native consent authorizes cleanup of the original local job only.
    /// No ProviderAccess, repository key, tool preflight, account lifecycle,
    /// StartRestore, RetryOperation or cloud command is involved.
    pub fn recover_restore_local(
        &self,
        selection: Value,
        gate: RestoreConsentGate,
    ) -> Result<Value> {
        let job_id = recovery_job_id(&selection)?;
        let _submission = self
            .submission
            .try_lock()
            .context("native restore submission or recovery is busy")?;
        ensure!(
            !self.agent.operations.is_running(job_id),
            "local recovery requires the original restore worker to stop"
        );
        // This synchronous call owns all cleanup. A retained registry reference
        // cannot spend this consent after the owned function returns, including
        // on an early error. There are no spawned workers or cloud operations.
        let active = Arc::new(std::sync::atomic::AtomicBool::new(true));
        let _consent_lease = LocalRecoveryConsentLease(Arc::clone(&active));
        let gate: RestoreConsentGate = Arc::new(move || {
            ensure!(
                active.load(std::sync::atomic::Ordering::Acquire),
                "local restore recovery consent has ended"
            );
            gate()
        });
        gate().context("local restore recovery authorization changed")?;
        let persisted = self.read_local_restore_plan(job_id)?;
        validate_local_plan_description(&persisted, job_id)?;
        let file_plan_digest = durable_file_plan_digest(&persisted)?;
        if let Some(expected) = selection.get("filePlanDigest").and_then(Value::as_str) {
            ensure!(
                expected == file_plan_digest,
                "local recovery plan changed after native approval"
            );
        }
        if let Some(expected) = selection
            .get("frozenPlanFingerprint")
            .and_then(Value::as_str)
        {
            ensure!(
                expected == persisted.frozen_plan_fingerprint,
                "local recovery scope changed after native approval"
            );
        }
        let controller = self.restore_controller()?;
        let expected = controller
            .authority
            .mac(&engine_binding_message(
                &persisted.provider_id,
                persisted.preview_id,
                &persisted.frozen_plan_fingerprint,
                &persisted.storage_fingerprint,
                &persisted.plan.device_mac,
                job_id,
            )?)
            .map_err(source_error)?;
        ensure!(
            constant_mac_equal(&expected, &persisted.binding_mac),
            "local restore provider/plan binding authentication failed"
        );
        // reattach separately authenticates the complete frozen preview before
        // any controller installation or native filesystem mutation.
        let control = controller.reattach(persisted.plan, Arc::clone(&gate))?;
        controller.install(&self.agent, control)?;
        gate().context("local restore recovery authorization changed before cleanup")?;
        let reports = self
            .agent
            .native_recover_restore(job_id)
            .map_err(source_error)?;
        let recovered = !reports.is_empty()
            && reports.iter().all(|report| {
                (report.rolled_back || report.committed)
                    && report.retained_artifacts.is_empty()
                    && report.owned_artifacts_clean
                    && report.metadata_only_workspace
            });
        let diagnostics = reports
            .iter()
            .flat_map(|report| &report.retained_artifacts)
            .take(32)
            .map(|text| public_recovery_diagnostic(text))
            .collect::<Vec<_>>();
        let public_reports = reports
            .iter()
            .map(|report| {
                json!({
                    "committed":report.committed,"rolledBack":report.rolled_back,
                    "removedOwnedEntries":report.removed_owned_entries,
                    "restoredOriginalEntries":report.restored_original_entries,
                    "ownedArtifactsClean":report.owned_artifacts_clean,
                    "metadataOnlyWorkspace":report.metadata_only_workspace,
                    "retainedDiagnosticCount":report.retained_artifacts.len(),
                })
            })
            .collect::<Vec<_>>();
        // Sanitized actual results: no raw journals, MACs, native IDs or keys.
        Ok(json!({
            "operationId":job_id,"recovered":recovered,"localOnly":true,
            "workspaceCount":reports.len(),"noRecordedWorkspaces":reports.is_empty(),
            "rolledBackWorkspaces":reports.iter().filter(|report| report.rolled_back).count(),
            "committedWorkspaces":reports.iter().filter(|report| report.committed).count(),
            "ownedArtifactsClean":!reports.is_empty() && reports.iter().all(|report| report.owned_artifacts_clean),
            "metadataOnlyWorkspaces":!reports.is_empty() && reports.iter().all(|report| report.metadata_only_workspace),
            "retainedArtifacts":reports.iter().any(|report| !report.retained_artifacts.is_empty()),
            "diagnostics":diagnostics,"newTransferStarted":false,
            "reports":public_reports,
        }))
    }

    pub async fn download_guarded(
        &self,
        access: ProviderAccess,
        selection: Value,
        gate: RestoreConsentGate,
    ) -> Result<Value> {
        gate().context("native restore approval changed before submission")?;
        let controller = self.restore_controller()?;
        self.preflight().await?;
        let _submission = self.submission.lock().await;
        let preview_id = selection["restorePreviewId"]
            .as_str()
            .or_else(|| selection["previewId"].as_str())
            .context("download requires its frozen native restorePreviewId")?;
        let preview_id =
            Uuid::parse_str(preview_id).context("invalid native restore preview ID")?;
        let approved = controller.approve_preview(
            preview_id,
            selection["overwriteAcknowledgement"].as_bool() == Some(true),
            Arc::clone(&gate),
        )?;
        ensure!(
            access.provider_id == approved.provider_id,
            "native restore provider differs from its frozen preview"
        );
        let storage_fingerprint = {
            let state = self
                .restore
                .lock()
                .map_err(|_| anyhow::anyhow!("native restore state lock poisoned"))?;
            let binding = state
                .bindings
                .get(&preview_id)
                .context("native restore preview binding is unavailable; preview again")?;
            ensure!(
                binding.created.elapsed() < PREVIEW_TTL,
                "native restore preview expired"
            );
            binding.storage_fingerprint.clone()
        };
        let mut private = self.private_access(&access, Some(approved.job_id))?;
        ensure!(
            provider_fingerprint(&private)? == storage_fingerprint,
            "native restore storage root/backend changed after preview"
        );
        private.session.operation_id = approved.job_id.to_string();
        let private = Arc::new(private);
        gate().context("native restore approval changed before durable admission")?;
        self.persist_restore_plan(&controller, &approved, &storage_fingerprint)?;
        controller.install(&self.agent, Arc::clone(&approved.control))?;
        self.reserve_private(approved.job_id, Arc::clone(&private))?;
        // No incoming mapping/file list can widen this selection. The only
        // authority is the retained exact preview and its in-process control.
        let native = selection_from_control_with_keys(&approved.control, approved.file_keys)?;
        let result = self
            .rpc_private(
                "StartRestore",
                &private,
                json!({
                    "app_id":approved.app_id,"bundle_id":approved.bundle_id,
                    "mode":"complete_application","client_operation_id":approved.job_id,
                    "native_selection":native,
                }),
            )
            .await;
        super::submission_result(result, approved.job_id)
    }

    fn persist_restore_plan(
        &self,
        controller: &NativeRestoreController,
        approved: &ApprovedNativeRestore,
        storage_fingerprint: &str,
    ) -> Result<()> {
        self._data.create_dir("shared-storage/restore-plans")?;
        let path = restore_plan_path(approved.job_id);
        let plan = controller.authenticated_plan_ref(&approved.control)?;
        let binding_mac = controller
            .authority
            .mac(&engine_binding_message(
                &approved.provider_id,
                approved.preview_id,
                &approved.frozen_plan_fingerprint,
                storage_fingerprint,
                &plan.device_mac,
                approved.job_id,
            )?)
            .map_err(source_error)?;
        let document = DurableEnginePlanRef {
            version: 1,
            provider_id: &approved.provider_id,
            preview_id: approved.preview_id,
            frozen_plan_fingerprint: &approved.frozen_plan_fingerprint,
            storage_fingerprint,
            plan,
            binding_mac,
        };
        if let Ok((file, stamp)) = self._data.read_file(&path) {
            quicksave_platform::verify_private_file(&file)?;
            let existing = read_durable_plan(file)?;
            self._data.verify_file(&path, &stamp)?;
            ensure!(
                existing.provider_id == approved.provider_id
                    && existing.preview_id == approved.preview_id
                    && existing.binding_mac == binding_mac
                    && existing.plan.preview.job_id == approved.job_id,
                "native restore operation already has a different durable plan"
            );
            return Ok(());
        }
        self._data.write_new(&path, |file| {
            let mut bounded = BoundedWriter {
                inner: file,
                written: 0,
            };
            serde_json::to_writer(&mut bounded, &document)?;
            Ok(())
        })
    }

    /// Explicit recovery/credential reattachment. This does not queue another
    /// restore, delete a cloud generation, or broaden the original file plan.
    pub async fn recover_restore(
        &self,
        access: ProviderAccess,
        selection: Value,
        gate: RestoreConsentGate,
    ) -> Result<Value> {
        let id = selection["operationId"]
            .as_str()
            .or_else(|| selection["nativeOperationId"].as_str())
            .or_else(|| selection["jobId"].as_str())
            .context("native restore recovery requires its original operationId")?;
        let job_id = Uuid::parse_str(id).context("invalid native restore operation ID")?;
        gate().context("native restore recovery authorization changed")?;
        let controller = self.restore_controller()?;
        self.preflight().await?;
        let _submission = self.submission.lock().await;
        let path = restore_plan_path(job_id);
        let (file, stamp) = self._data.read_file(&path)?;
        quicksave_platform::verify_private_file(&file)?;
        let persisted = read_durable_plan(file)?;
        self._data.verify_file(&path, &stamp)?;
        ensure!(
            persisted.version == 1
                && persisted.provider_id == access.provider_id
                && persisted.plan.preview.job_id == job_id,
            "native restore recovery provider/job differs from the original plan"
        );
        let expected = controller
            .authority
            .mac(&engine_binding_message(
                &persisted.provider_id,
                persisted.preview_id,
                &persisted.frozen_plan_fingerprint,
                &persisted.storage_fingerprint,
                &persisted.plan.device_mac,
                job_id,
            )?)
            .map_err(source_error)?;
        ensure!(
            constant_mac_equal(&expected, &persisted.binding_mac),
            "native restore provider/plan binding authentication failed"
        );
        let mut private = self.private_access(&access, Some(job_id))?;
        ensure!(
            provider_fingerprint(&private)? == persisted.storage_fingerprint,
            "native restore recovery storage root/backend changed"
        );
        private.session.operation_id = job_id.to_string();
        let private = Arc::new(private);
        let control = controller.reattach(persisted.plan, Arc::clone(&gate))?;
        controller.install(&self.agent, Arc::clone(&control))?;
        let reports = self
            .agent
            .native_recover_restore(job_id)
            .map_err(source_error)?;
        gate().context("native restore authorization changed after recovery")?;
        let native = selection_from_control(&control)?;
        // The source's signed operation replay verifies the original request;
        // an existing operation is reattached, not enqueued/duplicated.
        self.rpc_private("StartRestore", &private, json!({
            "app_id":control.preview().app_id.as_str(),"bundle_id":control.preview().bundle_id,
            "mode":"complete_application","client_operation_id":job_id,"native_selection":native,
        })).await?;
        self.reserve_private(job_id, private)?;
        let diagnostics = reports
            .iter()
            .flat_map(|report| &report.retained_artifacts)
            .take(32)
            .map(|diagnostic| diagnostic.chars().take(512).collect::<String>())
            .collect::<Vec<_>>();
        Ok(json!({
            "operationId":job_id,"recovered":true,"workspaceCount":reports.len(),
            "rolledBackWorkspaces":reports.iter().filter(|report| report.rolled_back).count(),
            "committedWorkspaces":reports.iter().filter(|report| report.committed).count(),
            "retainedArtifacts":reports.iter().any(|report| !report.retained_artifacts.is_empty()),
            "diagnostics":diagnostics,
        }))
    }

    pub async fn retry_restore_guarded(
        &self,
        access: ProviderAccess,
        id: &str,
        gate: RestoreConsentGate,
    ) -> Result<Value> {
        let job_id = Uuid::parse_str(id).context("invalid native restore operation ID")?;
        self.recover_restore(access, json!({"operationId":job_id}), Arc::clone(&gate))
            .await?;
        gate().context("native restore retry authorization changed")?;
        let private = self
            .access
            .lock()
            .map_err(|_| anyhow::anyhow!("native access lock poisoned"))?
            .get(&job_id)
            .cloned()
            .context("native restore credentials are not reattached")?;
        self.rpc_private("RetryOperation", &private, json!({"operation_id":job_id}))
            .await?;
        Ok(json!({"operationId":job_id}))
    }
}

fn selected_manifest_keys(
    manifest: &BundleManifest,
    selection: &Value,
) -> Result<Option<Vec<NativeFileKey>>> {
    let Some(ids) = selection.get("fileIds").filter(|ids| !ids.is_null()) else {
        return Ok(None);
    };
    let ids = ids.as_array().context("restore fileIds must be an array")?;
    ensure!(
        !ids.is_empty() && ids.len() <= 250_000,
        "select 1–250000 restore files"
    );
    let mut wanted = BTreeSet::new();
    for id in ids {
        let id = id
            .as_str()
            .filter(|id| !id.is_empty() && id.len() <= 256)
            .context("invalid restore file identity")?;
        ensure!(wanted.insert(id), "duplicate restore file identity");
    }
    let mut keys = Vec::new();
    for file in &manifest.files {
        if wanted.contains(
            noland_state_agent::native_host::native_file_id(
                &file.logical_root,
                &file.relative_path,
            )
            .as_str(),
        ) {
            ensure!(
                file.file_type != "directory",
                "individual restore selection does not expand directories"
            );
            keys.push(NativeFileKey {
                logical_root: file.logical_root.clone(),
                relative_path: file.relative_path.clone(),
            });
        }
    }
    ensure!(
        keys.len() == wanted.len(),
        "selected restore file is outside the authenticated manifest"
    );
    Ok(Some(keys))
}

fn selection_from_control(
    control: &NativeRestoreControl,
) -> Result<noland_state_agent::native_host::NativeSelection> {
    let preview = control.preview();
    let keys = preview
        .entries
        .iter()
        .map(|entry| NativeFileKey {
            logical_root: entry.logical_root.clone(),
            relative_path: entry.relative_path.clone(),
        })
        .collect();
    selection_from_control_with_keys(control, keys)
}

fn selection_from_control_with_keys(
    control: &NativeRestoreControl,
    keys: Vec<NativeFileKey>,
) -> Result<noland_state_agent::native_host::NativeSelection> {
    let preview = control.preview();
    ensure!(preview.destination_identity.file_id[1] == 0,
        "the current native host selection ABI requires the full Windows-ID port before this destination is supported");
    let identity = (
        preview.destination_identity.device,
        preview.destination_identity.file_id[0],
    );
    Ok(noland_state_agent::native_host::NativeSelection {
        version: 1,
        file_keys: Some(keys),
        roots_fingerprint: blake3::hash(format!("{}:{}", identity.0, identity.1).as_bytes())
            .to_hex()
            .to_string(),
        destination: Some(preview.destination.clone()),
        destination_identity: Some(identity),
        snapshot_identity: None,
        expected_files: None,
        capture_scope: None,
        coverage: noland_state_agent::native_host::NativeCoverage::LegacyExactSelection,
        software_instance_id: None,
    })
}

fn provider_fingerprint(private: &super::PrivateAccess) -> Result<String> {
    let session = &private.session;
    for part in [
        &session.provider,
        &session.backend_type,
        &session.remote_name,
        &session.root,
    ] {
        ensure!(
            part.len() <= 32768,
            "native storage identity exceeds its bound"
        );
    }
    Ok(blake3::hash(&serde_json::to_vec(&(
        &session.provider,
        &session.backend_type,
        &session.remote_name,
        &session.root,
    ))?)
    .to_hex()
    .to_string())
}

fn restore_plan_path(job_id: Uuid) -> String {
    format!("shared-storage/restore-plans/{job_id}.json")
}

struct LocalRecoveryConsentLease(Arc<std::sync::atomic::AtomicBool>);

impl Drop for LocalRecoveryConsentLease {
    fn drop(&mut self) {
        self.0.store(false, std::sync::atomic::Ordering::Release);
    }
}

fn recovery_job_id(selection: &Value) -> Result<Uuid> {
    let id = selection["operationId"]
        .as_str()
        .or_else(|| selection["nativeOperationId"].as_str())
        .or_else(|| selection["jobId"].as_str())
        .context("local restore recovery requires its original operationId")?;
    Uuid::parse_str(id).context("invalid original native restore operation ID")
}

fn validate_local_plan_description(plan: &DurableEnginePlan, job_id: Uuid) -> Result<()> {
    ensure!(
        plan.version == 1 && plan.plan.preview.job_id == job_id,
        "local restore plan belongs to another original job/version"
    );
    super::validate_id(&plan.provider_id)?;
    super::validate_id(plan.plan.preview.app_id.as_str())?;
    ensure!(
        !plan.provider_id.is_empty()
            && plan.provider_id.len() <= 128
            && plan.plan.preview.app_id.as_str().len() <= 512
            && plan
                .plan
                .preview
                .entries
                .len()
                .saturating_add(plan.plan.preview.tombstones.len())
                <= 250_000
            && plan.plan.preview.destination.is_absolute()
            && plan
                .plan
                .preview
                .destination
                .to_str()
                .is_some_and(|path| path.len() <= 32768 && !path.chars().any(char::is_control))
            && [&plan.frozen_plan_fingerprint, &plan.storage_fingerprint]
                .iter()
                .all(|digest| digest.len() == 64
                    && digest.bytes().all(|byte| byte.is_ascii_hexdigit())),
        "local restore plan description exceeds its native bounds"
    );
    Ok(())
}

fn public_recovery_diagnostic(text: &str) -> &'static str {
    // Reports count actual retained errors, but arbitrary source errors, paths,
    // native identifiers and journal bytes are not an IPC diagnostic format.
    let lower = text.to_ascii_lowercase();
    if lower.contains("mac") || lower.contains("authentic") || lower.contains("integrity") {
        "Local recovery retained data because journal authentication or integrity could not be verified."
    } else if lower.contains("foreign")
        || lower.contains("replaced")
        || lower.contains("modified")
        || lower.contains("identity")
        || lower.contains("changed")
    {
        "Local recovery retained data because an original, output, artifact or root changed."
    } else if lower.contains("no such file")
        || lower.contains("not found")
        || lower.contains("unavailable")
    {
        "Local recovery retained data because required local recovery evidence is unavailable."
    } else if lower.contains("unknown")
        || lower.contains("unapproved")
        || lower.contains("plaintext")
    {
        "Local recovery retained unapproved workspace data; no path-based deletion was attempted."
    } else {
        "Local recovery retained artifacts because cleanup or durability could not be verified."
    }
}

fn durable_file_plan_digest(plan: &DurableEnginePlan) -> Result<String> {
    let preview_digest = plan.plan.preview.digest().map_err(source_error)?;
    let message = engine_binding_message(
        &plan.provider_id,
        plan.preview_id,
        &plan.frozen_plan_fingerprint,
        &plan.storage_fingerprint,
        &plan.plan.device_mac,
        plan.plan.preview.job_id,
    )?;
    let mut hash = blake3::Hasher::new();
    hash.update(b"QuickSave local recovery descriptive file plan v1\0");
    hash.update(&plan.version.to_le_bytes());
    hash.update(&message);
    hash.update(preview_digest.as_bytes());
    hash.update(&plan.binding_mac);
    Ok(hash.finalize().to_hex().to_string())
}

fn engine_binding_message(
    provider: &str,
    preview_id: Uuid,
    fingerprint: &str,
    storage_fingerprint: &str,
    plan_mac: &[u8; 32],
    job_id: Uuid,
) -> Result<Vec<u8>> {
    ensure!(
        provider.len() <= 128 && fingerprint.len() == 64 && storage_fingerprint.len() == 64,
        "invalid native restore durable binding"
    );
    let mut bytes = b"QuickSave native restore provider binding v1\0".to_vec();
    bytes.extend_from_slice(job_id.as_bytes());
    bytes.extend_from_slice(preview_id.as_bytes());
    bytes.extend_from_slice(&(provider.len() as u64).to_le_bytes());
    bytes.extend_from_slice(provider.as_bytes());
    bytes.extend_from_slice(fingerprint.as_bytes());
    bytes.extend_from_slice(storage_fingerprint.as_bytes());
    bytes.extend_from_slice(plan_mac);
    Ok(bytes)
}

fn constant_mac_equal(left: &[u8; 32], right: &[u8; 32]) -> bool {
    left.iter()
        .zip(right)
        .fold(0u8, |difference, (a, b)| difference | (a ^ b))
        == 0
}

struct BoundedWriter<'a> {
    inner: &'a mut std::fs::File,
    written: usize,
}
impl std::io::Write for BoundedWriter<'_> {
    fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
        if self
            .written
            .checked_add(bytes.len())
            .is_none_or(|size| size > noland_restore::MAX_NATIVE_RESTORE_METADATA)
        {
            return Err(std::io::Error::other("native restore plan exceeds 512 MiB"));
        }
        let count = std::io::Write::write(self.inner, bytes)?;
        self.written += count;
        Ok(count)
    }
    fn flush(&mut self) -> std::io::Result<()> {
        std::io::Write::flush(self.inner)
    }
}

fn read_durable_plan(file: std::fs::File) -> Result<DurableEnginePlan> {
    use std::io::Read;
    ensure!(
        file.metadata()?.len() <= noland_restore::MAX_NATIVE_RESTORE_METADATA as u64,
        "native restore durable plan exceeds 512 MiB"
    );
    // Deserialize directly from a bounded reader, not a second whole-document
    // byte buffer or a serde_json::Value clone of a giant inventory.
    serde_json::from_reader(file.take(noland_restore::MAX_NATIVE_RESTORE_METADATA as u64 + 1))
        .map_err(|_| anyhow::anyhow!("native restore durable plan is invalid"))
}

#[cfg(test)]
mod recovery_tests {
    use super::*;
    use noland_state_core::{
        AppId, BackupMode, ManifestApp, ManifestFile, ManifestSource, OperationRecord,
        PersistenceClass, SemanticRole,
    };
    use std::{
        fs,
        sync::atomic::{AtomicUsize, Ordering},
    };

    struct Fixture {
        _temp: tempfile::TempDir,
        root: PathBuf,
        destination: PathBuf,
        engine: super::super::NativeEngine,
    }

    impl Fixture {
        fn new() -> Result<Self> {
            let approved =
                Path::new("/private/var/folders/bm/fyg39kl11r5crgrby4bqs4lr0000gn/T/opencode");
            let temp = if approved.is_dir() {
                tempfile::tempdir_in(approved)?
            } else {
                tempfile::tempdir()?
            };
            let root = fs::canonicalize(temp.path())?;
            let destination = root.join("destination");
            fs::create_dir(&destination)?;
            fs::create_dir(root.join("home"))?;
            let engine = super::super::NativeEngine::open(&root.join("data"), &root.join("home"))?;
            Ok(Self {
                _temp: temp,
                root,
                destination,
                engine,
            })
        }

        fn plan(&self) -> Result<(noland_restore::RestorePlan, Arc<NativeRestoreControl>)> {
            let controller = self.engine.restore_controller()?;
            let mut manifest = BundleManifest::new(
                ManifestApp {
                    app_id: AppId("quicksave:local-recovery-fixture".into()),
                    display_name: "Local recovery fixture".into(),
                    aliases: vec![],
                    desktop_entry_id: None,
                    steam_app_id: None,
                    launcher: None,
                    canonical_executable: None,
                    icon_path: None,
                },
                ManifestSource {
                    instance_id: Uuid::new_v4(),
                    image_id: "isolated-fixture".into(),
                    captured_at: chrono::Utc::now(),
                },
                BackupMode::CompleteApplication,
            );
            manifest.files.push(ManifestFile {
                logical_root: "$XDG_DATA_HOME".into(),
                relative_path: "empty.sav".into(),
                source_path_hint: None,
                file_type: "file".into(),
                size: 0,
                file_hash: format!("blake3:{}", blake3::hash(b"").to_hex()),
                chunks: vec![],
                mode: None,
                mtime_ns: None,
                uid: None,
                gid: None,
                symlink_target: None,
                persistence_class: PersistenceClass::PersistentState,
                semantic_role: SemanticRole::UserState,
                association_confidence: 1.0,
                shared_app_ids: vec![],
            });
            let job_id = Uuid::new_v4();
            let identity = SafeRoot::open(&self.destination)?.identity()?;
            let preview = controller.preview(
                job_id,
                &manifest,
                &self.destination,
                NativeObjectId {
                    device: identity.device,
                    file_id: identity.file_id,
                },
                NativeConflictMode::CreateOnly,
            )?;
            let scope = controller.freeze_preview("disconnected-fixture-provider", preview)?;
            let approved =
                controller.approve_preview(scope.preview_id, false, Arc::new(|| Ok(())))?;
            self.engine
                .persist_restore_plan(&controller, &approved, &"8".repeat(64))?;
            let now = chrono::Utc::now();
            self.engine
                .agent
                .db
                .upsert_operation(&OperationRecord {
                    operation_id: job_id,
                    kind: "restore".into(),
                    app_id: Some(manifest.app.app_id.clone()),
                    state: "CANCELLED".into(),
                    created_at: now,
                    updated_at: now,
                    last_error: None,
                    detail_json: json!({"bundle_id":manifest.bundle_id}),
                })
                .map_err(source_error)?;
            controller.install(&self.engine.agent, Arc::clone(&approved.control))?;
            let restore_id = Uuid::new_v4();
            let staging = self
                .engine
                .agent
                .config
                .paths
                .restore_dir(&restore_id.to_string());
            for child in ["packs", "materialized/.chunks", "pre_restore", "logs"] {
                fs::create_dir_all(staging.join(child))?;
            }
            Ok((
                noland_restore::RestorePlan {
                    restore_id,
                    staging,
                    pack_cache: self.engine.agent.config.paths.cache.join("restore-packs"),
                    manifest,
                    mode: RestoreMode::CompleteApplication,
                },
                approved.control,
            ))
        }
    }

    #[test]
    fn recovery_scope_and_activity_hint_do_not_spend_vault_authority_or_require_a_runtime(
    ) -> Result<()> {
        let fixture = Fixture::new()?;
        let calls = Arc::new(AtomicUsize::new(0));
        let mac_calls = Arc::clone(&calls);
        fixture
            .engine
            .install_restore_authority(Arc::new(move |bytes| {
                mac_calls.fetch_add(1, Ordering::Relaxed);
                Ok(*blake3::keyed_hash(&[0x64; 32], bytes).as_bytes())
            }))?;
        let (plan, control) = fixture.plan()?;
        let id = control.preview().job_id;
        let before = calls.load(Ordering::Relaxed);
        assert!(fixture.engine.restore_recovery_available(id)?);
        let scope = fixture.engine.restore_recovery_scope(&id.to_string())?;
        assert_eq!(calls.load(Ordering::Relaxed), before);
        assert!(fixture.engine.runtime.get().is_none());
        assert!(fixture.engine.access.lock().unwrap().is_empty());
        assert_eq!(scope["operationId"], json!(id));
        assert_eq!(scope["roots"], json!([{"path":fixture.destination}]));
        assert!(scope["summary"].is_string());
        assert!(scope["filePlanDigest"].is_string());
        assert_eq!(scope.as_object().unwrap().len(), 8);

        // Reopening the engine supplies no vault authority at all. Both UI
        // metadata reads remain usable; execution fails before local mutation.
        let Fixture {
            _temp,
            root,
            destination,
            engine,
        } = fixture;
        drop(engine);
        let engine = super::super::NativeEngine::open(&root.join("data"), &root.join("home"))?;
        assert!(engine.restore_recovery_available(id)?);
        assert!(engine.restore_recovery_scope(&id.to_string()).is_ok());
        assert!(engine
            .recover_restore_local(json!({"operationId":id}), Arc::new(|| Ok(())),)
            .is_err());
        assert!(fs::read_dir(&destination)?.next().is_none());
        assert!(plan.staging.is_dir());
        drop(engine);
        drop(_temp);
        Ok(())
    }

    #[test]
    fn local_recovery_rolls_back_original_cancelled_job_without_provider_access_or_transfer(
    ) -> Result<()> {
        let fixture = Fixture::new()?;
        fixture.engine.install_restore_authority(Arc::new(|bytes| {
            Ok(*blake3::keyed_hash(&[0x64; 32], bytes).as_bytes())
        }))?;
        let (plan, control) = fixture.plan()?;
        let id = control.preview().job_id;
        let roots = noland_state_agent::native_host::native_restore_roots(
            &fixture.destination,
            &plan.manifest,
        )?;
        let mut transaction =
            noland_restore::RestoreTransaction::new_native(&plan, &roots, Arc::clone(&control))?;
        transaction.publish_to(noland_restore::RestoreTarget::Complete)?;
        let target = roots
            .resolve(&noland_state_core::LogicalRoot::parse("$XDG_DATA_HOME").unwrap())
            .unwrap()
            .join("empty.sav");
        assert!(target.is_file());
        // Simulate a stopped owner before restart; no Drop rollback happens.
        std::mem::forget(transaction);
        let scope = fixture.engine.restore_recovery_scope(&id.to_string())?;
        let result = fixture.engine.recover_restore_local(
            json!({
                "operationId":id, "frozenPlanFingerprint":scope["frozenPlanFingerprint"],
                "filePlanDigest":scope["filePlanDigest"],
            }),
            Arc::new(|| Ok(())),
        )?;
        assert_eq!(result["operationId"], json!(id));
        assert_eq!(result["recovered"], true);
        assert_eq!(result["newTransferStarted"], false);
        assert_eq!(result["reports"][0]["rolledBack"], true);
        assert_eq!(result["reports"][0]["ownedArtifactsClean"], true);
        assert!(!target.exists());
        assert_eq!(
            fixture
                .engine
                .agent
                .db
                .projected_operation(id, false)?
                .unwrap()
                .state,
            "CANCELLED"
        );
        assert!(fixture.engine.runtime.get().is_none());
        assert!(fixture.engine.access.lock().unwrap().is_empty());
        assert!(
            fixture
                .engine
                .agent
                .native_restore_control(id)?
                .check_gate()
                .is_err(),
            "return revokes the recovery-only consent even if its control was retained"
        );
        Ok(())
    }

    #[test]
    fn recovery_hint_checks_private_metadata_and_terminal_restore_kind_without_parsing_inventory(
    ) -> Result<()> {
        use std::os::unix::fs::PermissionsExt;
        let fixture = Fixture::new()?;
        let id = Uuid::new_v4();
        let now = chrono::Utc::now();
        let operation = OperationRecord {
            operation_id: id,
            kind: "restore".into(),
            app_id: None,
            state: "FAILED".into(),
            created_at: now,
            updated_at: now,
            last_error: None,
            detail_json: json!({}),
        };
        fixture.engine.agent.db.upsert_operation(&operation)?;
        assert!(!fixture.engine.restore_recovery_available(id)?);
        fixture
            .engine
            ._data
            .create_dir("shared-storage/restore-plans")?;
        let path = restore_plan_path(id);
        let write_plan = |job_id| {
            fixture
                .engine
                ._data
                .write_new(&restore_plan_path(job_id), |file| {
                    use std::io::Write;
                    file.write_all(b"not a parsed inventory")?;
                    Ok(())
                })
        };
        write_plan(id)?;
        // Deliberately invalid contents prove polling never deserializes the
        // plan. This is only a candidate hint; scope/spend still reject it.
        assert!(fixture.engine.restore_recovery_available(id)?);
        assert!(fixture
            .engine
            .restore_recovery_scope(&id.to_string())
            .is_err());
        // Source operation kinds are immutable on conflict. Use fresh IDs and
        // actual private files for both negative cases, not an attempted kind
        // mutation or a missing-file shortcut.
        for (kind, state) in [("backup", "FAILED"), ("restore", "COMPLETED")] {
            let candidate = OperationRecord {
                operation_id: Uuid::new_v4(),
                kind: kind.into(),
                state: state.into(),
                ..operation.clone()
            };
            fixture.engine.agent.db.upsert_operation(&candidate)?;
            write_plan(candidate.operation_id)?;
            let persisted = fixture
                .engine
                .agent
                .db
                .projected_operation(candidate.operation_id, false)?
                .context("fixture operation was not persisted")?;
            assert_eq!(persisted.kind, kind);
            assert_eq!(persisted.state, state);
            assert!(!fixture
                .engine
                .restore_recovery_available(candidate.operation_id)?);
        }
        let persisted = fixture
            .engine
            .agent
            .db
            .projected_operation(id, false)?
            .context("original restore fixture was not persisted")?;
        assert_eq!(persisted.kind, "restore");
        assert_eq!(persisted.state, "FAILED");
        assert!(fixture.engine.restore_recovery_available(id)?);
        let (file, _) = fixture.engine._data.read_file(&path)?;
        file.set_permissions(fs::Permissions::from_mode(0o644))?;
        assert!(!fixture.engine.restore_recovery_available(id)?);
        file.set_permissions(fs::Permissions::from_mode(0o600))?;
        fs::hard_link(
            fixture.root.join("data").join(&path),
            fixture.root.join("foreign-alias"),
        )?;
        assert!(!fixture.engine.restore_recovery_available(id)?);
        Ok(())
    }
}
