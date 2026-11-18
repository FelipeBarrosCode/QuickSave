// SPDX-License-Identifier: GPL-3.0-only
//! Frozen native restore handles. A download never accepts editable mappings.

use crate::{
    boundary as dto, Active, RestorePreview, WorkspaceService, PREVIEW_LIFETIME, PREVIEW_LIMIT,
};
use anyhow::{anyhow, ensure, Result};
use serde_json::{json, Value};
use std::{
    collections::BTreeSet,
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc,
    },
    time::Instant,
};

// A root metadata/conflict entry is not a file. Empty application roots can
// legitimately have metadata changes even when the file inventory is empty.
fn conflict_inventory(raw: &Value, files: u64) -> Result<Value> {
    let blocking = raw["conflictCount"]
        .as_u64()
        .ok_or_else(|| anyhow!("Native restore conflict count is missing"))?;
    let optional_count = |field: &str| -> Result<u64> {
        match raw.get(field) {
            None | Some(Value::Null) => Ok(0),
            Some(value) => value
                .as_u64()
                .ok_or_else(|| anyhow!("Native restore conflict count is invalid")),
        }
    };
    let replacements = optional_count("replacementCount")?;
    let metadata = optional_count("metadataChangeCount")?;
    let tombstones = optional_count("tombstoneCount")?;
    let mut root_conflicts = 0u64;
    let mut root_metadata = 0u64;
    let root_count = match raw.get("rootChanges") {
        None | Some(Value::Null) => 0,
        Some(changes) => {
            let changes = changes
                .as_array()
                .ok_or_else(|| anyhow!("Native restore root change inventory is invalid"))?;
            ensure!(
                changes.len() <= 64,
                "Native restore root change inventory is oversized"
            );
            let mut seen = BTreeSet::new();
            for root in changes {
                let path = root["destinationRelative"]
                    .as_str()
                    .ok_or_else(|| anyhow!("Native restore root change destination is missing"))?;
                ensure!(
                    path.len() <= 32_768
                        && !path.chars().any(char::is_control)
                        && seen.insert(path),
                    "Native restore root change inventory is ambiguous"
                );
                ensure!(
                    root["kind"] == "directory",
                    "Native restore root kind is invalid"
                );
                match root["action"].as_str() {
                    Some("conflict") => root_conflicts += 1,
                    Some("metadata") => root_metadata += 1,
                    Some("create" | "reuse") => {}
                    _ => anyhow::bail!("Native restore root action is invalid"),
                }
            }
            changes.len() as u64
        }
    };
    let conflicts = blocking
        .checked_add(replacements)
        .and_then(|n| n.checked_add(metadata))
        .ok_or_else(|| anyhow!("Native restore conflict count overflow"))?;
    let file_targets = files
        .checked_add(tombstones)
        .ok_or_else(|| anyhow!("Native restore target count overflow"))?;
    let all_targets = file_targets
        .checked_add(root_count)
        .ok_or_else(|| anyhow!("Native restore target count overflow"))?;
    ensure!(
        blocking >= root_conflicts
            && metadata >= root_metadata
            && replacements <= files
            && conflicts <= all_targets
            && conflicts - root_conflicts - root_metadata <= file_targets,
        "Native restore conflict inventory is inconsistent"
    );
    Ok(json!({
        "conflictCount":conflicts, "blockingConflicts":blocking,
        "replacementCount":replacements, "metadataChangeCount":metadata,
        "rootChangeCount":root_count, "rootConflictCount":root_conflicts,
        "rootMetadataChangeCount":root_metadata,
    }))
}

impl WorkspaceService {
    fn original_restore_id(&self, requested: &str) -> Result<String> {
        let operations = self
            .operations
            .lock()
            .map_err(|_| anyhow!("Operation state lock failed"))?;
        if let Some(operation) = operations.get(requested) {
            ensure!(
                operation.activity["kind"] == "download" && dto::terminal(&operation.activity),
                "Only a terminal original restore can be recovered"
            );
            return operation
                .native_id
                .clone()
                .ok_or_else(|| anyhow!("This restore never reached native admission"));
        }
        // A restart exposes the original native ID, not a newly invented job.
        Ok(requested.to_owned())
    }

    pub(super) async fn recovery_scope(&self, requested: &str) -> Result<Value> {
        let native = self.original_restore_id(requested)?;
        let mut scope = self
            .engine_call(
                "restore_recovery_scope",
                None,
                json!({"operationId":native}),
            )
            .await?;
        ensure!(
            scope["operationId"] == native
                && scope["roots"]
                    .as_array()
                    .is_some_and(|roots| !roots.is_empty() && roots.len() <= 64),
            "The native recovery scope is missing its original operation or destinations"
        );
        dto::text(&scope, "summary", 8192)?;
        dto::text(&scope, "frozenPlanFingerprint", 512)?;
        for root in scope["roots"].as_array().unwrap() {
            dto::absolute(dto::text(root, "path", 4096)?)?;
        }
        scope["requestedOperationId"] = json!(requested);
        Ok(scope)
    }

    pub(super) async fn recover_restore(&self, params: Value) -> Result<Value> {
        let _active = Active::acquire(&self.lifetime, true)?;
        let requested = dto::id(&params, "operationId")?;
        let scope = self.recovery_scope(requested).await?;
        let mut selection = json!({"operationId":scope["operationId"],
            "frozenPlanFingerprint":scope["frozenPlanFingerprint"],
            "filePlanDigest":scope["filePlanDigest"]});
        if let Some(paths) = params.get("_approvedPaths") {
            selection["_approvedPaths"] = paths.clone();
        }
        let live = Arc::new(AtomicBool::new(true));
        let lease = RecoveryLease(live.clone());
        let weak = self.weak.clone();
        let gate = Arc::new(move || {
            ensure!(
                live.load(Ordering::Acquire),
                "This native recovery approval has ended"
            );
            let service = weak
                .upgrade()
                .ok_or_else(|| anyhow!("The native workspace is no longer available"))?;
            ensure!(
                !service.lifetime.shutdown_complete.load(Ordering::Acquire),
                "The native workspace has shut down"
            );
            Ok(())
        });
        let result = self
            .engine
            .recover_restore_local(selection, gate)
            .await
            .map_err(|error| anyhow!(dto::engine_error(&error)))?;
        dto::bounded(&result, dto::MAX_OUTPUT_BYTES)?;
        drop(lease);
        // Recovery may roll back incomplete files; it does not mean the original
        // download completed. Keep its actual terminal state/history unchanged.
        self.patch_operation(
            requested,
            json!({"canRecover":result["recovered"] != true
            || result["retainedArtifacts"] == true,"canRetry":false}),
        );
        Ok(json!({"recovery":result}))
    }
    pub(super) fn restore_preview(&self, id: &str) -> Result<RestorePreview> {
        let previews = self
            .restore_previews
            .lock()
            .map_err(|_| anyhow!("Restore preview lock failed"))?;
        let preview = previews
            .get(id)
            .ok_or_else(|| anyhow!("Create a fresh native restore preview first"))?;
        ensure!(
            preview.created.elapsed() < PREVIEW_LIFETIME,
            "Native restore preview expired; preview again"
        );
        Ok(preview.clone())
    }

    pub(super) async fn prepare_restore(&self, params: Value) -> Result<Value> {
        let _active = Active::acquire(&self.lifetime, false)?;
        let provider = dto::id(&params, "providerId")?;
        dto::provider_record(&self.snapshot()?, provider)?;
        let access = self
            .access(provider, &uuid::Uuid::new_v4().to_string(), false)
            .await?;
        let raw = self
            .engine_call("preview_restore", Some(access), params.clone())
            .await?;
        let id = dto::id(&raw, "previewId")?.to_owned();
        ensure!(
            raw["requiresOverwriteAcknowledgement"].is_boolean(),
            "Native restore preview lacks its actual conflict policy"
        );
        let mut summary = dto::copy_fields(
            &raw,
            &[
                "previewId",
                "fileCount",
                "logicalBytes",
                "conflictCount",
                "sourceInstance",
                "readiness",
                "requiresOverwriteAcknowledgement",
                "frozenPlanFingerprint",
                "expiresAt",
            ],
        );
        for field in ["providerId", "bundleId", "appId", "mode", "destination"] {
            summary[field] = params[field].clone();
        }
        let roots = raw["roots"]
            .as_array()
            .ok_or_else(|| anyhow!("Frozen native restore roots are missing"))?;
        ensure!(
            !roots.is_empty() && roots.len() <= 64,
            "Native restore root count is invalid"
        );
        summary["roots"] = json!(roots
            .iter()
            .map(|root| dto::copy_fields(root, &["id", "path"]))
            .collect::<Vec<_>>());
        for root in summary["roots"].as_array().unwrap() {
            dto::absolute(dto::text(root, "path", 32_768)?)?;
        }
        let count = raw["fileCount"]
            .as_u64()
            .ok_or_else(|| anyhow!("Native restore file count is missing"))?;
        let inventory = conflict_inventory(&raw, count)?;
        let conflicts = inventory["conflictCount"].as_u64().unwrap();
        for (field, value) in inventory.as_object().unwrap() {
            summary[field] = value.clone();
        }
        if let Some(roots) = raw["rootChanges"].as_array() {
            summary["rootChanges"] = json!(roots
                .iter()
                .map(|root| dto::copy_fields(
                    root,
                    &[
                        "destinationRelative",
                        "kind",
                        "action",
                        "requestedMode",
                        "requestedMtimeNs",
                        "requestedUid",
                        "requestedGid",
                    ]
                ))
                .collect::<Vec<_>>());
        }
        summary["files"] = json!(count);
        summary["bytes"] = raw["logicalBytes"]
            .as_u64()
            .ok_or_else(|| anyhow!("Native restore byte count is missing"))?
            .into();
        summary["conflicts"] = json!([]);
        summary["summary"] = json!(format!(
            "Restore {count} selected entries from backup {} for application {} using {} mode into {}. {conflicts} conflicting existing entries. Only this frozen native plan is authorized; unrelated local files remain untouched.",
            dto::id(&params, "bundleId")?, dto::id(&params, "appId")?,
            dto::text(&params, "mode", 32)?, dto::text(&params, "destination", 32_768)?,
        ));
        if let Some(files) = raw.get("files").and_then(Value::as_array) {
            ensure!(
                files.len() <= 200,
                "Native restore preview page exceeds its limit"
            );
            let entries = files
                .iter()
                .map(|file| {
                    dto::copy_fields(
                        file,
                        &[
                            "id",
                            "path",
                            "action",
                            "conflict",
                            "sourcePath",
                            "destinationPath",
                            "sourceSize",
                            "existingSize",
                        ],
                    )
                })
                .collect::<Vec<_>>();
            let mut conflicts = Vec::new();
            for entry in &entries {
                let action = entry["action"].as_str().unwrap_or("");
                if matches!(action, "replace" | "metadata" | "conflict" | "delete") {
                    let path = entry
                        .get("destinationPath")
                        .or_else(|| entry.get("path"))
                        .and_then(Value::as_str)
                        .ok_or_else(|| anyhow!("Native conflict path is missing"))?;
                    ensure!(
                        path.len() <= 32_768 && !path.chars().any(char::is_control),
                        "Native conflict path is invalid"
                    );
                    conflicts.push(json!({"path":path,"reason":match action {
                        "metadata" => "Existing metadata will be changed",
                        "delete" => "An authenticated deletion-state entry needs acknowledgement",
                        "replace" => "An existing entry will be replaced",
                        _ => "This existing entry blocks the frozen restore plan",
                    }}));
                }
            }
            summary["conflicts"] = json!(conflicts);
            summary["entries"] = json!(entries);
        }
        if let Some(roots) = summary["rootChanges"].as_array() {
            let root_conflicts = roots
                .iter()
                .filter(|root| matches!(root["action"].as_str(), Some("metadata" | "conflict")))
                .map(|root| {
                    json!({
                        "path":root["destinationRelative"],
                        "reason":if root["action"] == "metadata" {
                            "Existing root directory metadata will be changed"
                        } else { "This existing root directory blocks the frozen restore plan" },
                    })
                })
                .collect::<Vec<_>>();
            summary["conflicts"]
                .as_array_mut()
                .unwrap()
                .extend(root_conflicts);
        }
        dto::bounded(&summary, dto::MAX_OUTPUT_BYTES)?;
        let mut previews = self
            .restore_previews
            .lock()
            .map_err(|_| anyhow!("Restore preview lock failed"))?;
        previews.retain(|_, preview| preview.created.elapsed() < PREVIEW_LIFETIME);
        ensure!(
            previews.len() < PREVIEW_LIMIT,
            "The bounded native restore preview cache is full"
        );
        previews.insert(
            id,
            RestorePreview {
                params,
                summary: summary.clone(),
                created: Instant::now(),
            },
        );
        Ok(summary)
    }
}

struct RecoveryLease(Arc<AtomicBool>);
impl Drop for RecoveryLease {
    fn drop(&mut self) {
        self.0.store(false, Ordering::Release);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_root_metadata_is_a_real_root_change_not_a_fictitious_file() {
        let raw = json!({
            "fileCount":0,"conflictCount":0,"metadataChangeCount":1,
            "rootChanges":[{"destinationRelative":"Synthetic.app","kind":"directory","action":"metadata"}],
        });
        let counts = conflict_inventory(&raw, 0).unwrap();
        assert_eq!(counts["conflictCount"], 1);
        assert_eq!(counts["rootChangeCount"], 1);
        assert_eq!(counts["rootMetadataChangeCount"], 1);
        assert_eq!(raw["fileCount"], 0);
    }

    #[test]
    fn root_conflicts_cannot_hide_missing_or_extra_file_conflicts() {
        let mut raw = json!({
            "conflictCount":1,"metadataChangeCount":1,
            "rootChanges":[
                {"destinationRelative":"a","kind":"directory","action":"conflict"},
                {"destinationRelative":"b","kind":"directory","action":"metadata"},
            ],
        });
        assert!(conflict_inventory(&raw, 0).is_ok());
        raw["conflictCount"] = json!(0);
        assert!(conflict_inventory(&raw, 0).is_err());
        raw["conflictCount"] = json!(2);
        assert!(conflict_inventory(&raw, 0).is_err());
        assert!(conflict_inventory(&raw, 1).is_ok());
    }

    #[test]
    fn file_replacements_are_not_authorized_by_extra_root_rows() {
        let raw = json!({
            "conflictCount":0,"replacementCount":1,
            "rootChanges":[{"destinationRelative":"a","kind":"directory","action":"create"}],
        });
        assert!(conflict_inventory(&raw, 0).is_err());
        assert!(conflict_inventory(&raw, 1).is_ok());
    }

    #[test]
    fn malformed_duplicate_and_oversized_root_inventories_fail() {
        let row = json!({"destinationRelative":"a","kind":"directory","action":"metadata"});
        for roots in [
            json!({"not":"an inventory"}),
            json!([row.clone(), row.clone()]),
            json!(vec![row; 65]),
            json!([{"destinationRelative":"a","kind":"directory","action":"replace"}]),
        ] {
            assert!(conflict_inventory(
                &json!({
                    "conflictCount":0,"metadataChangeCount":1,"rootChanges":roots,
                }),
                0
            )
            .is_err());
        }
        assert!(conflict_inventory(
            &json!({
                "conflictCount":0,"replacementCount":"not a count",
            }),
            1
        )
        .is_err());
    }
}
