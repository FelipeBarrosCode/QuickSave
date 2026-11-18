// SPDX-License-Identifier: GPL-3.0-only
//! Bounded input validation and allowlisted, non-secret UI projections.

use anyhow::{bail, ensure, Result};
use serde_json::{json, Map, Value};
use std::collections::BTreeSet;

pub const MAX_INPUT_BYTES: usize = 1024 * 1024;
pub const MAX_OUTPUT_BYTES: usize = 8 * 1024 * 1024;
pub const MAX_WORK_BYTES: usize = 256 * 1024 * 1024;
pub const MAX_PAGE: usize = 500;
pub const MAX_ACTIVITY: usize = 128;
pub const MAX_SELECTION: usize = 4096;
pub const MISSING_RCLONE: &str =
    "The required rclone executable is missing; install rclone >=1.76 before connecting storage.";
pub const UNSUPPORTED_PLATFORM: &str =
    "Native storage operations are unsupported on this platform.";
pub const READ_ONLY_PROVIDER: &str =
    "This provider is read-only; explicitly enable uploads with native consent first.";
pub const NATIVE_FAILURE: &str =
    "The requested native engine operation is unavailable or failed safely.";
pub const OAUTH_STORAGE_UNAVAILABLE: &str = "Native OAuth storage is unavailable until refreshed tokens can be durably persisted; no browser was opened and no credentials were stored.";

/// Inspect a bounded prefix only to select a fixed category. Source error text
/// is never returned, logged, attached to errors or retained in operation DTOs.
pub fn engine_error(error: &anyhow::Error) -> &'static str {
    struct Prefix(String);
    impl std::fmt::Write for Prefix {
        fn write_str(&mut self, text: &str) -> std::fmt::Result {
            let remaining = 4096usize.saturating_sub(self.0.len());
            let mut end = text.len().min(remaining);
            while !text.is_char_boundary(end) {
                end -= 1;
            }
            self.0.push_str(&text[..end]);
            Ok(())
        }
    }
    let mut prefix = Prefix(String::new());
    let _ = std::fmt::write(&mut prefix, format_args!("{error}"));
    let prefix = prefix.0.to_ascii_lowercase();
    if prefix.contains("rclone is not installed") || prefix.contains("rclone executable is missing")
    {
        MISSING_RCLONE
    } else if prefix.contains("unsupported on this platform")
        || prefix.contains("unsupported platform")
    {
        UNSUPPORTED_PLATFORM
    } else if prefix.contains("provider is read-only") || prefix.contains("no native write grant") {
        READ_ONLY_PROVIDER
    } else {
        NATIVE_FAILURE
    }
}

fn public_activity_error(error: &str) -> &'static str {
    match error {
        MISSING_RCLONE => MISSING_RCLONE,
        UNSUPPORTED_PLATFORM => UNSUPPORTED_PLATFORM,
        READ_ONLY_PROVIDER => READ_ONLY_PROVIDER,
        OAUTH_STORAGE_UNAVAILABLE => OAUTH_STORAGE_UNAVAILABLE,
        _ => "The native operation did not complete safely. Review access and retry the original plan.",
    }
}

pub fn bounded(value: &Value, limit: usize) -> Result<()> {
    bounded_size(value, limit).map(|_| ())
}

pub fn bounded_size(value: &Value, limit: usize) -> Result<usize> {
    fn visit(value: &Value, depth: usize, nodes: &mut usize) -> Result<()> {
        ensure!(
            depth <= 24 && *nodes > 0,
            "JSON structure exceeds its bounded limit"
        );
        *nodes -= 1;
        match value {
            Value::Array(values) => {
                ensure!(
                    values.len() <= 250_000,
                    "JSON array exceeds its entry limit"
                );
                for value in values {
                    visit(value, depth + 1, nodes)?;
                }
            }
            Value::Object(object) => {
                ensure!(object.len() <= 256, "JSON object exceeds its field limit");
                for (key, value) in object {
                    ensure!(key.len() <= 32_768, "JSON object key exceeds its bound");
                    visit(value, depth + 1, nodes)?;
                }
            }
            _ => {}
        }
        Ok(())
    }
    let mut nodes = (limit / 2).clamp(100_000, 8_000_000);
    visit(value, 0, &mut nodes)?;
    struct Counter {
        size: usize,
        limit: usize,
    }
    impl std::io::Write for Counter {
        fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
            self.size = self
                .size
                .checked_add(bytes.len())
                .filter(|size| *size <= self.limit)
                .ok_or_else(|| std::io::Error::other("JSON exceeds its bounded byte limit"))?;
            Ok(bytes.len())
        }
        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }
    // Exact streaming size, no duplicate credential/document buffer and no
    // six-times overestimate that rejects legitimate large capture evidence.
    let mut counter = Counter { size: 0, limit };
    serde_json::to_writer(&mut counter, value)
        .map_err(|_| anyhow::anyhow!("JSON exceeds its bounded byte limit"))?;
    Ok(counter.size)
}

pub fn text<'a>(value: &'a Value, field: &str, max: usize) -> Result<&'a str> {
    let text = value
        .get(field)
        .and_then(Value::as_str)
        .ok_or_else(|| anyhow::anyhow!("A required text field is missing"))?;
    ensure!(
        !text.trim().is_empty() && text.len() <= max && !text.chars().any(char::is_control),
        "A text field is invalid"
    );
    Ok(text)
}

pub fn id<'a>(value: &'a Value, field: &str) -> Result<&'a str> {
    let value = text(value, field, 512)?;
    ensure!(
        value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || b"._:-@".contains(&byte)),
        "An identifier is invalid"
    );
    Ok(value)
}

pub fn boolean(value: &Value, field: &str) -> Result<bool> {
    value
        .get(field)
        .and_then(Value::as_bool)
        .ok_or_else(|| anyhow::anyhow!("A required boolean field is missing"))
}

pub fn limit(value: &Value) -> Result<usize> {
    let limit = match value.get("limit") {
        None => 100,
        Some(value) => value
            .as_u64()
            .ok_or_else(|| anyhow::anyhow!("Page limit must be an integer"))?,
    };
    ensure!(
        limit > 0 && limit <= MAX_PAGE as u64,
        "Page limit must be between 1 and 500"
    );
    Ok(limit as usize)
}

pub fn file_ids(value: &Value) -> Result<Option<Vec<String>>> {
    let Some(ids) = value.get("fileIds") else {
        return Ok(None);
    };
    let ids = ids
        .as_array()
        .ok_or_else(|| anyhow::anyhow!("File selection must be an array"))?;
    ensure!(
        !ids.is_empty() && ids.len() <= MAX_SELECTION,
        "File selection must contain 1 to 4096 entries"
    );
    let mut seen = BTreeSet::new();
    for item in ids {
        let item = item
            .as_str()
            .ok_or_else(|| anyhow::anyhow!("Invalid file identity"))?;
        ensure!(
            !item.is_empty() && item.len() <= 1024 && !item.chars().any(char::is_control),
            "Invalid file identity"
        );
        ensure!(seen.insert(item.to_owned()), "Duplicate file identity");
    }
    Ok(Some(seen.into_iter().collect()))
}

pub fn validate_action(action: &str, input: &Value) -> Result<()> {
    bounded(input, 8 * 1024 * 1024)?;
    bounded(&without_native_fingerprint(input), MAX_INPUT_BYTES)?;
    let fields: &[&str] = match action {
        "connect_provider" => &["kind", "name", "bucket", "prefix", "fields", "credentials"],
        "connect_oauth" => &["kind", "name", "clientId", "clientSecret", "fields"],
        "disconnect_provider"
        | "verify_provider"
        | "approve_provider_writes"
        | "authorize_provider_writes" => &["providerId"],
        "reauthorize_provider" => &["providerId", "credentials"],
        "export_recovery_key" => &["providerId", "destination"],
        "discover_noland_import" | "refresh_app_tracking" => &[],
        "import_noland" => &["sourceId", "stateFile", "profileIds"],
        "enable_app_tracking" => &["enabled", "defaultProviderId", "roles"],
        "track_software" => &["softwareId", "appId", "name", "roots", "providerId"],
        "add_files" => &["softwareId", "name", "paths", "providerId"],
        "set_provider" => &["softwareId", "providerId"],
        "set_autosave" => &["softwareId", "providerId", "enabled"],
        "upload" => &["softwareId", "providerId", "fileIds"],
        "preview_upload_all" => &["providerId", "softwareIds"],
        "upload_all" => &["planSetId"],
        "preview_restore" => &[
            "providerId",
            "bundleId",
            "appId",
            "destination",
            "fileIds",
            "mode",
        ],
        "download" => &["restorePreviewId", "overwriteAcknowledgement"],
        "preview_delete" => &["providerId", "bundleId", "appId"],
        "delete_cloud" => &["providerId", "previewId", "acknowledgeDependencies"],
        "cancel" | "retry" | "recover_restore" => &["operationId"],
        _ => bail!("This workspace action is not supported"),
    };
    let object = input
        .as_object()
        .ok_or_else(|| anyhow::anyhow!("Parameters must be a JSON object"))?;
    ensure!(
        object.keys().all(|key| fields.contains(&key.as_str())
            || key == "_scopeFingerprint"
            || key == "_approvedPaths"),
        "An unexpected action parameter was supplied"
    );
    if let Some(fingerprint) = object.get("_scopeFingerprint") {
        ensure!(
            fingerprint
                .as_str()
                .is_some_and(|s| s.len() == 64 && s.bytes().all(|b| b.is_ascii_hexdigit())),
            "Invalid native scope fingerprint"
        );
    }
    if let Some(proofs) = object.get("_approvedPaths") {
        let proofs = proofs
            .as_array()
            .ok_or_else(|| anyhow::anyhow!("Invalid native approved-path proofs"))?;
        ensure!(
            !proofs.is_empty() && proofs.len() <= 4096,
            "Native approved-path proof count exceeds its bound"
        );
        for proof in proofs {
            absolute(text(proof, "path", 32_768)?)?;
            ensure!(
                matches!(proof["kind"].as_str(), Some("directory" | "file")),
                "Invalid native approved-path proof kind"
            );
            serde_json::from_value::<quicksave_state::NativeFileStampID>(proof["identity"].clone())
                .map_err(|_| anyhow::anyhow!("Native approved-path identity is invalid"))?;
            if proof["kind"] == "file" {
                serde_json::from_value::<quicksave_platform::FileStamp>(proof["stamp"].clone())
                    .map_err(|_| anyhow::anyhow!("Native approved-file stamp is invalid"))?;
                serde_json::from_value::<quicksave_state::NativeFileStampID>(
                    proof["parentIdentity"].clone(),
                )
                .map_err(|_| anyhow::anyhow!("Native approved-file parent identity is invalid"))?;
            }
        }
    }
    match action {
        "connect_provider" | "connect_oauth" => {
            id(input, "kind")?;
            text(input, "name", 512)?;
        }
        "disconnect_provider"
        | "verify_provider"
        | "approve_provider_writes"
        | "authorize_provider_writes" => {
            id(input, "providerId")?;
        }
        "reauthorize_provider" => {
            id(input, "providerId")?;
            if let Some(credentials) = input.get("credentials") {
                ensure!(
                    credentials.is_object(),
                    "Provider credentials must be an object"
                );
                bounded(credentials, 128 * 1024)?;
            }
        }
        "export_recovery_key" => {
            id(input, "providerId")?;
            absolute(text(input, "destination", 4096)?)?;
        }
        "track_software" => {
            text(input, "name", 512)?;
            let roots = input["roots"]
                .as_array()
                .ok_or_else(|| anyhow::anyhow!("Approved source roots are required"))?;
            ensure!(
                !roots.is_empty() && roots.len() <= 16,
                "Track between 1 and 16 roots"
            );
            for root in roots {
                let root = root
                    .as_object()
                    .ok_or_else(|| anyhow::anyhow!("Invalid source root"))?;
                ensure!(
                    root.keys()
                        .all(|k| ["id", "path", "role", "source"].contains(&k.as_str())),
                    "Unexpected root authority field"
                );
                absolute(text(&Value::Object(root.clone()), "path", 32_768)?)?;
            }
        }
        "add_files" => {
            let paths = input["paths"]
                .as_array()
                .ok_or_else(|| anyhow::anyhow!("Explicit file paths are required"))?;
            ensure!(
                !paths.is_empty() && paths.len() <= 4096,
                "Select between 1 and 4096 files"
            );
            for path in paths {
                absolute(
                    path.as_str()
                        .ok_or_else(|| anyhow::anyhow!("Invalid file path"))?,
                )?;
            }
        }
        "set_provider" | "set_autosave" | "upload" => {
            id(input, "softwareId")?;
            id(input, "providerId")?;
            if action == "set_autosave" {
                boolean(input, "enabled")?;
            }
            if action == "upload" {
                file_ids(input)?;
            }
        }
        "preview_restore" | "preview_delete" => {
            id(input, "providerId")?;
            id(input, "bundleId")?;
            id(input, "appId")?;
            if action == "preview_restore" {
                absolute(text(input, "destination", 32_768)?)?;
                file_ids(input)?;
                ensure!(
                    matches!(
                        input["mode"].as_str(),
                        Some("create_new" | "merge" | "replace")
                    ),
                    "Unknown native restore mode"
                );
            }
        }
        "download" => {
            id(input, "restorePreviewId")?;
            boolean(input, "overwriteAcknowledgement")?;
        }
        "preview_upload_all" => {
            id(input, "providerId")?;
            if let Some(ids) = input.get("softwareIds") {
                let ids = ids
                    .as_array()
                    .ok_or_else(|| anyhow::anyhow!("Invalid application selection"))?;
                ensure!(
                    !ids.is_empty() && ids.len() <= 4096,
                    "Invalid application selection size"
                );
                let mut unique = BTreeSet::new();
                for value in ids {
                    let value = value
                        .as_str()
                        .ok_or_else(|| anyhow::anyhow!("Invalid application ID"))?;
                    id(&json!({"id":value}), "id")?;
                    ensure!(unique.insert(value), "Duplicate application selection");
                }
            }
        }
        "upload_all" => {
            id(input, "planSetId")?;
        }
        "enable_app_tracking" => {
            boolean(input, "enabled")?;
            if input.get("defaultProviderId").is_some() {
                id(input, "defaultProviderId")?;
            }
            if let Some(roles) = input.get("roles") {
                let roles = roles
                    .as_array()
                    .ok_or_else(|| anyhow::anyhow!("Invalid application role policy"))?;
                ensure!(
                    !roles.is_empty() && roles.len() <= 4,
                    "Invalid application role count"
                );
                let mut unique = BTreeSet::new();
                for role in roles {
                    let role = role
                        .as_str()
                        .ok_or_else(|| anyhow::anyhow!("Invalid application role"))?;
                    ensure!(
                        ["installation", "save", "config", "runtime"].contains(&role)
                            && unique.insert(role),
                        "Unknown or duplicate application root role"
                    );
                }
            }
        }
        "delete_cloud" => {
            id(input, "providerId")?;
            id(input, "previewId")?;
            boolean(input, "acknowledgeDependencies")?;
        }
        "cancel" | "retry" | "recover_restore" => {
            id(input, "operationId")?;
        }
        "import_noland" => {
            ensure!(
                input.get("sourceId").is_some() != input.get("stateFile").is_some(),
                "Select exactly one discovered No Land source or advanced source file"
            );
            if input.get("sourceId").is_some() {
                id(input, "sourceId")?;
            }
            if input.get("stateFile").is_some() {
                absolute(text(input, "stateFile", 32_768)?)?;
            }
            if let Some(ids) = input.get("profileIds") {
                let ids = ids
                    .as_array()
                    .ok_or_else(|| anyhow::anyhow!("Invalid profile selection"))?;
                ensure!(
                    !ids.is_empty() && ids.len() <= 256,
                    "Invalid profile selection size"
                );
                for item in ids {
                    ensure!(
                        item.as_str().is_some_and(|s| !s.is_empty()
                            && s.len() <= 512
                            && !s.chars().any(char::is_control)),
                        "Invalid profile identity"
                    );
                }
            }
        }
        _ => {}
    }
    Ok(())
}

pub fn absolute(path: &str) -> Result<()> {
    let path = std::path::Path::new(path);
    ensure!(
        path.is_absolute() && path.parent().is_some(),
        "Select a non-root absolute path"
    );
    ensure!(
        path.as_os_str().len() <= 32_768
            && !path
                .as_os_str()
                .to_string_lossy()
                .chars()
                .any(char::is_control),
        "Invalid path"
    );
    ensure!(
        !path.components().any(|part| matches!(
            part,
            std::path::Component::ParentDir | std::path::Component::CurDir
        )),
        "Dot path components are not allowed"
    );
    Ok(())
}

pub fn fingerprint(value: &Value) -> Result<String> {
    struct HashWriter(blake3::Hasher);
    impl std::io::Write for HashWriter {
        fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
            self.0.update(bytes);
            Ok(bytes.len())
        }
        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }
    let mut writer = HashWriter(blake3::Hasher::new());
    serde_json::to_writer(&mut writer, value)?;
    Ok(writer.0.finalize().to_hex().to_string())
}

fn clean_text(value: Option<&Value>, max: usize) -> Option<Value> {
    value
        .and_then(Value::as_str)
        .filter(|s| !s.is_empty() && s.len() <= max && !s.chars().any(char::is_control))
        .map(|s| Value::String(s.to_owned()))
}

pub fn provider(value: &Value, verified: bool) -> Result<Value> {
    id(value, "id")?;
    text(value, "name", 512)?;
    id(value, "kind")?;
    let mut output = json!({
        "id": value["id"], "name": value["name"], "kind": value["kind"],
        "status": match value["status"].as_str() {
            Some("connected") if verified => "connected",
            Some("connected" | "connecting") => "connecting",
            Some("error") => "error",
            _ => "disconnected",
        },
        "origin": if value["origin"] == "noland" { "noland" } else { "quicksave" },
        "readOnly": value["readOnly"].as_bool().unwrap_or(true),
        "error": Value::Null,
    });
    if value.get("error").is_some_and(|v| !v.is_null()) {
        output["error"] = json!("Provider access has not been verified. Review the connection.");
    }
    Ok(output)
}

pub fn software(value: &Value) -> Result<Value> {
    id(value, "id")?;
    text(value, "name", 512)?;
    let tracked = value["tracked"].as_bool().unwrap_or(false);
    let status = match value["status"].as_str() {
        Some("needs_backup" | "saved" | "checking" | "uploading" | "error") if tracked => {
            value["status"].clone()
        }
        _ if tracked => json!("needs_backup"),
        _ => json!("not_tracked"),
    };
    let mut output = json!({
        "id":value["id"], "name":value["name"], "tracked":tracked,
        "status":status, "autosave":tracked && value["autosave"].as_bool().unwrap_or(false),
        "dirty":tracked && value["dirty"].as_bool().unwrap_or(true),
        "error":if value.get("error").is_some_and(|v| !v.is_null()) { json!("Source reconciliation or new native approval is required.") } else { Value::Null },
    });
    for field in ["appId", "providerId", "lastSavedAt"] {
        if let Some(text) = clean_text(value.get(field), 1024) {
            output[field] = text;
        }
    }
    for field in ["fileCount", "logicalBytes"] {
        if value[field].as_u64().is_some() {
            output[field] = value[field].clone();
        }
    }
    if let Some(roots) = value.get("roots").and_then(Value::as_array) {
        ensure!(
            roots.len() <= 64,
            "Native software root projection exceeded its bound"
        );
        let mut entries = Vec::with_capacity(roots.len());
        let mut seen = BTreeSet::new();
        for root in roots {
            let root_id = id(root, "id")?;
            ensure!(
                seen.insert(root_id),
                "Duplicate native software root identifier"
            );
            let path = text(root, "path", 32_768)?;
            absolute(path)?;
            let mut entry = json!({"id":root_id,"path":path});
            if let Some(role) = clean_text(root.get("role"), 64) {
                entry["role"] = role;
            }
            for field in ["fileCount", "logicalBytes"] {
                if let Some(count) = root[field].as_u64() {
                    entry[field] = json!(count);
                }
            }
            entries.push(entry);
        }
        output["roots"] = json!(entries);
    }
    Ok(output)
}

pub fn activity(value: &Value) -> Result<Value> {
    id(value, "id")?;
    let kind = match value["kind"].as_str() {
        Some("upload" | "download" | "delete" | "connect" | "autosave") => value["kind"].clone(),
        _ => bail!("Native operation kind is unavailable"),
    };
    let state = match value["state"].as_str() {
        Some("queued" | "running" | "completed" | "failed" | "cancelled" | "interrupted") => {
            value["state"].clone()
        }
        _ => bail!("Native operation state is unavailable"),
    };
    let mut output = json!({
        "id":value["id"], "kind":kind,
        "name":clean_text(value.get("name"), 512).unwrap_or_else(|| json!("Native storage operation")),
        "state":state, "canCancel":value["canCancel"].as_bool().unwrap_or(false),
        "canRetry":value["canRetry"].as_bool().unwrap_or(false), "error":Value::Null,
        "canRecover":value["canRecover"].as_bool().unwrap_or(false),
    });
    for field in [
        "providerId",
        "softwareId",
        "planSetId",
        "startedAt",
        "finishedAt",
    ] {
        if let Some(value) = clean_text(value.get(field), 1024) {
            output[field] = value;
        }
    }
    if let Some(phase) = value.get("phase").and_then(Value::as_str) {
        // Native phases are enums, not free-form subprocess output.
        if [
            "preparing",
            "queued",
            "native_operation",
            "storing_native_credentials",
            "verifying_provider_access",
            "checking_native_prerequisites",
            "authorizing_oauth",
            "hashing",
            "packing",
            "uploading",
            "downloading",
            "capture_and_upload",
            "committing",
            "releasing_repository",
            "deleting_packs",
            "finalizing",
            "finalized",
            "completed",
            "cancelled",
            "failed",
            "interrupted",
            "scanning",
            "capturing",
            "verifying",
            "restoring",
            "publishing",
            "reconciling",
            "native_status_unavailable",
            "durable_finalization_required",
        ]
        .contains(&phase)
        {
            output["phase"] = json!(phase);
        }
    }
    for field in [
        "completedBytes",
        "totalBytes",
        "completedFiles",
        "totalFiles",
    ] {
        if value[field].as_u64().is_some() {
            output[field] = value[field].clone();
        }
    }
    if value.get("error").is_some_and(|value| !value.is_null()) {
        output["error"] = json!(public_activity_error(value["error"].as_str().unwrap_or("")));
    }
    if let Some(operation_id) = value.get("operationId") {
        ensure!(
            operation_id == &value["id"],
            "Native activity changed its original operation identity"
        );
        output["operationId"] = operation_id.clone();
    }
    if let Some(batch) = value.get("batch").filter(|batch| !batch.is_null()) {
        ensure!(batch.is_object(), "Native batch activity is invalid");
        let mut summary = json!({});
        for field in [
            "softwareCount",
            "completed",
            "failed",
            "cancelled",
            "interrupted",
            "active",
            "notStarted",
            "unknown",
            "awaitingFinalization",
            "reconciliationGapCount",
        ] {
            if let Some(count) = batch[field].as_u64() {
                ensure!(
                    count <= 4096,
                    "Native batch activity exceeded the approved instance bound"
                );
                summary[field] = json!(count);
            }
        }
        if let Some(jobs) = batch["jobCount"].as_u64() {
            ensure!(jobs <= 32, "Native batch job count exceeded its bound");
            summary["jobCount"] = json!(jobs);
        }
        for field in [
            "closeBlocked",
            "reconciliationRequired",
            "requiresNativeReattachment",
            "previewOnly",
        ] {
            if let Some(flag) = batch[field].as_bool() {
                summary[field] = json!(flag);
            }
        }
        if let Some(progress) = batch["progress"].as_array() {
            ensure!(
                progress.len() <= 64,
                "Native batch progress exceeded its phase bound"
            );
            let mut phases = Vec::with_capacity(progress.len());
            for row in progress {
                let phase = text(row, "phase", 128)?;
                let unit = text(row, "unit", 32)?;
                ensure!(
                    matches!(unit, "bytes" | "files" | "items"),
                    "Native batch progress has an unknown unit"
                );
                let completed = row["completed"].as_u64().ok_or_else(|| {
                    anyhow::anyhow!("Native batch progress completion is missing")
                })?;
                let total =
                    if row["total"].is_null() {
                        None
                    } else {
                        Some(row["total"].as_u64().ok_or_else(|| {
                            anyhow::anyhow!("Native batch progress total is invalid")
                        })?)
                    };
                let mut item =
                    json!({"phase":phase,"unit":unit,"completed":completed,"total":total});
                if let Some(children) = row["reportingChildren"].as_u64() {
                    ensure!(
                        children <= 4096,
                        "Native progress child count exceeded its bound"
                    );
                    item["reportingChildren"] = json!(children);
                }
                phases.push(item);
            }
            summary["progress"] = json!(phases);
        }
        output["batch"] = summary;
    }
    Ok(output)
}

pub fn terminal(value: &Value) -> bool {
    matches!(
        value["state"].as_str(),
        Some("completed" | "failed" | "cancelled" | "interrupted")
    )
}

pub fn files(value: &Value, requested_limit: usize) -> Result<Value> {
    bounded(value, MAX_OUTPUT_BYTES)?;
    let entries = value["files"]
        .as_array()
        .ok_or_else(|| anyhow::anyhow!("Native file listing is unavailable"))?;
    ensure!(
        entries.len() <= requested_limit,
        "Native file listing exceeded the requested page limit"
    );
    let mut output = Vec::with_capacity(entries.len());
    for entry in entries {
        text(entry, "id", 1024)?;
        text(entry, "name", 512)?;
        let path = text(entry, "path", 32_768)?;
        ensure!(
            !path.starts_with('/')
                // Display source-native names exactly. A backslash may be a
                // literal Unix filename, never a separator to normalize here.
                // Restore target compatibility is checked by the native plan.
                && !path.contains('\0')
                && path
                    .split('/')
                    .all(|p| !p.is_empty() && p != "." && p != ".."),
            "Native file listing escaped the logical root"
        );
        let directory = entry["directory"]
            .as_bool()
            .ok_or_else(|| anyhow::anyhow!("Invalid native directory flag"))?;
        let size = entry["size"]
            .as_u64()
            .ok_or_else(|| anyhow::anyhow!("Invalid native file size"))?;
        let mut item = json!({"id":entry["id"],"name":entry["name"],"path":path,"directory":directory,"size":size});
        if let Some(root) = clean_text(entry.get("rootId"), 512) {
            item["rootId"] = root;
        }
        if let Some(role) = clean_text(entry.get("role"), 64) {
            item["role"] = role;
        }
        if let Some(status) = entry.get("status").and_then(Value::as_str).filter(|s| {
            [
                "saved",
                "changed",
                "pending",
                "new",
                "deleted",
                "unknown",
                "needs_backup",
                "checking",
            ]
            .contains(s)
        }) {
            item["status"] = json!(status);
        }
        output.push(item);
    }
    let mut result = json!({"files":output});
    if let Some(cursor) = clean_text(value.get("nextCursor"), 4096) {
        result["nextCursor"] = cursor;
    }
    Ok(result)
}

pub fn bundle(value: &Value, provider_id: &str) -> Result<Value> {
    id(value, "id")?;
    id(value, "appId")?;
    text(value, "name", 512)?;
    if let Some(id) = value.get("providerId").and_then(Value::as_str) {
        ensure!(id == provider_id, "Native catalog provider scope mismatch");
    }
    let mut output = json!({"id":value["id"],"appId":value["appId"],"name":value["name"],"providerId":provider_id});
    for field in ["createdAt", "platform", "format", "compatibility"] {
        if let Some(text) = clean_text(value.get(field), 512) {
            output[field] = text;
        }
    }
    for field in ["fileCount", "logicalBytes"] {
        if value[field].as_u64().is_some() {
            output[field] = value[field].clone();
        }
    }
    Ok(output)
}

pub fn provider_record<'a>(snapshot: &'a Value, provider_id: &str) -> Result<&'a Value> {
    snapshot["providers"]
        .as_array()
        .and_then(|providers| {
            providers
                .iter()
                .find(|provider| provider["id"] == provider_id)
        })
        .ok_or_else(|| anyhow::anyhow!("Provider was not found"))
}

pub fn software_record<'a>(snapshot: &'a Value, software_id: &str) -> Result<&'a Value> {
    snapshot["software"]
        .as_array()
        .and_then(|software| {
            software
                .iter()
                .find(|software| software["id"] == software_id)
        })
        .ok_or_else(|| anyhow::anyhow!("Tracked software was not found"))
}

pub fn without_native_fingerprint(value: &Value) -> Value {
    let mut value = value.clone();
    if let Some(object) = value.as_object_mut() {
        object.remove("_scopeFingerprint");
        object.remove("_approvedPaths");
    }
    value
}

pub fn copy_fields(source: &Value, fields: &[&str]) -> Value {
    Value::Object(
        fields
            .iter()
            .filter_map(|field| source.get(*field).map(|v| (field.to_string(), v.clone())))
            .collect::<Map<_, _>>(),
    )
}

/// Discovery is metadata only. Native proofs, source stamps and credential
/// account references stay in the source registry rather than in renderer DTOs.
pub fn noland_discovery(raw: &Value) -> Result<Value> {
    let candidates = raw["candidates"]
        .as_array()
        .ok_or_else(|| anyhow::anyhow!("Native No Land discovery has no candidate list"))?;
    ensure!(
        candidates.len() <= 32,
        "Native No Land discovery exceeded its bound"
    );
    let mut ids = BTreeSet::new();
    let candidates = candidates
        .iter()
        .map(|source| {
            let id = id(source, "sourceId")?;
            ensure!(
                ids.insert(id.to_owned()),
                "Native source identifiers are duplicated"
            );
            Ok(json!({
                "id":id, "label":text(source, "name", 512)?,
                "path":text(source, "pathSafeSummary", 4096)?,
            }))
        })
        .collect::<Result<Vec<_>>>()?;
    let mut result = json!({"candidates":candidates,"manualFallback":"advanced_only"});
    if let Some(selected) = raw.get("selectedSourceId").and_then(Value::as_str) {
        ensure!(
            ids.contains(selected),
            "Native source selection is not a discovered candidate"
        );
        result["selectedId"] = json!(selected);
    }
    if let Some(rejected) = raw["rejectedCandidates"].as_u64() {
        result["rejectedCandidates"] = json!(rejected);
    }
    Ok(result)
}
