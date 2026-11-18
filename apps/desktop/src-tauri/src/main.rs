// SPDX-License-Identifier: GPL-3.0-only
#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

use std::{sync::Arc, time::Instant};

use approval::{validate_uuid, Kind, PathProofs, Scope};
use quicksave_client::{Operation, OperationManager};
use quicksave_control::{approval, runtime};
use runtime::{blocking, AppState, Lane};
use serde_json::{json, Value};
use tauri::{Manager, State};
use tauri_plugin_dialog::{DialogExt, MessageDialogButtons, MessageDialogKind};
use uuid::Uuid;

mod workspace;
use workspace::{workspace_execute, workspace_prepare, workspace_query, WorkspaceHost};

fn message(error: anyhow::Error) -> String {
    format!("{error:#}")
}

fn local_operations_supported(platform: &Value) -> bool {
    platform
        .pointer("/filesystem/durable_create_new")
        .and_then(Value::as_bool)
        .unwrap_or(false)
        && platform
            .pointer("/filesystem/private_directory_creation")
            .and_then(Value::as_bool)
            .unwrap_or(false)
}

#[tauri::command]
fn get_capabilities() -> Value {
    let platform = quicksave_platform::capabilities();
    let local_writes = local_operations_supported(&platform);
    json!({
        "platform": platform,
        "engineLimits": quicksave_client::engine_limits(),
        "integrations": quicksave_integrations::integration_capabilities(),
        "product": "QuickSave",
        "version": env!("CARGO_PKG_VERSION"),
        "releaseStage": "development-preview",
        "localFolderBackups": local_writes,
        "localFolderRestore": local_writes,
        "cloudBackups": false,
        "restoreOverwrites": false,
        "automaticRetention": false,
        "backgroundService": false,
        "keyStorage": "external-private-recovery-file",
        "nolandRepositoryCompatibility": false,
        "nativeOperationApprovalRequired": true,
        "approvalLifetimeSeconds": approval::APPROVAL_TTL.as_secs(),
        "maxUnusedApprovals": approval::MAX_APPROVALS,
        "maxConcurrentReadWorkers": 2,
        "limitations": [
            "Local repository only; cloud providers are not enabled.",
            "Restore requires an existing empty folder.",
            "Close applications before capture; stable files are not an application-atomic snapshot.",
            "Keep QuickSave open while work runs. A separate background service is not installed.",
            "No automatic source deletion, snapshot pruning, or backup execution."
        ]
    })
}

#[tauri::command]
async fn get_directories(state: State<'_, Arc<AppState>>) -> Result<Value, String> {
    blocking(Arc::clone(state.inner()), Lane::Read, || {
        quicksave_platform::app_directories().map_err(message)
    })
    .await
}

#[tauri::command]
async fn discover_applications(state: State<'_, Arc<AppState>>) -> Result<Value, String> {
    blocking(Arc::clone(state.inner()), Lane::Read, || {
        quicksave_integrations::discover_applications().map_err(message)
    })
    .await
}

#[tauri::command]
// Flat fields intentionally preserve the existing Tauri invoke convention.
#[allow(clippy::too_many_arguments)]
async fn authorize_operation(
    app: tauri::AppHandle,
    state: State<'_, Arc<AppState>>,
    kind: String,
    repository: String,
    key_file: String,
    source: Option<String>,
    destination: Option<String>,
    snapshot_id: Option<String>,
) -> Result<String, String> {
    // Pure lexical validation only. In particular, no selected path, recovery
    // key, operation history or repository is opened before native confirmation.
    let scope = Scope::new(
        Kind::parse(&kind)?,
        &repository,
        &key_file,
        source.as_deref(),
        destination.as_deref(),
        snapshot_id.as_deref(),
    )?;
    if !local_operations_supported(&quicksave_platform::capabilities()) {
        return Err(
            "Local repository operations are unsupported here: native durable writes/private key protection are unavailable"
                .into(),
        );
    }
    let state = Arc::clone(state.inner());
    blocking(Arc::clone(&state), Lane::Dialog, move || {
        state.check_approval_capacity()?;
        let window = app
            .get_webview_window("main")
            .ok_or_else(|| "The main QuickSave window is unavailable".to_owned())?;
        let approved = app
            .dialog()
            .message(scope.confirmation_message())
            .title("Authorize one QuickSave operation")
            .parent(&window)
            .buttons(MessageDialogButtons::OkCancel)
            .kind(MessageDialogKind::Warning)
            .blocking_show();
        if !approved {
            return Err("Native authorization canceled; no selected files were opened".into());
        }
        let issued_at = Instant::now();
        let proofs = PathProofs::pin(&scope).map_err(message)?;
        state.record_approval(scope, proofs, issued_at)
    })
    .await
}

struct Submitted {
    manager: Arc<OperationManager>,
    operation: Operation,
}

async fn submit(
    state: Arc<AppState>,
    scope: Scope,
    approval_id: Uuid,
) -> Result<Submitted, String> {
    blocking(Arc::clone(&state), Lane::Mutation, move || {
        // Exact scope is checked and the token spent BEFORE any filesystem IO.
        let approval = state.consume_approval(approval_id, &scope)?;
        approval.verify().map_err(message)?;
        let manager = state
            .load_manager(true)?
            .ok_or_else(|| "Operation manager did not initialize".to_owned())?;
        // History loading, receipt fsync and worker admission all run here,
        // never on the GUI thread. Proofs move into the owned engine worker.
        let operation = manager
            .submit(scope.kind.name(), move || approval.execute())
            .map_err(message)?;
        Ok(Submitted { manager, operation })
    })
    .await
}

#[tauri::command]
async fn initialize_repository(
    state: State<'_, Arc<AppState>>,
    repository: String,
    key_file: String,
    approval_id: String,
) -> Result<Value, String> {
    let scope = Scope::new(Kind::Initialize, &repository, &key_file, None, None, None)?;
    let approval_id = validate_uuid(&approval_id, "Approval ID")?;
    let submitted = submit(Arc::clone(state.inner()), scope, approval_id).await?;
    loop {
        // This is only bounded in-memory receipt access on the async runtime.
        // The client's atomic active flag keeps normal quit blocked through
        // engine execution AND durable completion-receipt publication.
        let current = submitted
            .manager
            .get(&submitted.operation.id)
            .map_err(message)?;
        if current.state == "completed" {
            return current
                .result
                .ok_or_else(|| "Initialization completed without a receipt".to_owned());
        }
        if current.state != "running" {
            return Err(current
                .error
                .unwrap_or_else(|| "Initialization did not complete".to_owned()));
        }
        tokio::time::sleep(std::time::Duration::from_millis(100)).await;
    }
}

#[tauri::command]
async fn backup_folder(
    state: State<'_, Arc<AppState>>,
    repository: String,
    source: String,
    key_file: String,
    approval_id: String,
) -> Result<Operation, String> {
    let scope = Scope::new(
        Kind::Backup,
        &repository,
        &key_file,
        Some(&source),
        None,
        None,
    )?;
    let approval_id = validate_uuid(&approval_id, "Approval ID")?;
    Ok(submit(Arc::clone(state.inner()), scope, approval_id)
        .await?
        .operation)
}

#[tauri::command]
async fn list_snapshots(
    state: State<'_, Arc<AppState>>,
    repository: String,
    key_file: String,
    approval_id: String,
) -> Result<Value, String> {
    let scope = Scope::new(Kind::List, &repository, &key_file, None, None, None)?;
    let approval_id = validate_uuid(&approval_id, "Approval ID")?;
    let state = Arc::clone(state.inner());
    blocking(Arc::clone(&state), Lane::Read, move || {
        let approval = state.consume_approval(approval_id, &scope)?;
        approval.execute().map_err(message)
    })
    .await
}

#[tauri::command]
async fn restore_snapshot(
    state: State<'_, Arc<AppState>>,
    repository: String,
    snapshot_id: String,
    destination: String,
    key_file: String,
    approval_id: String,
) -> Result<Operation, String> {
    let scope = Scope::new(
        Kind::Restore,
        &repository,
        &key_file,
        None,
        Some(&destination),
        Some(&snapshot_id),
    )?;
    let approval_id = validate_uuid(&approval_id, "Approval ID")?;
    Ok(submit(Arc::clone(state.inner()), scope, approval_id)
        .await?
        .operation)
}

#[tauri::command]
async fn operation_status(
    state: State<'_, Arc<AppState>>,
    operation_id: String,
) -> Result<Operation, String> {
    validate_uuid(&operation_id, "Operation ID")?;
    let state = Arc::clone(state.inner());
    blocking(Arc::clone(&state), Lane::Read, move || {
        state
            .load_manager(false)?
            .ok_or_else(|| "No QuickSave operation history exists".to_owned())?
            .get(&operation_id)
            .map_err(message)
    })
    .await
}

#[tauri::command]
async fn operation_history(state: State<'_, Arc<AppState>>) -> Result<Vec<Operation>, String> {
    let state = Arc::clone(state.inner());
    blocking(Arc::clone(&state), Lane::Read, move || {
        match state.load_manager(false)? {
            Some(manager) => manager.history().map_err(message),
            None => Ok(Vec::new()),
        }
    })
    .await
}

fn main() {
    tauri::Builder::default()
        .plugin(tauri_plugin_dialog::init())
        .manage(Arc::new(AppState::new()))
        .manage(Arc::new(WorkspaceHost::default()))
        .setup(|app| {
            #[cfg(debug_assertions)]
            if std::env::var_os("QUICKSAVE_DEV_WORKSPACE").is_some() {
                if let Some(window) = app.get_webview_window("main") {
                    window.set_title("QuickSave — isolated development")?;
                }
            }
            Ok(())
        })
        .invoke_handler(tauri::generate_handler![
            // The desktop has one native authority boundary. The older local-
            // repository commands remain separate CLI/library code, not a
            // fallback or unconsented discovery path reachable from this UI.
            workspace_query,
            workspace_prepare,
            workspace_execute
        ])
        .on_window_event(|window, event| {
            if window.label() == "main" {
                if let tauri::WindowEvent::CloseRequested { api, .. } = event {
                    let state = window.state::<Arc<AppState>>();
                    let workspace = window.state::<Arc<WorkspaceHost>>();
                    if workspace.shutdown_complete() {
                        return;
                    }
                    api.prevent_close();
                    if workspace.background_enabled() {
                        // Closing a window is not quitting an opted-in autosave
                        // worker. Dock activation reopens this same window.
                        let _ = window.hide();
                    } else if workspace.shutdown_blocked() || state.prevent_shutdown() {
                        let _ = window.set_focus();
                    } else {
                        Arc::clone(workspace.inner())
                            .begin_shutdown(window.app_handle().clone(), Arc::clone(state.inner()));
                    }
                }
            }
        })
        .build(tauri::generate_context!())
        .expect("QuickSave could not start")
        .run(|app, event| match event {
            tauri::RunEvent::ExitRequested { api, .. } => {
                let state = app.state::<Arc<AppState>>();
                let workspace = app.state::<Arc<WorkspaceHost>>();
                if workspace.shutdown_complete() {
                    return;
                }
                api.prevent_exit();
                if workspace.shutdown_blocked() || state.prevent_shutdown() {
                    if let Some(window) = app.get_webview_window("main") {
                        let _ = window.show();
                        let _ = window.set_focus();
                    }
                } else {
                    Arc::clone(workspace.inner())
                        .begin_shutdown(app.clone(), Arc::clone(state.inner()));
                }
            }
            #[cfg(target_os = "macos")]
            tauri::RunEvent::Reopen { .. } => {
                if let Some(window) = app.get_webview_window("main") {
                    let _ = window.show();
                    let _ = window.set_focus();
                }
            }
            _ => {}
        });
}
