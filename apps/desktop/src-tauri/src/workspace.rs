// SPDX-License-Identifier: GPL-3.0-only
//! Native gateway for the software/provider workspace. No command accepts a
//! caller-supplied approval flag or replacement parameters when spending a grant.

use std::{
    path::PathBuf,
    sync::{
        atomic::{AtomicBool, AtomicU8, Ordering},
        Arc, Mutex,
    },
    time::Instant,
};

use quicksave_control::{
    approval::validate_uuid,
    runtime::{asynchronous, AppState, Lane},
    workspace::{validate_query, Request, TicketStore, WorkspaceProofs},
};
use quicksave_service::WorkspaceService;
use serde_json::{json, Value};
use tauri::{Manager, State};
use tauri_plugin_dialog::{DialogExt, MessageDialogButtons, MessageDialogKind};
use tokio::sync::OnceCell;

#[derive(Default)]
pub struct WorkspaceHost {
    service: OnceCell<Arc<WorkspaceService>>,
    tickets: Mutex<TicketStore<WorkspaceProofs>>,
    background_enabled: AtomicBool,
    shutdown: AtomicU8,
}

impl WorkspaceHost {
    async fn service(&self) -> Result<Arc<WorkspaceService>, String> {
        self.service
            .get_or_try_init(|| async {
                let (data, home) = workspace_directories()?;
                #[cfg(debug_assertions)]
                if std::env::var_os("QUICKSAVE_DEV_WORKSPACE").is_some() {
                    return WorkspaceService::open_isolated(&data, &home)
                        .await
                        .map_err(public_error);
                }
                WorkspaceService::open(&data, &home)
                    .await
                    .map_err(public_error)
            })
            .await
            .cloned()
    }

    /// Called only from native lifecycle callbacks: no filesystem or vault IO.
    pub fn shutdown_blocked(&self) -> bool {
        self.service
            .get()
            .is_some_and(|service| service.shutdown_blocked())
    }

    pub fn background_enabled(&self) -> bool {
        self.background_enabled.load(Ordering::Acquire)
    }

    fn observe_dashboard(&self, value: &Value) {
        if let Some(enabled) = value
            .pointer("/summary/autosaveEnabled")
            .and_then(Value::as_u64)
        {
            // This controls only whether closing a window hides it. It grants
            // no filesystem or upload authority; the signed worker scope does.
            self.background_enabled
                .store(enabled > 0, Ordering::Release);
        }
    }

    pub fn shutdown_complete(&self) -> bool {
        self.shutdown.load(Ordering::Acquire) == 2
    }

    /// The GUI callback only starts this owned asynchronous join. No worker
    /// joins, vault reads or filesystem operations run on the GUI thread.
    pub fn begin_shutdown(self: Arc<Self>, app: tauri::AppHandle, state: Arc<AppState>) {
        if self
            .shutdown
            .compare_exchange(0, 1, Ordering::AcqRel, Ordering::Acquire)
            .is_err()
        {
            return;
        }
        tauri::async_runtime::spawn(async move {
            let result = match self.service.get() {
                Some(service) => service.shutdown().await,
                None => Ok(()),
            };
            if result.is_ok() {
                self.shutdown.store(2, Ordering::Release);
                app.exit(0);
            } else {
                // Queued autosave can race the first atomic close check. Keep
                // the app alive and let the admitted work reach a known state.
                state.resume_after_failed_shutdown();
                self.shutdown.store(0, Ordering::Release);
                if let Some(window) = app.get_webview_window("main") {
                    let _ = window.show();
                    let _ = window.set_focus();
                }
            }
        });
    }
}

fn workspace_directories() -> Result<(PathBuf, PathBuf), String> {
    #[cfg(debug_assertions)]
    if let Some(directory) = std::env::var_os("QUICKSAVE_DEV_WORKSPACE") {
        let root = PathBuf::from(directory);
        let temporary = std::env::temp_dir()
            .canonicalize()
            .map_err(|_| "Native temporary-directory discovery failed".to_owned())?;
        // Explicit isolated development launch only. Never let a test override
        // point at a No Land checkout, real home, or production application data.
        if !root.is_absolute()
            || root == temporary
            || !root.starts_with(&temporary)
            || root.components().any(|part| {
                matches!(
                    part,
                    std::path::Component::ParentDir | std::path::Component::CurDir
                )
            })
        {
            return Err(
                "The isolated development workspace must be inside the native temporary directory"
                    .into(),
            );
        }
        quicksave_platform::ensure_private_directory(&root).map_err(|_| {
            "The isolated development workspace is not a private real directory".to_owned()
        })?;
        let data = root.join("data");
        let home = root.join("home");
        quicksave_platform::ensure_private_directory(&data)
            .map_err(|_| "Isolated native data creation failed".to_owned())?;
        quicksave_platform::ensure_private_directory(&home)
            .map_err(|_| "Isolated native home creation failed".to_owned())?;
        return Ok((data, home));
    }
    let directories = quicksave_platform::app_directories()
        .map_err(|_| "Native QuickSave directories are unavailable".to_owned())?;
    let data = directories
        .get("data")
        .and_then(Value::as_str)
        .map(PathBuf::from)
        .ok_or_else(|| "Native QuickSave data directory is unavailable".to_owned())?;
    let home = quicksave_platform::home_directory()
        .map_err(|_| "Native account home directory is unavailable".to_owned())?;
    Ok((data, home))
}

// Never forward raw vault, OAuth, provider HTTP or subprocess errors into the
// webview. Validation errors are separately constructed by our pure policies.
fn public_error(error: anyhow::Error) -> String {
    let text = error.to_string().to_ascii_lowercase();
    if text.contains("unsupported") || text.contains("not supported") {
        "This operation is not supported by the current native engine on this platform.".into()
    } else if text.contains("read-only") || text.contains("read only") {
        "This imported connection is read-only. Explicitly allow uploads before changing cloud data.".into()
    } else if text.contains("rclone") && (text.contains("not found") || text.contains("missing")) {
        "The required rclone executable is unavailable. Install the supported version before connecting storage.".into()
    } else if text.contains("scope") || text.contains("identity") || text.contains("grant") {
        "The approved software, provider, or file identity changed. Review it and request a new native approval.".into()
    } else {
        "QuickSave could not complete this request. Check the connection and approved selection; no automatic retry was started.".into()
    }
}

#[cfg(debug_assertions)]
fn validate_isolated_selection(params: &Value) -> Result<(), String> {
    let Some(directory) = std::env::var_os("QUICKSAVE_DEV_WORKSPACE") else {
        return Ok(());
    };
    let root = PathBuf::from(directory);
    let check = |value: &Value| -> Result<(), String> {
        let path = value
            .as_str()
            .ok_or_else(|| "Invalid isolated native path".to_owned())?;
        let path = std::path::Path::new(path);
        if !path.is_absolute()
            || !path.starts_with(&root)
            || path.components().any(|part| {
                matches!(
                    part,
                    std::path::Component::ParentDir | std::path::Component::CurDir
                )
            })
        {
            return Err("The isolated development app can inspect only synthetic paths inside its development workspace.".into());
        }
        Ok(())
    };
    for field in ["stateFile", "destination"] {
        if let Some(value) = params.get(field) {
            check(value)?;
        }
    }
    for value in params
        .get("paths")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
    {
        check(value)?;
    }
    for value in params
        .get("roots")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
    {
        check(&value["path"])?;
    }
    Ok(())
}

#[tauri::command]
pub async fn workspace_query(
    state: State<'_, Arc<AppState>>,
    host: State<'_, Arc<WorkspaceHost>>,
    query: String,
    params: Option<Value>,
) -> Result<Value, String> {
    let params = params.unwrap_or_else(|| json!({}));
    validate_query(&query, &params).map_err(|error| error.to_string())?;
    // Discovery is a separate consent-backed action, not a startup query.
    if query == "noland_import_preview" {
        return Ok(
            json!({"requiresNativeDiscovery":true,"readOnly":true,"manualFallback":"advanced_only"}),
        );
    }
    let host = Arc::clone(host.inner());
    asynchronous(Arc::clone(state.inner()), Lane::Read, async move {
        let value = host
            .service()
            .await?
            .query(&query, params)
            .await
            .map_err(public_error)?;
        host.observe_dashboard(&value);
        Ok(value)
    })
    .await
}

#[tauri::command]
pub async fn workspace_prepare(
    app: tauri::AppHandle,
    state: State<'_, Arc<AppState>>,
    host: State<'_, Arc<WorkspaceHost>>,
    action: String,
    params: Option<Value>,
) -> Result<Value, String> {
    // No selected root, file, keychain item or account is opened by this policy.
    let params = params.unwrap_or_else(|| json!({}));
    #[cfg(debug_assertions)]
    validate_isolated_selection(&params)?;
    let mut request = Request::new(&action, params).map_err(|error| error.to_string())?;
    let host = Arc::clone(host.inner());
    asynchronous(Arc::clone(state.inner()), Lane::Dialog, async move {
        host.tickets
            .lock()
            .map_err(|_| "Native workspace approvals are unavailable".to_owned())?
            .check_capacity(Instant::now())
            .map_err(|error| error.to_string())?;
        let service = host.service().await?;
        let scope = service
            .approval_scope(request.action().name(), request.params())
            .await
            .map_err(public_error)?;
        request
            .bind_scope(scope)
            .map_err(|error| error.to_string())?;
        let confirmation = request
            .confirmation_message()
            .map_err(|error| error.to_string())?;
        let (request, proof, issued_at) = tokio::task::spawn_blocking(move || {
            let window = app
                .get_webview_window("main")
                .ok_or_else(|| "The main QuickSave window is unavailable".to_owned())?;
            let approved = app
                .dialog()
                .message(confirmation)
                .title("Approve QuickSave")
                .parent(&window)
                .buttons(MessageDialogButtons::OkCancel)
                .kind(MessageDialogKind::Warning)
                .blocking_show();
            if !approved {
                return Err("Native authorization canceled; no new access was granted".to_owned());
            }
            let issued_at = Instant::now();
            let proof = WorkspaceProofs::pin(&request).map_err(public_error)?;
            Ok((request, proof, issued_at))
        })
        .await
        .map_err(|_| "Native authorization did not finish".to_owned())??;
        let ticket_id = host
            .tickets
            .lock()
            .map_err(|_| "Native workspace approvals are unavailable".to_owned())?
            .issue(request, proof, issued_at)
            .map_err(|error| error.to_string())?;
        Ok(json!({"ticketId":ticket_id}))
    })
    .await
}

#[tauri::command]
pub async fn workspace_execute(
    state: State<'_, Arc<AppState>>,
    host: State<'_, Arc<WorkspaceHost>>,
    ticket_id: String,
) -> Result<Value, String> {
    let id = validate_uuid(&ticket_id, "Workspace approval ID")?;
    // Spend before any selected filesystem, provider or vault IO, including
    // failing admission or stale authority. No execution params come from JS.
    let ticket = host
        .tickets
        .lock()
        .map_err(|_| "Native workspace approvals are unavailable".to_owned())?
        .consume(id, Instant::now())
        .map_err(|error| error.to_string())?;
    let host = Arc::clone(host.inner());
    asynchronous(Arc::clone(state.inner()), Lane::Mutation, async move {
        let service = host.service().await?;
        let scope = service
            .approval_scope(ticket.request.action().name(), ticket.request.params())
            .await
            .map_err(public_error)?;
        let (mut ticket, identities) = tokio::task::spawn_blocking(move || {
            ticket.verify(&scope).map_err(public_error)?;
            let identities = ticket.proof.worker_identities().map_err(public_error)?;
            Ok::<_, String>((ticket, identities))
        })
        .await
        .map_err(|_| "Native scope verification did not finish".to_owned())??;
        let action = ticket.request.action().name();
        let fingerprint = ticket
            .request
            .native_scope()
            .get("scopeFingerprint")
            .cloned();
        let mut params = ticket.request.take_params();
        if let Some(fingerprint) = fingerprint {
            // This field is never accepted by Request::new from the webview.
            // Bind the service's own admission check to the native-held ticket.
            params["_scopeFingerprint"] = fingerprint;
        }
        if identities.as_array().is_some_and(|paths| !paths.is_empty()) {
            params["_approvedPaths"] = identities;
        }
        let result = service
            .execute_authorized(action, params)
            .await
            .map_err(public_error);
        // Keep the approved handles alive through the entire admitted call.
        // Asynchronous transfer workers independently retain their source scope.
        drop(ticket);
        if let Ok(value) = &result {
            host.observe_dashboard(value);
        }
        result
    })
    .await
}
