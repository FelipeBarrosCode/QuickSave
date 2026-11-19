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
    workspace::{validate_query, Action, Request, Ticket, TicketStore, WorkspaceProofs},
};
use quicksave_service::WorkspaceService;
use quicksave_state::WorkspaceStore;
use serde_json::{json, Value};
use tauri::{Manager, State};
use tauri_plugin_dialog::{DialogExt, MessageDialogButtons, MessageDialogKind};
use tokio::sync::OnceCell;

#[derive(Default)]
pub struct WorkspaceHost {
    service: OnceCell<Arc<WorkspaceService>>,
    // Serializes service initialization with the explicit pre-worker migration.
    startup: tokio::sync::Mutex<()>,
    service_started: AtomicBool,
    #[cfg(debug_assertions)]
    isolated_vault: quicksave_state::MemoryVault,
    tickets: Mutex<TicketStore<WorkspaceProofs>>,
    background_enabled: AtomicBool,
    shutdown: AtomicU8,
}

impl WorkspaceHost {
    async fn service(&self) -> Result<Arc<WorkspaceService>, String> {
        let _startup = self.startup.lock().await;
        self.service_started.store(true, Ordering::Release);
        self.service
            .get_or_try_init(|| async {
                let (data, home) = workspace_directories()?;
                #[cfg(debug_assertions)]
                if std::env::var_os("QUICKSAVE_DEV_WORKSPACE").is_some() {
                    return WorkspaceService::open_isolated_with_vault(
                        &data,
                        &home,
                        Arc::new(self.isolated_vault.clone()),
                    )
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

    fn migration_available(&self) -> Result<(), String> {
        if self.service_started.load(Ordering::Acquire)
            || self.service.get().is_some()
            || self.shutdown.load(Ordering::Acquire) != 0
        {
            return Err("Restart QuickSave before migrating secrets. Migration is available only before workspace workers start.".into());
        }
        Ok(())
    }

    /// Opening private state and reading its format/scope performs no vault IO.
    /// Development launches always inject a synthetic vault, never OS entries.
    fn local_store(&self) -> Result<WorkspaceStore, String> {
        let (data, _) = workspace_directories()?;
        #[cfg(debug_assertions)]
        if std::env::var_os("QUICKSAVE_DEV_WORKSPACE").is_some() {
            return WorkspaceStore::open_with_vault(&data, Arc::new(self.isolated_vault.clone()))
                .map_err(public_error);
        }
        WorkspaceStore::open(&data).map_err(public_error)
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

fn execute_vault_migration(
    store: &WorkspaceStore,
    ticket: Ticket<WorkspaceProofs>,
) -> Result<Value, String> {
    execute_vault_migration_with_backend(store, ticket, None)
}

fn execute_vault_migration_with_backend(
    store: &WorkspaceStore,
    ticket: Ticket<WorkspaceProofs>,
    approved_native_directory: Option<&std::path::Path>,
) -> Result<Value, String> {
    let action = ticket.request.action();
    if !is_local_vault_action(action) {
        return Err("Native vault setup requires its exact native ticket".into());
    }
    let scope = store
        .encrypted_vault_migration_scope()
        .map_err(public_error)?;
    ticket.verify(&scope).map_err(public_error)?;
    let approved = ticket.request.native_scope();
    let generation = approved["generation"]
        .as_u64()
        .ok_or_else(|| "Native migration generation is unavailable".to_owned())?;
    let identity = approved["workspaceIdentity"]
        .as_str()
        .ok_or_else(|| "Native migration identity is unavailable".to_owned())?;
    // Recheck original ticket generation/root under the held OS lock before
    // any vault IO. No reset or legacy fallback on failure. OS prompt behavior
    // is controlled by the OS; a single prompt is not guaranteed.
    let result = match (action, approved_native_directory) {
        (Action::SetupLocalTracking, Some(directory)) => {
            WorkspaceStore::setup_local_tracking_with_native_authorization(
                directory, generation, identity,
            )
        }
        (Action::AuthorizeTrackingStorage, Some(directory)) => {
            WorkspaceStore::authorize_tracking_storage_with_native_authorization(
                directory, generation, identity,
            )
        }
        (Action::SetupLocalTracking, None) => {
            store.setup_local_tracking_scoped(generation, identity)
        }
        (Action::AuthorizeTrackingStorage, None) => {
            store.authorize_tracking_storage_scoped(generation, identity)
        }
        (Action::MigrateVault, Some(directory)) => {
            WorkspaceStore::migrate_with_native_authorization(directory, generation, identity)
        }
        (Action::MigrateVault, None) => {
            store.migrate_to_encrypted_state_scoped(generation, identity)
        }
        _ => unreachable!("local vault action checked before vault access"),
    };
    result.map_err(|error| {
        let message = quicksave_state::migration_error_message(&error);
        // Only fixed phase/reason labels and an optional numeric OS status.
        // Never print the raw backend error, account, or credential value.
        eprintln!("[QuickSave migration] {message}");
        message
    })
}

fn is_local_vault_action(action: Action) -> bool {
    matches!(
        action,
        Action::MigrateVault | Action::SetupLocalTracking | Action::AuthorizeTrackingStorage
    )
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
        if query == "vault_status" || query == "vault_readiness" {
            return tokio::task::spawn_blocking(move || {
                let store = host.local_store()?;
                if query == "vault_readiness" {
                    // Existing root only, strictly noninteractive; never service boot.
                    store.encrypted_storage_readiness().map_err(public_error)
                } else {
                    store.encrypted_vault_status().map_err(public_error)
                }
            })
            .await
            .map_err(|_| "Local vault format inspection did not finish".to_owned())?;
        }
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
        let scope = if is_local_vault_action(request.action()) {
            let _startup = host.startup.lock().await;
            host.migration_available()?;
            let host = Arc::clone(&host);
            tokio::task::spawn_blocking(move || {
                host.local_store()?
                    .encrypted_vault_migration_scope()
                    .map_err(public_error)
            })
            .await
            .map_err(|_| "Local migration scope inspection did not finish".to_owned())??
        } else {
            host.service()
                .await?
                .approval_scope(request.action().name(), request.params())
                .await
                .map_err(public_error)?
        };
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
        if is_local_vault_action(ticket.request.action()) {
            // Ticket was already spent, including if startup admission fails.
            let _startup = host.startup.lock().await;
            host.migration_available()?;
            let host = Arc::clone(&host);
            return tokio::task::spawn_blocking(move || {
                let store = host.local_store()?;
                #[cfg(debug_assertions)]
                if std::env::var_os("QUICKSAVE_DEV_WORKSPACE").is_some() {
                    return execute_vault_migration(&store,ticket);
                }
                let (directory,_) = workspace_directories()?;
                execute_vault_migration_with_backend(&store,ticket,Some(&directory))
            })
            .await
            .map_err(|_| "Secret migration did not finish; completion has not been verified. No automatic retry was started.".to_owned())?;
        }
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

#[cfg(test)]
mod migration_tests {
    use super::*;
    use quicksave_state::{CredentialVault, MemoryVault, QUICKSAVE_VAULT_SERVICE};

    // Every fixture owns a unique private temporary directory and MemoryVault.
    // Never use workspace_directories(), application data, or native keychains.
    struct Fixture {
        directory: PathBuf,
        store: WorkspaceStore,
        vault: MemoryVault,
    }

    impl Fixture {
        fn new() -> Self {
            let base = std::env::temp_dir().canonicalize().unwrap();
            let preferred = base.join("opencode");
            let base = if preferred.is_dir() { preferred } else { base };
            let directory = base.join(format!(
                "quicksave-native-migration-test-{}",
                uuid::Uuid::new_v4()
            ));
            quicksave_platform::ensure_private_directory(&directory).unwrap();
            let vault = MemoryVault::default();
            let store =
                WorkspaceStore::open_with_vault(&directory, Arc::new(vault.clone())).unwrap();
            Self {
                directory,
                store,
                vault,
            }
        }

        fn ticket(&self) -> Ticket<WorkspaceProofs> {
            self.action_ticket("migrate_vault")
        }

        fn action_ticket(&self, action: &str) -> Ticket<WorkspaceProofs> {
            let mut request = Request::new(action, json!({})).unwrap();
            request
                .bind_scope(self.store.encrypted_vault_migration_scope().unwrap())
                .unwrap();
            let proof = WorkspaceProofs::pin(&request).unwrap();
            assert_eq!(proof.worker_identities().unwrap(), json!([]));
            let mut tickets = TicketStore::default();
            let now = Instant::now();
            let id = tickets.issue(request, proof, now).unwrap().parse().unwrap();
            let ticket = tickets.consume(id, now).unwrap();
            assert!(tickets.consume(id, now).is_err());
            ticket
        }
    }

    impl Drop for Fixture {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.directory);
        }
    }

    #[test]
    fn local_status_and_approval_work_with_a_denied_vault_without_service_boot() {
        let fixture = Fixture::new();
        fixture.vault.deny_access(true).unwrap();
        let host = WorkspaceHost::default();
        host.migration_available().unwrap();
        assert!(host.service.get().is_none());
        let status = fixture.store.encrypted_vault_status().unwrap();
        assert_eq!(status["format"], "legacy");
        assert_eq!(status["nativeAuthorizationVerified"], false);
        assert_eq!(status["secretsInPlaintext"], false);
        let ticket = fixture.ticket();
        assert!(execute_vault_migration(&fixture.store, ticket).is_err());
        assert!(host.service.get().is_none());
        assert_eq!(
            fixture.vault.access_log().unwrap(),
            json!({"reads":[],"writes":[]})
        );
        assert_eq!(
            fixture.store.encrypted_vault_status().unwrap()["format"],
            "legacy"
        );
    }

    #[test]
    fn migration_direct_route_preserves_legacy_items_and_never_needs_service() {
        let fixture = Fixture::new();
        fixture
            .vault
            .seed(
                QUICKSAVE_VAULT_SERVICE,
                "synthetic-recovery",
                "fixture-only",
            )
            .unwrap();
        let host = WorkspaceHost::default();
        let ticket = fixture.ticket();
        execute_vault_migration(&fixture.store, ticket).unwrap();
        assert!(host.service.get().is_none());
        assert_eq!(
            fixture.store.encrypted_vault_status().unwrap()["format"],
            "encrypted_state"
        );
        assert_eq!(
            fixture
                .vault
                .read(QUICKSAVE_VAULT_SERVICE, "synthetic-recovery")
                .unwrap()
                .unwrap()
                .as_str(),
            "fixture-only"
        );
    }

    #[test]
    fn changed_generation_or_native_root_spends_ticket_before_any_vault_io() {
        let fixture = Fixture::new();
        let ticket = fixture.ticket();
        fixture
            .store
            .transaction(|document| {
                document.settings.launch_at_login = !document.settings.launch_at_login;
                Ok(())
            })
            .unwrap();
        assert!(execute_vault_migration(&fixture.store, ticket).is_err());
        assert_eq!(
            fixture.vault.access_log().unwrap(),
            json!({"reads":[],"writes":[]})
        );

        let first = Fixture::new();
        let other = Fixture::new();
        let ticket = first.ticket();
        assert!(execute_vault_migration(&other.store, ticket).is_err());
        assert_eq!(
            other.vault.access_log().unwrap(),
            json!({"reads":[],"writes":[]})
        );
    }

    #[test]
    fn migration_is_rejected_after_any_service_boot_attempt_or_shutdown() {
        let host = WorkspaceHost::default();
        host.migration_available().unwrap();
        host.service_started.store(true, Ordering::Release);
        assert!(host.migration_available().is_err());
        let host = WorkspaceHost::default();
        host.shutdown.store(1, Ordering::Release);
        assert!(host.migration_available().is_err());
    }

    #[test]
    fn local_setup_rejects_changed_generation_and_root_before_vault_access() {
        let fixture = Fixture::new();
        let ticket = fixture.action_ticket("setup_local_tracking");
        fixture
            .store
            .transaction(|document| {
                document.settings.launch_at_login = !document.settings.launch_at_login;
                Ok(())
            })
            .unwrap();
        assert!(execute_vault_migration(&fixture.store, ticket).is_err());
        assert_eq!(
            fixture.vault.access_log().unwrap(),
            json!({"reads":[],"writes":[]})
        );
        let first = Fixture::new();
        let other = Fixture::new();
        let ticket = first.action_ticket("setup_local_tracking");
        assert!(execute_vault_migration(&other.store, ticket).is_err());
        assert_eq!(
            other.vault.access_log().unwrap(),
            json!({"reads":[],"writes":[]})
        );
    }

    #[test]
    fn local_setup_and_authorization_do_not_boot_service_or_bulk_import() {
        let fixture = Fixture::new();
        fixture
            .vault
            .seed(
                QUICKSAVE_VAULT_SERVICE,
                "synthetic-cloud-password",
                "fixture-only",
            )
            .unwrap();
        let host = WorkspaceHost::default();
        execute_vault_migration(
            &fixture.store,
            fixture.action_ticket("setup_local_tracking"),
        )
        .unwrap();
        assert!(host.service.get().is_none());
        assert_eq!(
            fixture.store.encrypted_vault_status().unwrap()["credentialSetupPending"],
            true
        );
        assert_eq!(
            fixture.store.encrypted_storage_readiness().unwrap()["ready"],
            true
        );
        let log = fixture.vault.access_log().unwrap().to_string();
        assert!(!log.contains("synthetic-cloud-password"));
        execute_vault_migration(
            &fixture.store,
            fixture.action_ticket("authorize_tracking_storage"),
        )
        .unwrap();
        assert!(host.service.get().is_none());
        assert_eq!(
            fixture.store.encrypted_vault_status().unwrap()["credentialSetupPending"],
            true
        );
        let ticket = fixture.action_ticket("authorize_tracking_storage");
        fixture
            .store
            .transaction(|document| {
                document.settings.launch_at_login = !document.settings.launch_at_login;
                Ok(())
            })
            .unwrap();
        let before = fixture.vault.access_log().unwrap();
        assert!(execute_vault_migration(&fixture.store, ticket).is_err());
        assert_eq!(fixture.vault.access_log().unwrap(), before);
    }
}
