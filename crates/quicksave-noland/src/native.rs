// SPDX-License-Identifier: GPL-3.0-only
use anyhow::{bail, ensure, Context, Result};
use noland_crypto::MasterKey;
use noland_rclone_adapter::EphemeralRcloneSession;
use noland_rpc::{RpcHandler, RpcRequest};
use noland_snapshot::SourcePath;
use noland_state_agent::{
    native_host::{
        native_file_id, ApprovedNativeRoot, NativeCoverage, NativeExpectedFile, NativeFileKey,
        NativeRootRole, NativeSelection,
    },
    rpc_handler::AgentRpc,
    AgentConfig, StateAgent,
};
use noland_state_core::{AgentPaths, AppId, AppIdentity, BundleManifest, StateError};
use noland_storage::{write_guarded_ephemeral_session, RcloneStorage, SharedStorageProvider};
use quicksave_platform::{ensure_private_directory, SafeRoot};
use quicksave_state::ProviderAccess;
use serde_json::{json, Value};
use std::{
    collections::{BTreeMap, BTreeSet, HashMap},
    fs::File,
    io::{Read, Write},
    os::{fd::AsRawFd, unix::fs::MetadataExt},
    path::{Path, PathBuf},
    process::Stdio,
    sync::{Arc, Mutex},
    time::{Duration, Instant},
};
use tokio::{io::AsyncReadExt, process::Command, sync::Semaphore};
use uuid::Uuid;

#[path = "batch_control.rs"]
pub(crate) mod batch_control;
#[path = "observation_control.rs"]
pub mod observation_control;
#[path = "restore_control.rs"]
pub(crate) mod restore_control;

const MAX_SESSION: usize = 2 * 1024 * 1024;
const MAX_PRIVATE_ACCESS: usize = 64;
const MAX_PAGE: usize = 1000;
const MAX_MANIFEST_FILES: usize = 1_000_000;

/// No Debug implementation: sessions/configuration and master material are
/// native-private. Only the preflight's sanitized version is returned to UI.
pub struct SourceRuntime {
    executable: PathBuf,
    version: String,
}

impl SourceRuntime {
    pub async fn discover() -> Result<Self> {
        // Do not search or mutate PATH, accept an environment override, invoke a
        // shell, download a tool, or execute source provisioning installers.
        let candidates = [
            "/opt/homebrew/bin/rclone",
            "/usr/local/bin/rclone",
            "/usr/bin/rclone",
            "/bin/rclone",
        ];
        let mut found = None;
        for candidate in candidates {
            if Path::new(candidate).exists() {
                // Package managers commonly use a symlink to a versioned Cellar.
                // Resolve the installed-tool link once, then pin and validate the
                // actual executable through the source no-follow native handle.
                found = Some(std::fs::canonicalize(candidate)?);
                break;
            }
        }
        let executable = found.context("rclone is not installed in a supported native tool location; install rclone >=1.76 separately")?;
        let held = SourcePath::new(&executable)?.open_regular()?;
        let before = held.metadata()?;
        ensure!(
            before.mode() & 0o022 == 0
                && before.mode() & 0o111 != 0
                && (before.uid() == 0 || before.uid() == unsafe { libc::geteuid() }),
            "installed rclone executable is not trusted"
        );
        let version_output = tool_output(&executable, &["version"], 64 * 1024).await?;
        let version = parse_rclone_version(&version_output)?;
        let flags = tool_output(&executable, &["help", "flags"], 2 * 1024 * 1024).await?;
        for flag in [
            "--immutable",
            "--checksum",
            "--checksum-choice",
            "--files-from-raw",
            "--no-traverse",
            "--error-on-no-transfer",
            "--use-json-log",
            "--multi-thread-streams",
            "--low-level-retries",
            "--ask-password",
        ] {
            ensure!(
                flags.contains(flag),
                "installed rclone is missing required flag {flag}"
            );
        }
        let listing = tool_output(&executable, &["lsjson", "--help"], 512 * 1024).await?;
        ensure!(
            listing.contains("--stat")
                && listing.contains("--recursive")
                && listing.contains("--no-mimetype")
                && listing.contains("--no-modtime"),
            "installed rclone lacks the source engine's lsjson listing/stat flags"
        );
        ensure!(
            noland_snapshot::same_file_identity(&before, &held.metadata()?)
                && noland_snapshot::same_file_identity(
                    &before,
                    &SourcePath::new(&executable)?.open_regular()?.metadata()?
                ),
            "installed rclone changed during preflight"
        );
        noland_storage::install_native_rclone(&executable)?;
        Ok(Self {
            executable,
            version,
        })
    }

    pub fn sanitized(&self) -> Value {
        let _ = &self.executable;
        json!({"available":true,"version":self.version,"minimumVersion":"1.76.0",
            "engineApiVersion":22,"format":"No Land shared storage",
            "captureConsistency":"validated_stable_files","automaticRetirement":false,
            "oauthRefreshPersistence":false,
            "oauthStorageOperations":"unsupported_until_checked_native_vault_refresh_handoff",
            "nativeRestoreAutoRollback":false,"nativeRestoreRetry":false,
            "nativeRestoreRecovery":"retained_artifacts_no_automatic_path_replay"})
    }
}

fn parse_rclone_version(output: &str) -> Result<String> {
    let raw = output
        .lines()
        .next()
        .and_then(|line| line.strip_prefix("rclone v"))
        .context("rclone returned an unrecognized version")?;
    let components = raw
        .split(['.', '-', '+'])
        .take(3)
        .map(str::parse::<u64>)
        .collect::<std::result::Result<Vec<_>, _>>()
        .context("rclone version is malformed")?;
    ensure!(
        components.len() == 3 && (components[0], components[1], components[2]) >= (1, 76, 0),
        "rclone >=1.76.0 is required by the source shared-storage flags and checksum chain"
    );
    Ok(raw.chars().take(64).collect())
}

async fn tool_output(executable: &Path, args: &[&str], limit: usize) -> Result<String> {
    let mut command = Command::new(executable);
    command
        .args(args)
        .env_clear()
        .env("LANG", "C")
        .env("LC_ALL", "C")
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .kill_on_drop(true);
    let mut child = command
        .spawn()
        .context("could not execute installed rclone")?;
    let stdout = child
        .stdout
        .take()
        .context("rclone stdout is unavailable")?;
    let mut bytes = Vec::new();
    let result = tokio::time::timeout(Duration::from_secs(15), async {
        stdout
            .take((limit + 1) as u64)
            .read_to_end(&mut bytes)
            .await?;
        ensure!(
            bytes.len() <= limit,
            "rclone preflight output exceeded its bound"
        );
        ensure!(
            child.wait().await?.success(),
            "rclone preflight failed; private output withheld"
        );
        Ok::<_, anyhow::Error>(())
    })
    .await;
    if !matches!(&result, Ok(Ok(()))) {
        let _ = child.kill().await;
        let _ = child.wait().await;
    }
    result.context("rclone preflight timed out")??;
    String::from_utf8(bytes).context("rclone preflight returned invalid text")
}

struct SoftwareBinding {
    app: AppId,
    instance: String,
    name: String,
}

struct PrivateAccess {
    provider_id: String,
    session: EphemeralRcloneSession,
    master: MasterKey,
    read_only: bool,
    lifecycle: Option<Arc<crate::provider_lifecycle::NativeProviderLifecycle>>,
}

impl PrivateAccess {
    fn from_access(access: &ProviderAccess) -> Result<Self> {
        Self::with_lifecycle(access, None)
    }

    fn with_lifecycle(
        access: &ProviderAccess,
        lifecycle: Option<Arc<crate::provider_lifecycle::NativeProviderLifecycle>>,
    ) -> Result<Self> {
        ensure!(
            !access.provider_id.is_empty() && access.provider_id.len() <= 128,
            "invalid provider identity"
        );
        // Serialize only to apply an explicit document-size bound. Neither this
        // buffer nor the source session is ever included in errors or UI output.
        ensure!(
            serde_json::to_vec(&access.session)?.len() <= MAX_SESSION,
            "provider session exceeds its size bound"
        );
        let session: EphemeralRcloneSession = serde_json::from_value(access.session.clone())
            .map_err(|_| {
                anyhow::anyhow!("provider session is not a valid No Land ephemeral rclone session")
            })?;
        if lifecycle.is_none()
            && noland_rclone_adapter::ProviderKind::parse(&session.provider)
                .is_some_and(|provider| provider.is_oauth())
        {
            bail!("OAuth shared-storage sessions are gated: the source rclone guard has no checked native-vault refresh-token handoff; connect/PKCE alone cannot establish durable storage authentication");
        }
        ensure!(
            session.config_ini.len() <= MAX_SESSION
                && session.operation_id.len() <= 128
                && !session.operation_id.is_empty(),
            "provider session is outside its native bounds"
        );
        Ok(Self {
            provider_id: access.provider_id.clone(),
            session,
            master: MasterKey::from_bytes(access.repository_key),
            read_only: access.read_only,
            lifecycle,
        })
    }

    fn params(&self, mut params: Value) -> Result<Value> {
        ensure!(
            params.is_object(),
            "private engine request must be an object"
        );
        params["session"] = serde_json::to_value(&self.session)?;
        // The source RPC library parses/clones the request-local key before
        // spawning work. There is no shared install_master_key race.
        let mut hex = String::with_capacity(64);
        for byte in self.master.0 {
            use std::fmt::Write;
            write!(&mut hex, "{byte:02x}")?;
        }
        params["master_key_hex"] = json!(hex);
        Ok(params)
    }
}

struct Preview {
    provider_id: String,
    dependency_count: u64,
    frozen: crate::catalog_control::FrozenFullDeletionPlan,
    created: Instant,
}

pub struct NativeEngine {
    agent: Arc<StateAgent>,
    software: Mutex<BTreeMap<String, SoftwareBinding>>,
    access: Mutex<HashMap<Uuid, Arc<PrivateAccess>>>,
    previews: Mutex<HashMap<Uuid, Preview>>,
    submission: tokio::sync::Mutex<()>,
    reads: Semaphore,
    runtime: tokio::sync::OnceCell<SourceRuntime>,
    workspace: Option<quicksave_state::WorkspaceStore>,
    restore: Mutex<restore_control::EngineRestoreState>,
    batch: Mutex<batch_control::EngineBatchState>,
    observation: Mutex<observation_control::EngineObservationState>,
    _lock: File,
    _data: SafeRoot,
    _home: SafeRoot,
}

impl NativeEngine {
    pub fn open(data_dir: &Path, home: &Path) -> Result<Self> {
        ensure!(
            data_dir.is_absolute() && home.is_absolute(),
            "native data/home paths must be absolute"
        );
        ensure_private_directory(data_dir)?;
        let data = SafeRoot::open(data_dir)?;
        let home_handle = SafeRoot::open(home)?;
        data.create_dir("shared-storage")?;
        let private = data_dir.join("shared-storage");
        ensure_private_directory(&private)?;
        let private_root = SafeRoot::open(&private)?;
        let lock =
            SourcePath::new(&private.join("native-engine.lock"))?.open_or_create_private()?;
        quicksave_platform::verify_private_file(&lock)?;
        ensure!(
            unsafe { libc::flock(lock.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) } == 0,
            "another native shared-storage engine owns this QuickSave data directory"
        );
        let instance_id = match private_root.read_file("instance-id") {
            Ok((file, _)) => {
                let mut bytes = Vec::new();
                file.take(65).read_to_end(&mut bytes)?;
                ensure!(bytes.len() <= 64, "native instance identity is oversized");
                Uuid::parse_str(std::str::from_utf8(&bytes)?)?
            }
            Err(error) => {
                if private.join("instance-id").exists() {
                    return Err(error);
                }
                let id = Uuid::new_v4();
                private_root.write_new("instance-id", |file| {
                    file.write_all(id.to_string().as_bytes())?;
                    Ok(())
                })?;
                id
            }
        };
        private_root.create_dir("state")?;
        private_root.create_dir("run")?;
        let paths = AgentPaths::from_roots(private.join("state"), private.join("run"));
        for dir in [
            &paths.state_root,
            &paths.run_root,
            &paths.staging,
            &paths.snapshots,
            &paths.packs,
            &paths.restore,
            &paths.checkpoints,
            &paths.cache,
        ] {
            ensure_private_directory(dir)?;
        }
        let data_identity = data.identity()?;
        let private_identity = private_root.identity()?;
        let state_root = SafeRoot::open(&paths.state_root)?;
        let state_identity = state_root.identity()?;
        if paths.db_path.exists() {
            let database = SourcePath::new(&paths.db_path)?.open_regular()?;
            quicksave_platform::verify_private_file(&database)?;
        }
        let config = AgentConfig {
            instance_id,
            image_id: format!("quicksave-native-{}", std::env::consts::OS),
            paths,
            home: home.to_path_buf(),
            user: "quicksave-native".into(),
            converge_complete_backups: false,
            native_host: true,
            capture_exclusions: vec![data_dir.to_path_buf()],
        };
        let agent = StateAgent::boot(config).map_err(public_source_error)?;
        ensure!(
            data.identity()? == data_identity
                && private_root.identity()? == private_identity
                && state_root.identity()? == state_identity,
            "native database parent identity changed during initialization"
        );
        quicksave_platform::verify_private_file(
            &SourcePath::new(&agent.config.paths.db_path)?.open_regular()?,
        )?;
        agent.recover().map_err(public_source_error)?;
        Ok(Self {
            agent: Arc::new(agent),
            software: Mutex::new(BTreeMap::new()),
            access: Mutex::new(HashMap::new()),
            previews: Mutex::new(HashMap::new()),
            submission: tokio::sync::Mutex::new(()),
            reads: Semaphore::new(2),
            runtime: tokio::sync::OnceCell::new(),
            workspace: None,
            restore: Mutex::new(restore_control::EngineRestoreState::default()),
            batch: Mutex::new(batch_control::EngineBatchState::default()),
            observation: Mutex::new(observation_control::EngineObservationState::default()),
            _lock: lock,
            _data: data,
            _home: home_handle,
        })
    }

    /// Trusted native composition only. No webview can replace a workspace,
    /// credential sink, device key, or session rotation callback.
    pub fn with_workspace(mut self, store: quicksave_state::WorkspaceStore) -> Result<Self> {
        ensure!(
            self.workspace.is_none(),
            "The native workspace is already bound"
        );
        let recovery_store = store.clone();
        self.install_restore_authority(Arc::new(move |bytes| {
            recovery_store.recovery_mac_existing(bytes)
        }))?;
        self.workspace = Some(store);
        Ok(self)
    }

    fn private_access(
        &self,
        access: &ProviderAccess,
        operation: Option<Uuid>,
    ) -> Result<PrivateAccess> {
        let operation_id = operation
            .map(|id| id.to_string())
            .or_else(|| access.session["operation_id"].as_str().map(str::to_owned))
            .context("Native provider operation binding is missing")?;
        let lifecycle = self
            .workspace
            .as_ref()
            .map(|store| {
                crate::provider_lifecycle::register_native_provider_lifecycle(
                    store.clone(),
                    access,
                    &operation_id,
                )
                .map(Arc::new)
            })
            .transpose()?;
        let mut private = PrivateAccess::with_lifecycle(access, lifecycle)?;
        private.session.operation_id = operation_id;
        Ok(private)
    }

    pub async fn preflight(&self) -> Result<Value> {
        let runtime = self
            .runtime
            .get_or_try_init(SourceRuntime::discover)
            .await?;
        // API 22 admission/receipt/deletion semantics are required. This is an
        // in-process call, never a server/socket or remote process.
        let health = self.rpc("GetHealth", json!({})).await?;
        ensure!(
            health["agent_api_version"].as_u64() == Some(22),
            "shared-storage library API 22 is required"
        );
        let mut report = runtime.sanitized();
        if self.workspace.is_some() {
            report["oauthRefreshPersistence"] = json!(true);
            report["oauthStorageOperations"] =
                json!("operation_bound_checked_native_vault_handoff");
        }
        Ok(report)
    }

    /// Closing never cancels or retires work implicitly. Service admission has
    /// stopped already; wait only for final owner release after a terminal row.
    pub async fn shutdown(&self) -> Result<()> {
        let deadline = tokio::time::Instant::now() + Duration::from_secs(5);
        loop {
            let owners = self.agent.operations.running_snapshots();
            if owners.is_empty() {
                break;
            }
            ensure!(
                tokio::time::Instant::now() < deadline,
                "Native storage workers have not drained; keep QuickSave open"
            );
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        let access = std::mem::take(
            &mut *self
                .access
                .lock()
                .map_err(|_| anyhow::anyhow!("Native credential ownership lock failed"))?,
        );
        for private in access.values() {
            if let Some(lifecycle) = &private.lifecycle {
                lifecycle.invalidate()?;
            }
        }
        Ok(())
    }

    pub async fn register(&self, software: &Value) -> Result<()> {
        let _guard = self.submission.lock().await;
        self.register_approved_record(software)
    }

    /// Native-only explicit index materialization. This is not an IPC entry
    /// point, and never starts a source collector, transfer or filesystem walk.
    pub fn register_materialized(&self, software: &Value) -> Result<()> {
        let _guard = self
            .submission
            .try_lock()
            .context("native application registration is busy")?;
        self.register_approved_record(software)
    }

    fn register_approved_record(&self, software: &Value) -> Result<()> {
        let id = identifier(software, "id")?;
        let instance = software
            .get("appId")
            .and_then(Value::as_str)
            .filter(|s| !s.is_empty())
            .map(str::to_owned)
            .unwrap_or_else(|| format!("quicksave:{id}"));
        let mut identity = match software.get("sourceIdentity") {
            Some(value) if !value.is_null() => serde_json::from_value::<AppIdentity>(value.clone())
                .context("verified source application identity is invalid")?,
            _ => AppIdentity::new(AppId(instance.clone()), ""),
        };
        let app = identity.app_id.0.clone();
        validate_id(&app)?;
        validate_id(&instance)?;
        {
            let registered = self
                .software
                .lock()
                .map_err(|_| anyhow::anyhow!("native registration lock poisoned"))?;
            ensure!(
                registered.len() < 4096 || registered.contains_key(&id),
                "native software registration limit reached"
            );
            // Several verified installation instances may share the original
            // product ID. Per-attempt native root fingerprints remain exact.
        }
        let name = bounded_text(
            software
                .get("name")
                .and_then(Value::as_str)
                .context("software name missing")?,
            256,
        )?;
        let roots = software
            .get("roots")
            .and_then(Value::as_array)
            .context("approved software roots missing")?;
        ensure!(
            !roots.is_empty() && roots.len() <= 128,
            "approve 1–128 software roots"
        );
        let mut approved = Vec::new();
        for (index, root) in roots.iter().enumerate() {
            let path = PathBuf::from(
                root.get("path")
                    .and_then(Value::as_str)
                    .context("approved root path missing")?,
            );
            ensure!(
                path.to_str().is_some_and(|s| s.len() <= 32768),
                "root path is too long"
            );
            let root_id = root
                .get("id")
                .and_then(Value::as_str)
                .map(str::to_owned)
                .unwrap_or_else(|| format!("root-{index}"));
            validate_id(&root_id)?;
            let allowed_files = match root.get("allowedFiles") {
                None | Some(Value::Null) => None,
                Some(value) => {
                    let leaves = value
                        .as_array()
                        .context("allowedFiles must be an exact leaf array")?;
                    ensure!(
                        !leaves.is_empty() && leaves.len() <= 250_000,
                        "manual file allowlist is outside its native bound"
                    );
                    let set = leaves
                        .iter()
                        .map(|leaf| {
                            let leaf = leaf
                                .as_str()
                                .context("manual file allowlist entry must be text")?;
                            noland_state_agent::native_host::validate_native_relative(leaf)
                                .map_err(public_source_error)?;
                            ensure!(
                                !leaf.contains('/'),
                                "manual file allowlist entries must be individual leaves"
                            );
                            Ok(leaf.to_owned())
                        })
                        .collect::<Result<BTreeSet<_>>>()?;
                    ensure!(
                        set.len() == leaves.len(),
                        "duplicate manual file allowlist entry"
                    );
                    Some(set)
                }
            };
            let expected_identity = match root.get("identity") {
                None | Some(Value::Null) => None,
                Some(identity) => {
                    let device = identity["device"]
                        .as_u64()
                        .context("approved native root device missing")?;
                    let file_id = identity["fileId"]
                        .as_array()
                        .context("approved native root file ID missing")?;
                    ensure!(
                        file_id.len() == 2 && file_id[1].as_u64() == Some(0),
                        "unsupported native root file identity"
                    );
                    Some((
                        device,
                        file_id[0]
                            .as_u64()
                            .context("approved native root inode missing")?,
                    ))
                }
            };
            approved.push(ApprovedNativeRoot {
                id: root_id,
                path,
                allowed_files,
                expected_identity,
                role: NativeRootRole::parse(
                    root.get("role").and_then(Value::as_str).unwrap_or("manual"),
                )
                .map_err(public_source_error)?,
            });
        }
        let app = AppId(app);
        ensure!(
            identity.app_id == app,
            "source application identity does not match the approved software"
        );
        if let Some(steam_id) = identity.steam_app_id {
            ensure!(
                identity.app_id == AppId::steam(steam_id),
                "Steam identity does not match its exact application ID"
            );
        }
        if let Some(executable) = &identity.canonical_executable {
            ensure!(
                executable.is_absolute(),
                "application executable identity must be absolute"
            );
            SourcePath::new(executable)?
                .open_regular()
                .map_err(public_source_error)?;
        }
        identity.display_name = name.clone();
        self.agent
            .native_register(identity, approved)
            .map_err(public_source_error)?;
        let mut registered = self
            .software
            .lock()
            .map_err(|_| anyhow::anyhow!("native registration lock poisoned"))?;
        ensure!(
            registered.len() < 4096 || registered.contains_key(&id),
            "native software registration limit reached"
        );
        registered.insert(
            id,
            SoftwareBinding {
                app,
                instance,
                name,
            },
        );
        Ok(())
    }

    pub async fn catalog(&self, access: &ProviderAccess) -> Result<Value> {
        self.preflight().await?;
        let _slot = self
            .reads
            .try_acquire()
            .context("native metadata reader is at capacity")?;
        let private = self.private_access(access, None)?;
        let value = self
            .rpc_private("ListCloudCatalog", &private, json!({}))
            .await?;
        crate::catalog_control::catalog_projection_from_rpc(
            &access.provider_id,
            &value,
            &crate::catalog_control::CatalogEvidence::default(),
        )
    }

    /// Read-only connection evidence. No probe writes a test object, creates a
    /// repository, acquires a write lease or treats configuration as success.
    pub async fn probe(&self, access: &ProviderAccess) -> Result<Value> {
        self.preflight().await?;
        let _slot = self
            .reads
            .try_acquire()
            .context("native metadata reader is at capacity")?;
        let private = self.private_access(access, None)?;
        let (config, guard) =
            write_guarded_ephemeral_session(&self.agent.config.paths.run_root, &private.session)
                .map_err(public_source_error)?;
        let result = async {
        let provider = RcloneStorage::try_from_session(&private.session, &config)
            .map_err(public_source_error)?;
        let observed = chrono::Utc::now();
        let listed = provider.health_check().await.map_err(public_source_error)?;
        if !listed.ok {
            return Ok(
                json!({"providerId":access.provider_id,"canList":false,"canRead":false,
                "repositoryAccessible":false,"repositoryEmpty":null,"keyVerified":false,
                "observedAt":observed,"evidence":"provider_list_failed",
                "error":"Provider listing failed; private provider output withheld."}),
            );
        }
        let head = provider
            .stat(&noland_storage::RemoteKey::new(
                noland_state_core::catalog_latest_key(),
            ))
            .await
            .map_err(public_source_error)?;
        if head.is_none() {
            // An absent head alone is not proof of a new repository. Existing
            // packs/bundles with a missing pointer must not be adopted under a
            // new key as though they were an empty verified account.
            for prefix in [
                "catalog",
                "bundles",
                "packs",
                "checkpoints",
                "instances",
                "maintenance",
                "deletions",
            ] {
                let entries = provider
                    .list_prefix(&noland_storage::RemoteKey::new(prefix))
                    .await
                    .map_err(public_source_error)?;
                if entries.iter().any(|entry| !entry.is_prefix) {
                    return Ok(
                        json!({"providerId":access.provider_id,"canList":true,"canRead":false,
                        "repositoryAccessible":false,"repositoryEmpty":false,"keyVerified":false,
                        "observedAt":observed,"evidence":"missing_catalog_head_with_existing_repository_objects",
                        "error":"Existing repository objects lack a verifiable catalog head; recovery is required."}),
                    );
                }
            }
            return Ok(
                json!({"providerId":access.provider_id,"canList":true,"canRead":false,
                "repositoryAccessible":true,"repositoryEmpty":true,"keyVerified":false,
                "observedAt":observed,"evidence":"provider_root_list_and_empty_repository_namespace_inventory",
                "error":null}),
            );
        }
        match noland_storage::load_catalog(&provider, &private.master).await {
            Ok(_) => Ok(
                json!({"providerId":access.provider_id,"canList":true,"canRead":true,
                "repositoryAccessible":true,"repositoryEmpty":false,"keyVerified":true,
                "observedAt":observed,"evidence":"authenticated_live_catalog","error":null}),
            ),
            Err(_) => Ok(
                json!({"providerId":access.provider_id,"canList":true,"canRead":false,
                "repositoryAccessible":false,"repositoryEmpty":false,"keyVerified":false,
                "observedAt":observed,"evidence":"catalog_authentication_or_read_failed",
                "error":"Existing repository could not be authenticated with this key."}),
            ),
        }
        }.await;
        guard.finish().map_err(public_source_error)?;
        result
    }

    pub async fn health(&self, access: &ProviderAccess) -> Result<Value> {
        self.probe(access).await
    }

    pub async fn files(&self, access: &ProviderAccess, bundle: &Value) -> Result<Value> {
        self.preflight().await?;
        let _slot = self
            .reads
            .try_acquire()
            .context("native metadata reader is at capacity")?;
        let private = self.private_access(access, None)?;
        let mut manifest = self.manifest(&private, bundle).await?;
        // Never allocate a million renderer DTOs to return one page. The
        // immutable manifest supplies a deterministic metadata-only order.
        manifest.files.sort_by(|left, right| {
            left.logical_root
                .cmp(&right.logical_root)
                .then_with(|| left.relative_path.cmp(&right.relative_path))
        });
        let offset = file_page_offset(bundle, manifest.files.len())?;
        let limit = file_page_limit(bundle)?;
        let end = offset.saturating_add(limit).min(manifest.files.len());
        let files = manifest.files[offset..end]
            .iter()
            .map(|file| {
                file_item(
                    &file.logical_root,
                    &file.relative_path,
                    file.file_type == "directory",
                    file.size,
                )
            })
            .collect::<Result<Vec<_>>>()?;
        Ok(
            json!({"files":files,"nextCursor":(end < manifest.files.len()).then(|| end.to_string())}),
        )
    }

    pub async fn software_files(&self, params: &Value) -> Result<Value> {
        let app = self.software_app(params)?;
        let files = self.local_files(&app)?;
        page(files, params)
    }

    pub async fn upload(&self, access: ProviderAccess, selection: Value) -> Result<Value> {
        let _ = (access, selection);
        bail!("native uploads require operation-bound publication authorization and canonical expected capture evidence; use upload_guarded")
    }

    pub async fn upload_guarded(
        &self,
        access: ProviderAccess,
        selection: Value,
        guard: Arc<dyn Fn() -> Result<()> + Send + Sync>,
    ) -> Result<Value> {
        guard().map_err(|_| {
            anyhow::anyhow!("native upload authorization changed before submission")
        })?;
        self.preflight().await?;
        ensure!(
            !access.read_only,
            "provider is read-only; a separate native write grant is required"
        );
        let _guard = self.submission.lock().await;
        let id = operation_id(&selection)?;
        let mut bound_access = self.private_access(&access, Some(id))?;
        bound_access.session.operation_id = id.to_string();
        let private = Arc::new(bound_access);
        let app = self.software_app(&selection)?;
        let files = self.local_files(&app)?;
        let file_keys = Some(match selection_keys(&selection, &files)? {
            Some(keys) => keys,
            None => {
                ensure!(
                    !files.is_empty(),
                    "approved software contains no capturable regular files"
                );
                files
                    .iter()
                    .map(|file| {
                        Ok(NativeFileKey {
                            logical_root: file["rootId"]
                                .as_str()
                                .context("native root missing")?
                                .into(),
                            relative_path: file["path"]
                                .as_str()
                                .context("native relative path missing")?
                                .into(),
                        })
                    })
                    .collect::<Result<Vec<_>>>()?
            }
        });
        let (snapshot_identity, expected_files) =
            expected_capture_evidence(&selection, file_keys.as_ref().unwrap(), &files)?;
        let (coverage, mode) = native_capture_mode(&selection)?;
        let native = NativeSelection {
            version: 1,
            file_keys,
            roots_fingerprint: self
                .agent
                .native_binding_fingerprint(&app)
                .map_err(public_source_error)?,
            destination: None,
            destination_identity: None,
            snapshot_identity: Some(snapshot_identity),
            expected_files: Some(expected_files),
            capture_scope: None,
            coverage,
            software_instance_id: Some(self.software_instance(&selection)?),
        };
        let lifecycle = private.lifecycle.clone();
        self.agent
            .native_set_publication_guard(
                id,
                Arc::new(move || {
                    if let Some(lifecycle) = &lifecycle {
                        lifecycle.checkpoint().map_err(|_| StateError::Conflict(
                            "native credential rotation could not be durably finalized before publication".into()))?;
                    }
                    guard().map_err(|_| {
                        StateError::Conflict(
                            "native upload authority changed before publication".into(),
                        )
                    })
                }),
            )
            .map_err(public_source_error)?;
        self.reserve_private(id, Arc::clone(&private))?;
        let result = self
            .rpc_private(
                "StartBackup",
                &private,
                json!({
                    "app_id":app.as_str(),"client_operation_id":id,"native_selection":native,"mode":mode,
                }),
            )
            .await;
        submission_result(result, id)
    }

    /// Optimized capture: metadata-only native selection, then the actual source
    /// pipeline supplies hashes/stable stamps once. No tracker prehash or bridge
    /// local_files walk is permitted on this path.
    pub async fn upload_captured_guarded(
        &self,
        access: ProviderAccess,
        selection: Value,
        guard: Arc<dyn Fn() -> Result<()> + Send + Sync>,
        controller: Arc<dyn crate::capture_control::NativeCaptureController>,
    ) -> Result<Value> {
        self.preflight().await?;
        ensure!(
            !access.read_only,
            "provider is read-only; native write consent is required"
        );
        let _submission = self.submission.lock().await;
        let id = operation_id(&selection)?;
        let private = Arc::new(self.private_access(&access, Some(id))?);
        let app = self.software_app(&selection)?;
        let metadata = &selection["captureSource"]["metadataSelection"];
        ensure!(
            selection["captureSource"]["stage"] == "awaiting_native_capture_receipt",
            "Actual source capture requires a frozen metadata-only scope"
        );
        let mut scope = crate::capture_control::CaptureScope {
            version: 1,
            work_id: identifier(&selection, "workId")?,
            metadata_identity: metadata["metadataIdentity"]
                .as_str()
                .context("Native metadata identity is missing")?
                .into(),
            node_count: metadata["nodeCount"]
                .as_u64()
                .and_then(|n| usize::try_from(n).ok())
                .context("Native node count is missing")?,
            full_scope: None,
        };
        if let Some(authority) = controller.full_scope_authority(&scope)? {
            authority.revalidate()?;
            scope.full_scope = Some(crate::capture_control::full_scope_from_evidence(
                &authority.evidence()?,
            )?);
        }
        ensure!(
            selection["captureSource"]["selectionKind"] != "full_scope"
                || scope.full_scope.is_some(),
            "A whole native snapshot requires its original Rust full-scope authority"
        );
        ensure!(
            metadata["workId"] == scope.work_id,
            "Native source capture work binding changed"
        );
        let keys = crate::capture_control::install(
            &self.agent,
            id,
            &app,
            scope.clone(),
            controller.clone(),
        )?;
        let (coverage, mode) = native_capture_mode(&selection)?;
        let native = NativeSelection {
            version: 1,
            file_keys: Some(keys),
            roots_fingerprint: self
                .agent
                .native_binding_fingerprint(&app)
                .map_err(public_source_error)?,
            destination: None,
            destination_identity: None,
            snapshot_identity: Some(scope.metadata_identity.clone()),
            expected_files: None,
            capture_scope: Some(scope),
            coverage,
            software_instance_id: Some(self.software_instance(&selection)?),
        };
        let lifecycle = private.lifecycle.clone();
        self.agent
            .native_set_publication_guard(
                id,
                Arc::new(move || {
                    if let Some(lifecycle) = &lifecycle {
                        lifecycle.checkpoint().map_err(|_| {
                            StateError::Conflict(
                                "Native credential refresh could not be durably finalized".into(),
                            )
                        })?;
                    }
                    controller.verify_publication().map_err(|_| {
                        StateError::Conflict(
                            "Native tracking authority refused the actual source capture receipt"
                                .into(),
                        )
                    })?;
                    guard().map_err(|_| {
                        StateError::Conflict(
                            "Native upload authority was revoked before publication".into(),
                        )
                    })
                }),
            )
            .map_err(public_source_error)?;
        self.reserve_private(id, private.clone())?;
        let result = self.rpc_private("StartBackup", &private, json!({
            "app_id":app.as_str(),"client_operation_id":id,"native_selection":native,"mode":mode,
        })).await;
        submission_result(result, id)
    }

    pub async fn download(&self, access: ProviderAccess, selection: Value) -> Result<Value> {
        self.preflight().await?;
        let _guard = self.submission.lock().await;
        let private = Arc::new(self.private_access(&access, None)?);
        let destination = PathBuf::from(
            selection
                .get("destination")
                .and_then(Value::as_str)
                .context("native download destination is required")?,
        );
        ensure!(
            destination.is_absolute(),
            "native destination must be absolute"
        );
        let root = SafeRoot::open(&destination)?;
        let destination_identity =
            approved_destination_identity(&selection, &destination, &root.identity()?)?;
        ensure!(
            root.entries()?.is_empty(),
            "download requires a fresh empty destination; overwrite is not authorized"
        );
        let metadata = SourcePath::new(&destination)?.metadata()?;
        ensure!(
            metadata.is_dir()
                && !metadata.is_symlink()
                && (metadata.dev(), metadata.ino()) == destination_identity,
            "download destination must remain the approved native directory"
        );
        let manifest = self.manifest(&private, &selection).await?;
        let files = manifest
            .files
            .iter()
            .map(|file| {
                file_item(
                    &file.logical_root,
                    &file.relative_path,
                    file.file_type == "directory",
                    file.size,
                )
            })
            .collect::<Result<Vec<_>>>()?;
        let file_keys = selection_keys(&selection, &files)?;
        let native = NativeSelection {
            version: 1,
            file_keys,
            roots_fingerprint: blake3::hash(
                format!("{}:{}", destination_identity.0, destination_identity.1).as_bytes(),
            )
            .to_hex()
            .to_string(),
            destination: Some(destination),
            destination_identity: Some(destination_identity),
            snapshot_identity: None,
            expected_files: None,
            capture_scope: None,
            coverage: NativeCoverage::LegacyExactSelection,
            software_instance_id: None,
        };
        let id = operation_id(&selection)?;
        self.reserve_private(id, Arc::clone(&private))?;
        let result = self.rpc_private("StartRestore",&private,json!({
            "app_id":manifest.app.app_id.as_str(),"bundle_id":manifest.bundle_id,
            "mode":"complete_application","client_operation_id":id,"native_selection":native,
        })).await;
        submission_result(result, id)
    }

    pub async fn preview_delete(&self, access: &ProviderAccess, selection: Value) -> Result<Value> {
        self.preflight().await?;
        ensure!(
            !access.read_only,
            "provider is read-only; deletion requires a separate native write grant"
        );
        let _guard = self.submission.lock().await;
        let app = identifier(&selection, "appId")?;
        let bundle = parse_uuid(&selection, "bundleId")?;
        let private = self.private_access(access, None)?;
        let preview = self
            .rpc_private(
                "PrepareDeletion",
                &private,
                json!({
                    "target":"cloud","selected_paths":[format!("/catalog/{app}/{bundle}")],
                }),
            )
            .await?;
        let id = parse_uuid(&preview, "planId")?;
        let dependency_count = preview["dependentBundles"]
            .as_u64()
            .context("source deletion preview lacks dependency count")?;
        let frozen = self
            .agent
            .native_with_deletion_plan(id, |plan| {
                crate::catalog_control::deletion_projection(
                    plan,
                    Some(&[crate::catalog_control::DeletionSelection {
                        app_id: app.clone(),
                        bundle_id: bundle.to_string(),
                    }]),
                )
                .map_err(|_| {
                    StateError::Integrity("native deletion dependency projection is invalid".into())
                })
            })
            .map_err(public_source_error)?;
        let dependencies = frozen
            .dependencies
            .as_ref()
            .context("Original deletion dependencies are unknown")?;
        ensure!(
            dependencies.len() as u64 == dependency_count && dependencies.len() <= 256,
            "This deletion requires a larger exact-dependency review; no deletion was authorized"
        );
        let dependent_items = dependencies.iter().map(|dependency| json!({
            "id":dependency.bundle_id,"appId":dependency.app_id,"commitId":dependency.commit_id,
        })).collect::<Vec<_>>();
        // Source retains exactly one frozen plan. Retaining just that same ID
        // prevents an older UI preview from authorizing its replacement.
        let mut previews = self
            .previews
            .lock()
            .map_err(|_| anyhow::anyhow!("native preview lock poisoned"))?;
        previews.clear();
        previews.insert(
            id,
            Preview {
                provider_id: access.provider_id.clone(),
                dependency_count,
                frozen: frozen.clone(),
                created: Instant::now(),
            },
        );
        Ok(
            json!({"previewId":id,"providerId":access.provider_id,"dependentBundles":dependent_items,
            "dependentBundleCount":dependency_count,"affectedBundles":frozen.targets,
            "planDigest":frozen.digest,
            "items":preview["items"].as_u64(),"logicalBytes":preview["bytes"].as_u64(),
            "physicalBytes":preview["physicalBytes"].as_u64(),"packCount":preview["packCount"].as_u64(),
            "fullDeletion":true,"expiresInSeconds":600,
            "names":preview["names"].as_array().into_iter().flatten().filter_map(Value::as_str)
                .take(1000).map(|s| bounded_text(s,256)).collect::<Result<Vec<_>>>()?}),
        )
    }

    pub async fn delete(&self, access: ProviderAccess, selection: Value) -> Result<Value> {
        let _ = (access, selection);
        bail!("Native deletion requires its exact provider/publication authority");
    }

    pub async fn delete_guarded(
        &self,
        access: ProviderAccess,
        selection: Value,
        guard: Arc<dyn Fn() -> Result<()> + Send + Sync>,
    ) -> Result<Value> {
        self.preflight().await?;
        ensure!(
            !access.read_only,
            "provider is read-only; deletion requires a separate native write grant"
        );
        let _guard = self.submission.lock().await;
        let id = parse_uuid(&selection, "previewId")?;
        {
            let previews = self
                .previews
                .lock()
                .map_err(|_| anyhow::anyhow!("native preview lock poisoned"))?;
            let preview = previews
                .get(&id)
                .context("deletion preview is no longer available; preview again")?;
            ensure!(
                preview.provider_id == access.provider_id
                    && preview.created.elapsed() < Duration::from_secs(600),
                "deletion preview expired or provider changed"
            );
            let requested = preview.frozen.requested.as_ref().map(|items| {
                items
                    .iter()
                    .map(|item| crate::catalog_control::DeletionSelection {
                        app_id: item.app_id.clone(),
                        bundle_id: item.bundle_id.clone(),
                    })
                    .collect::<Vec<_>>()
            });
            let current = self
                .agent
                .native_with_deletion_plan(id, |plan| {
                    crate::catalog_control::deletion_projection(plan, requested.as_deref())
                        .map_err(|_| StateError::Integrity("native deletion plan changed".into()))
                })
                .map_err(public_source_error)?;
            ensure!(
                current == preview.frozen,
                "Frozen deletion dependency identities changed; preview again"
            );
            require_dependency_ack(preview.dependency_count, &selection)?;
        }
        let private = Arc::new(self.private_access(&access, Some(id))?);
        let lifecycle = private.lifecycle.clone();
        guard()?;
        self.agent
            .native_set_publication_guard(
                id,
                Arc::new(move || {
                    if let Some(lifecycle) = &lifecycle {
                        lifecycle.checkpoint().map_err(|_| {
                            StateError::Conflict(
                                "native credential finalization failed before deletion".into(),
                            )
                        })?;
                    }
                    guard().map_err(|_| {
                        StateError::Conflict("native deletion authority was revoked".into())
                    })
                }),
            )
            .map_err(public_source_error)?;
        self.reserve_private(id, Arc::clone(&private))?;
        let result = self.rpc_private("StartDeletion",&private,json!({
            "plan_id":id,"target":"cloud","confirmed":true,
            "native_dependency_ack":selection["acknowledgeDependencies"].as_bool() == Some(true),
        })).await;
        if result.is_ok() {
            self.previews
                .lock()
                .map_err(|_| anyhow::anyhow!("native preview lock poisoned"))?
                .remove(&id);
        }
        submission_result(result, id)
    }

    pub async fn status(&self, id: &str) -> Result<Value> {
        let id = Uuid::parse_str(id).context("invalid operation ID")?;
        let raw = self
            .rpc(
                "GetOperationStatus",
                json!({"operation_id":id,"projection":"progress"}),
            )
            .await?;
        let mut activity = self.activity(&raw)?;
        if matches!(
            activity["state"].as_str(),
            Some("completed" | "failed" | "cancelled" | "interrupted")
        ) && self.agent.operations.is_running(id)
        {
            // A terminal SQLite row can precede final worker/handle release.
            // Do not release service admission or acknowledge the tracker yet.
            activity["state"] = json!("running");
            activity["phase"] = json!("finalizing");
            activity["canCancel"] = json!(false);
        }
        if activity["kind"] == "download" {
            activity["canRecover"] = json!(self.restore_recovery_available(id).unwrap_or(false));
        }
        if matches!(
            activity["state"].as_str(),
            Some("completed" | "failed" | "cancelled" | "interrupted")
        ) {
            // Receipt objects own independent native pins until tracker
            // finalization. The coordinator's per-attempt pages can be released.
            let _ = noland_state_agent::native_capture::remove(&self.agent, id);
        }
        Ok(activity)
    }

    pub async fn recent(&self) -> Result<Vec<Value>> {
        // A matching list does not serialize private operation details/results.
        let raw = self
            .rpc(
                "ListRecentOperations",
                json!({"limit":50,"projection":"matching"}),
            )
            .await?;
        let operations = raw["operations"]
            .as_array()
            .context("source operation listing malformed")?;
        let mut out = Vec::with_capacity(operations.len());
        for operation in operations {
            let id = operation["operation_id"]
                .as_str()
                .context("source operation ID missing")?;
            out.push(self.status(id).await?);
        }
        Ok(out)
    }

    pub async fn cancel(&self, id: &str) -> Result<Value> {
        let operation = Uuid::parse_str(id).context("invalid operation ID")?;
        self.rpc("CancelOperation", json!({"operation_id":operation}))
            .await?;
        self.status(id).await
    }

    pub async fn retry(&self, id: &str) -> Result<Value> {
        self.preflight().await?;
        let operation = Uuid::parse_str(id).context("invalid operation ID")?;
        let _guard = self.submission.lock().await;
        let private = self
            .access
            .lock()
            .map_err(|_| anyhow::anyhow!("native access lock poisoned"))?
            .get(&operation)
            .cloned()
            .context("retry needs native provider reattachment after restart")?;
        let record = self
            .agent
            .db
            .get_operation(operation)
            .map_err(public_source_error)?
            .context("operation not found")?;
        ensure!(record.kind != "restore","native restore retry is disabled: retained outputs require identity-verified explicit cleanup; start a new restore into a new native-confirmed empty destination");
        if record.kind == "backup" {
            self.agent
                .native_check_publication_guard(operation)
                .map_err(public_source_error)?;
        }
        if matches!(record.kind.as_str(), "backup" | "delete") {
            ensure!(
                !private.read_only,
                "provider is read-only; retry is not authorized to write"
            );
        }
        if record.kind == "delete" {
            // Source StartDeletion resumes only its authenticated persisted
            // FullDeletionPlan, preserving the previously acknowledged scope.
            self.rpc_private(
                "StartDeletion",
                &private,
                json!({"plan_id":operation,"target":"cloud","confirmed":true}),
            )
            .await?;
        } else {
            self.rpc_private(
                "RetryOperation",
                &private,
                json!({"operation_id":operation}),
            )
            .await?;
        }
        Ok(json!({"operationId":operation}))
    }

    pub async fn retry_guarded(
        &self,
        id: &str,
        guard: Arc<dyn Fn() -> Result<()> + Send + Sync>,
    ) -> Result<Value> {
        let operation = Uuid::parse_str(id).context("invalid operation ID")?;
        let record = self
            .agent
            .db
            .get_operation(operation)
            .map_err(public_source_error)?
            .context("Native retry operation is missing")?;
        ensure!(record.detail_json.pointer("/native_selection/capture_scope").is_none_or(Value::is_null),
            "Receipt-backed retry requires reattachment of the original frozen native work; a new capture cannot replace it");
        let lifecycle = self
            .access
            .lock()
            .map_err(|_| anyhow::anyhow!("native access lock poisoned"))?
            .get(&operation)
            .and_then(|private| private.lifecycle.clone());
        self.agent
            .native_set_publication_guard(
                operation,
                Arc::new(move || {
                    if let Some(lifecycle) = &lifecycle {
                        lifecycle.checkpoint().map_err(|_| StateError::Conflict(
                            "native refreshed credentials could not be durably finalized before retry publication".into()))?;
                    }
                    guard().map_err(|_| {
                        StateError::Conflict("native retry publication authority changed".into())
                    })
                }),
            )
            .map_err(public_source_error)?;
        self.retry(id).await
    }

    pub async fn reattach(&self, access: ProviderAccess, id: &str) -> Result<()> {
        self.preflight().await?;
        let operation = Uuid::parse_str(id).context("invalid operation ID")?;
        let mut bound_access = self.private_access(&access, Some(operation))?;
        bound_access.session.operation_id = operation.to_string();
        let private = Arc::new(bound_access);
        let record = self
            .agent
            .db
            .get_operation(operation)
            .map_err(public_source_error)?
            .context("operation not found")?;
        ensure!(record.kind != "restore","native restore reattachment/retry is disabled until retained artifacts receive identity-verified explicit cleanup");
        if record.kind == "delete" {
            ensure!(
                !private.read_only,
                "provider is read-only; deletion reattachment is not authorized"
            );
            let preview = self.rpc_private("PrepareDeletion",&private,json!({
                "target":"cloud","selected_paths":[format!("/pending-deletions/{operation}")],
            })).await?;
            ensure!(
                parse_uuid(&preview, "planId")? == operation,
                "source deletion reattachment changed its frozen plan"
            );
            ensure!(preview["dependentBundles"].as_u64().unwrap_or(0) == 0
                || record.detail_json["native_dependency_ack"].as_bool() == Some(true),
                "interrupted deletion lacks the original dependency acknowledgement; preview and confirm again");
            return self.reserve_private(operation, private);
        }
        let method = match record.kind.as_str() {
            "backup" => "StartBackup",
            "restore" => "StartRestore",
            _ => bail!("operation cannot be reattached"),
        };
        let mut params = json!({"client_operation_id":operation});
        for key in [
            "app_id",
            "bundle_id",
            "mode",
            "performance_mode",
            "regenerable_caches",
            "native_selection",
        ] {
            if let Some(value) = record.detail_json.get(key) {
                params[key] = value.clone();
            }
        }
        self.rpc_private(method, &private, params).await?; // signed source replay, no work queued
        self.reserve_private(operation, private)
    }

    async fn rpc(&self, method: &str, params: Value) -> Result<Value> {
        // This allowlist is deliberately not a generic public RPC endpoint.
        ensure!(
            matches!(
                method,
                "GetHealth" | "GetOperationStatus" | "ListRecentOperations" | "CancelOperation"
            ),
            "native query is not public"
        );
        self.call(method, params).await
    }

    async fn rpc_private(
        &self,
        method: &str,
        private: &PrivateAccess,
        params: Value,
    ) -> Result<Value> {
        ensure!(
            matches!(
                method,
                "ListCloudCatalog"
                    | "StartBackup"
                    | "StartRestore"
                    | "PrepareDeletion"
                    | "StartDeletion"
                    | "RetryOperation"
            ),
            "native private operation is unsupported"
        );
        self.call(method, private.params(params)?).await
    }

    async fn call(&self, method: &str, params: Value) -> Result<Value> {
        AgentRpc(Arc::clone(&self.agent))
            .handle(&RpcRequest {
                id: Uuid::new_v4().to_string(),
                method: method.into(),
                params,
            })
            .await
            .map_err(public_source_error)
    }

    async fn manifest(&self, private: &PrivateAccess, selection: &Value) -> Result<BundleManifest> {
        let app = AppId(identifier(selection, "appId")?);
        let bundle = parse_uuid(selection, "bundleId")?;
        let (config, guard) =
            write_guarded_ephemeral_session(&self.agent.config.paths.run_root, &private.session)
                .map_err(public_source_error)?;
        let result = async {
            let provider = RcloneStorage::try_from_session(&private.session, &config)
                .map_err(public_source_error)?;
            let manifest =
                noland_storage::read_committed_manifest(&provider, &private.master, &app, bundle)
                    .await
                    .map_err(public_source_error)?;
            ensure!(
                manifest.files.len() <= MAX_MANIFEST_FILES,
                "manifest exceeds native file browse bound"
            );
            Ok(manifest)
        }
        .await;
        guard.finish().map_err(public_source_error)?;
        result
    }

    fn software_app(&self, params: &Value) -> Result<AppId> {
        let id = params
            .get("softwareId")
            .and_then(Value::as_str)
            .context("softwareId is required")?;
        self.software
            .lock()
            .map_err(|_| anyhow::anyhow!("native registration lock poisoned"))?
            .get(id)
            .map(|binding| binding.app.clone())
            .context("software has not been registered with approved native roots")
    }

    fn software_instance(&self, params: &Value) -> Result<String> {
        let id = identifier(params, "softwareId")?;
        let bindings = self
            .software
            .lock()
            .map_err(|_| anyhow::anyhow!("native registration lock poisoned"))?;
        let instance = &bindings
            .get(&id)
            .context("Approved software instance is not registered")?
            .instance;
        if let Some(given) = params.get("appId").and_then(Value::as_str) {
            ensure!(
                given == instance,
                "Native capture changed the approved software instance"
            );
        }
        Ok(instance.clone())
    }

    fn local_files(&self, app: &AppId) -> Result<Vec<Value>> {
        noland_state_agent::reconcile::reconcile_native_app(&self.agent, app)
            .map_err(public_source_error)?;
        let records = self
            .agent
            .db
            .associations_for_app(app)
            .map_err(public_source_error)?;
        let current_roots = self
            .agent
            .native_approved_roots(app)
            .map_err(public_source_error)?
            .into_iter()
            .map(|root| {
                let directory = SourcePath::new(&root)?.metadata()?.is_dir();
                Ok((root, directory))
            })
            .collect::<Result<Vec<_>>>()?;
        let mut files = Vec::new();
        for (record, _) in records {
            if record.file_type.as_deref() != Some("file") {
                continue;
            }
            let path = Path::new(&record.canonical_path);
            // Historical DB associations are hints, never current authority.
            // Filter BEFORE even inspecting a removed manual sibling's metadata.
            if !current_roots
                .iter()
                .any(|(root, directory)| path == root || *directory && path.starts_with(root))
            {
                continue;
            }
            let metadata = match SourcePath::new(path).and_then(|source| source.metadata()) {
                Err(StateError::Io(error)) if error.kind() == std::io::ErrorKind::NotFound => {
                    continue
                }
                result => result.map_err(public_source_error)?,
            };
            ensure!(
                metadata.is_file() && !metadata.is_symlink(),
                "native source file changed type"
            );
            let logical = self
                .agent
                .native_logical_path(app, path)
                .map_err(public_source_error)?;
            files.push(file_item(
                &logical.logical_root.as_token(),
                &logical.relative_path,
                false,
                metadata.len(),
            )?);
            ensure!(
                files.len() <= 250_000,
                "native inventory exceeds its file bound"
            );
        }
        files.sort_by(|a, b| a["id"].as_str().cmp(&b["id"].as_str()));
        Ok(files)
    }

    fn reserve_private(&self, id: Uuid, private: Arc<PrivateAccess>) -> Result<()> {
        let mut access = self
            .access
            .lock()
            .map_err(|_| anyhow::anyhow!("native access lock poisoned"))?;
        if access.len() >= MAX_PRIVATE_ACCESS && !access.contains_key(&id) {
            let mut disposable = Vec::new();
            for existing in access.keys() {
                if self
                    .agent
                    .db
                    .get_operation(*existing)
                    .map_err(public_source_error)?
                    .is_some_and(|op| op.state == "COMPLETED")
                    && !self.agent.operations.is_running(*existing)
                {
                    disposable.push(*existing);
                }
            }
            for existing in disposable {
                access.remove(&existing);
            }
        }
        ensure!(
            access.len() < MAX_PRIVATE_ACCESS || access.contains_key(&id),
            "native private operation access is at capacity; finish existing work first"
        );
        if let Some(prior) = access.get(&id) {
            ensure!(
                prior.provider_id == private.provider_id && prior.master.0 == private.master.0,
                "operation is bound to a different native provider"
            );
        }
        access.insert(id, private);
        Ok(())
    }

    fn activity(&self, raw: &Value) -> Result<Value> {
        let id = raw["operation_id"]
            .as_str()
            .context("source operation ID missing")?;
        let uuid = Uuid::parse_str(id)?;
        let source_state = raw["state"]
            .as_str()
            .context("source operation state missing")?;
        let running = raw["running"].as_bool().unwrap_or(false);
        let state = match source_state {
            "QUEUED" | "REQUESTED" => "queued",
            "COMPLETED" | "SEALED" => "completed",
            "FAILED" | "ROLLED_BACK" => "failed",
            "CANCELLED" => "cancelled",
            "INTERRUPTED" => "interrupted",
            _ => "running",
        };
        // A terminal DB write can precede the owning worker's joined teardown.
        // Do not let service shutdown/baseline finalization outrun that owner.
        let state =
            if running && matches!(state, "completed" | "failed" | "cancelled" | "interrupted") {
                "running"
            } else {
                state
            };
        let kind = match raw["kind"].as_str() {
            Some("backup") => "upload",
            Some("restore") => "download",
            Some("delete") => "delete",
            _ => bail!("unsupported native activity type"),
        };
        let private = self
            .access
            .lock()
            .map_err(|_| anyhow::anyhow!("native access lock poisoned"))?
            .get(&uuid)
            .cloned();
        let bindings = self
            .software
            .lock()
            .map_err(|_| anyhow::anyhow!("native registration lock poisoned"))?;
        let software = bindings
            .iter()
            .find(|(_, binding)| raw["app_id"].as_str() == Some(binding.app.as_str()));
        let progress = &raw["progress"];
        let detail = &progress["detail_json"];
        let mut value = json!({"id":id,"kind":kind,
            "name":software.map(|(_,binding)| binding.name.as_str()).unwrap_or(match kind { "upload"=>"Upload","download"=>"Download",_=>"Cloud deletion" }),
            "softwareId":software.map(|(id,_)| id.as_str()),"providerId":private.as_ref().map(|a| a.provider_id.as_str()),
            "state":state,"canCancel":running && !matches!(source_state,"COMPLETED"|"CANCELLED"|"FAILED"),
            "canRetry":!running && kind != "download" && matches!(state,"failed"|"cancelled"|"interrupted") && private.is_some(),
            "startedAt":raw["created_at"].as_str(),
            "finishedAt":if matches!(state,"completed"|"failed"|"cancelled"|"interrupted") {raw["updated_at"].as_str()} else {None},
            // Raw provider errors/private paths/operation detail never cross UI.
            "error":if state == "failed" {Some("Storage operation failed; verify provider access, source stability and available space before retrying.")} else {None},
        });
        if kind == "download" && matches!(state, "failed" | "cancelled" | "interrupted") {
            value["error"] = json!("Restore stopped. Any new outputs, partials and recovery artifacts are retained; automatic rollback and retry are disabled. A new restore requires a newly confirmed empty destination.");
        }
        if let Some(phase) = progress["phase"].as_str() {
            value["phase"] = json!(safe_phase(phase));
        }
        if progress["unit"].as_str() == Some("files") {
            copy_u64(progress, "completed_units", &mut value, "completedFiles");
            copy_u64(progress, "total_units", &mut value, "totalFiles");
        }
        if progress["unit"].as_str() == Some("bytes") {
            copy_u64(progress, "completed_units", &mut value, "completedBytes");
            copy_u64(progress, "total_units", &mut value, "totalBytes");
        } else if kind == "download" {
            copy_u64(
                &detail["pipeline"],
                "verified_bytes",
                &mut value,
                "completedBytes",
            );
            copy_u64(&detail["pipeline"], "total_bytes", &mut value, "totalBytes");
        } else {
            copy_u64(detail, "bytes_completed", &mut value, "completedBytes");
        }
        Ok(value)
    }
}

fn public_source_error(error: StateError) -> anyhow::Error {
    // Do not stringify a source Storage/Message error: it may contain raw
    // provider stderr, private configuration or a signed URL.
    let message = match error {
        StateError::UnsafePath(_) => {
            "native storage rejected an unsafe path or changed filesystem identity"
        }
        StateError::Integrity(_) => {
            "shared-storage authentication or integrity verification failed"
        }
        StateError::Crypto(_) => "shared-storage key authentication failed",
        StateError::Conflict(_) => {
            "shared-storage state changed or is busy; refresh and retry the exact plan"
        }
        StateError::NotFound(_) => "shared-storage item or operation was not found",
        StateError::Database(_) => "native shared-storage database failed",
        StateError::Io(_) => "native shared-storage filesystem or installed-tool operation failed",
        StateError::Invalid(_) => "shared-storage request or frozen selection is no longer valid",
        _ => "shared-storage operation failed; private provider details withheld",
    };
    anyhow::anyhow!(message)
}

fn native_capture_mode(selection: &Value) -> Result<(NativeCoverage, &'static str)> {
    match selection
        .pointer("/captureSource/selectionKind")
        .and_then(Value::as_str)
    {
        Some("full_scope") => Ok((NativeCoverage::FullApprovedScope, "complete_application")),
        Some("selected_nodes") | None => Ok((NativeCoverage::SelectedNodes, "custom")),
        Some(_) => bail!("Unknown authenticated native capture coverage"),
    }
}

fn validate_id(id: &str) -> Result<()> {
    ensure!(
        !id.is_empty()
            && id.len() <= 512
            && id
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b"_:.-@".contains(&b)),
        "invalid native metadata identifier"
    );
    Ok(())
}
fn identifier(value: &Value, key: &str) -> Result<String> {
    let id = value
        .get(key)
        .and_then(Value::as_str)
        .with_context(|| format!("{key} is required"))?;
    validate_id(id)?;
    Ok(id.into())
}
fn bounded_text(text: &str, limit: usize) -> Result<String> {
    ensure!(
        !text.is_empty() && text.len() <= limit && !text.chars().any(char::is_control),
        "untrusted metadata text is invalid"
    );
    Ok(text.into())
}
fn parse_uuid(value: &Value, key: &str) -> Result<Uuid> {
    Uuid::parse_str(
        value
            .get(key)
            .and_then(Value::as_str)
            .with_context(|| format!("{key} is required"))?,
    )
    .with_context(|| format!("{key} must be a UUID"))
}
fn operation_id(value: &Value) -> Result<Uuid> {
    if value.get("operationId").is_some() {
        parse_uuid(value, "operationId")
    } else {
        Ok(Uuid::new_v4())
    }
}
fn file_item(root: &str, relative: &str, directory: bool, size: u64) -> Result<Value> {
    ensure!(
        noland_state_core::LogicalRoot::parse(root).is_some(),
        "unknown authenticated logical root"
    );
    noland_state_agent::native_host::validate_native_relative(relative)
        .map_err(public_source_error)?;
    Ok(
        json!({"id":native_file_id(root,relative),"name":relative.rsplit('/').next().unwrap_or(relative),
        "path":relative,"directory":directory,"size":size,"rootId":root}),
    )
}
fn page(mut files: Vec<Value>, params: &Value) -> Result<Value> {
    files.sort_by(|a, b| a["id"].as_str().cmp(&b["id"].as_str()));
    let offset = file_page_offset(params, files.len())?;
    let limit = file_page_limit(params)?;
    let end = offset.saturating_add(limit).min(files.len());
    let next = (end < files.len()).then(|| end.to_string());
    Ok(json!({"files":files.drain(offset..end).collect::<Vec<_>>(),"nextCursor":next}))
}

fn file_page_offset(params: &Value, count: usize) -> Result<usize> {
    let offset = match params.get("cursor") {
        None | Some(Value::Null) => 0,
        Some(Value::String(raw)) if raw.len() <= 16 => {
            raw.parse::<usize>().context("invalid file cursor")?
        }
        _ => bail!("invalid file cursor"),
    };
    ensure!(
        offset <= count,
        "file cursor is outside the current inventory"
    );
    Ok(offset)
}
fn file_page_limit(params: &Value) -> Result<usize> {
    let limit = params
        .get("limit")
        .map(|v| v.as_u64().context("invalid file page limit"))
        .transpose()?
        .unwrap_or(200)
        .min(MAX_PAGE as u64) as usize;
    ensure!(limit > 0, "file page limit must be positive");
    Ok(limit)
}
fn selection_keys(selection: &Value, files: &[Value]) -> Result<Option<Vec<NativeFileKey>>> {
    let Some(ids) = selection.get("fileIds") else {
        return Ok(None);
    };
    let ids = ids.as_array().context("fileIds must be an array")?;
    ensure!(
        !ids.is_empty() && ids.len() <= 250_000,
        "select 1–250000 exact files"
    );
    let lookup = files
        .iter()
        .filter_map(|file| file["id"].as_str().map(|id| (id, file)))
        .collect::<HashMap<_, _>>();
    let mut keys = BTreeSet::new();
    for id in ids {
        let id = id.as_str().context("file identity must be text")?;
        let file = lookup
            .get(id)
            .context("selected file is outside the authenticated approved scope")?;
        ensure!(
            file["directory"].as_bool() == Some(false),
            "select individual files, not directory expansion"
        );
        keys.insert(NativeFileKey {
            logical_root: file["rootId"].as_str().context("file root missing")?.into(),
            relative_path: file["path"]
                .as_str()
                .context("file relative path missing")?
                .into(),
        });
    }
    ensure!(
        keys.len() == ids.len(),
        "duplicate file selection is invalid"
    );
    Ok(Some(keys.into_iter().collect()))
}
fn submission_result(result: Result<Value>, id: Uuid) -> Result<Value> {
    let value = result?;
    ensure!(
        value["operation_id"].as_str() == Some(id.to_string().as_str()),
        "source engine returned an unexpected operation identity"
    );
    Ok(json!({"operationId":id}))
}
fn copy_u64(from: &Value, key: &str, into: &mut Value, target: &str) {
    if let Some(value) = from[key].as_u64() {
        into[target] = json!(value);
    }
}
fn require_dependency_ack(dependencies: u64, selection: &Value) -> Result<()> {
    ensure!(
        dependencies == 0 || selection["acknowledgeDependencies"].as_bool() == Some(true),
        "dependent backups require separate explicit acknowledgement"
    );
    Ok(())
}
fn approved_destination_identity(
    selection: &Value,
    destination: &Path,
    pinned: &quicksave_platform::RootIdentity,
) -> Result<(u64, u64)> {
    ensure!(
        pinned.file_id[1] == 0,
        "unsupported native destination identity"
    );
    let Some(proofs) = selection.get("_approvedPaths") else {
        // Direct native-library callers already own their trusted path decision.
        // The IPC service always supplies the server-held gateway proof.
        return Ok((pinned.device, pinned.file_id[0]));
    };
    let proofs = proofs
        .as_array()
        .context("native approved path proofs must be an array")?;
    ensure!(
        proofs.len() <= 256,
        "native approved path proof bound exceeded"
    );
    let spelling = destination
        .to_str()
        .context("native destination must be UTF-8")?;
    let matches = proofs
        .iter()
        .filter(|proof| proof["path"].as_str() == Some(spelling))
        .collect::<Vec<_>>();
    ensure!(
        matches.len() == 1 && matches[0]["kind"].as_str() == Some("directory"),
        "native download destination lacks its exact approved directory proof"
    );
    let expected: quicksave_platform::RootIdentity =
        serde_json::from_value(matches[0]["identity"].clone())
            .map_err(|_| anyhow::anyhow!("native approved destination identity is malformed"))?;
    ensure!(
        &expected == pinned,
        "native download destination was replaced after confirmation"
    );
    Ok((expected.device, expected.file_id[0]))
}
fn safe_phase(phase: &str) -> String {
    phase
        .chars()
        .take(80)
        .filter(|c| c.is_ascii_alphanumeric() || matches!(c, '_' | '-' | ' '))
        .collect()
}

fn expected_capture_evidence(
    selection: &Value,
    keys: &[NativeFileKey],
    files: &[Value],
) -> Result<(String, Vec<NativeExpectedFile>)> {
    let capture = &selection["captureSource"];
    let snapshot = capture["snapshotIdentity"]
        .as_str()
        .filter(|value| !value.is_empty() && value.len() <= 512)
        .context("native upload requires the tracker snapshotIdentity")?;
    let evidence = capture["expectedFiles"].as_array().context(
        "native upload requires canonical captureSource.expectedFiles hash/size evidence",
    )?;
    ensure!(
        evidence.len() == keys.len() && !evidence.is_empty() && evidence.len() <= 250_000,
        "expected capture file evidence differs from the exact selected scope"
    );
    let selected = keys
        .iter()
        .map(|key| (native_file_id(&key.logical_root, &key.relative_path), key))
        .collect::<BTreeMap<_, _>>();
    let current = files
        .iter()
        .filter_map(|file| file["id"].as_str().map(|id| (id, file)))
        .collect::<BTreeMap<_, _>>();
    let mut bound = BTreeMap::new();
    for value in evidence {
        let id = value["id"]
            .as_str()
            .context("expected capture file ID missing")?;
        selected
            .get(id)
            .context("expected capture file is outside selected approved scope")?;
        let file = current
            .get(id)
            .context("expected source file disappeared before submission")?;
        ensure!(
            file["directory"].as_bool() == Some(false),
            "expected capture file is not a regular file"
        );
        let size = value["size"]
            .as_u64()
            .context("expected capture file size missing")?;
        ensure!(
            file["size"].as_u64() == Some(size),
            "source file size changed since approved capture"
        );
        let hash = value["fileHash"]
            .as_str()
            .context("expected capture fileHash missing")?;
        let hash = hash.strip_prefix("blake3:").unwrap_or(hash);
        ensure!(
            hash.len() == 64 && hash.bytes().all(|b| b.is_ascii_hexdigit()),
            "expected capture BLAKE3 hash is invalid"
        );
        let expected = NativeExpectedFile {
            id: id.into(),
            size,
            file_hash: format!("blake3:{}", hash.to_ascii_lowercase()),
        };
        ensure!(
            bound.insert(expected.id.clone(), expected).is_none(),
            "duplicate expected capture evidence"
        );
    }
    ensure!(
        bound.len() == keys.len(),
        "expected capture omitted selected file evidence"
    );
    Ok((snapshot.into(), bound.into_values().collect()))
}

#[cfg(test)]
mod tests;
