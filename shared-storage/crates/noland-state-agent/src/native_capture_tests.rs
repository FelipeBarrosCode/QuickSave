// SPDX-License-Identifier: GPL-3.0-only
// Derived RPC fixture patterns: No Land e81238a7536aae201540956ce76981364fd36595.
//! Actual AgentRpc admission and managed Custom capture. The only subprocess
//! transport is an explicitly installed, private local-only synthetic helper.
//! Enable noland-storage/native-test-runtime for this source unit-test build.

use super::*;
use crate::{
    native_host::{native_root_token, ApprovedNativeRoot, NativeRootRole, NativeSelection},
    rpc_handler::AgentRpc,
    AgentConfig,
};
use noland_rclone_adapter::EphemeralRcloneSession;
use noland_rpc::{RpcHandler, RpcRequest};
use noland_state_core::{AppIdentity, LogicalRootMap};
use noland_storage::LocalStorage;
use std::{
    fs,
    io::Read,
    os::unix::fs::{MetadataExt, PermissionsExt},
    process::{Command, Stdio},
    time::{Duration, Instant},
};

const CHILD: &str = "native_capture::tests::native_custom_rpc_local_child";
const CHILD_ROOT: &str = "QUICKSAVE_SYNTHETIC_NATIVE_RPC_ROOT";
const MAX_OUTPUT: u64 = 256 * 1024;

struct OwnedRoot {
    path: PathBuf,
    identity: (u64, u64),
}

impl OwnedRoot {
    fn create() -> Result<Self> {
        let preferred =
            Path::new("/private/var/folders/bm/fyg39kl11r5crgrby4bqs4lr0000gn/T/opencode");
        let parent = if preferred.is_dir() {
            preferred.to_path_buf()
        } else {
            std::env::temp_dir()
        };
        let path = fs::canonicalize(parent)?.join(format!("native-custom-rpc-{}", Uuid::new_v4()));
        fs::create_dir(&path)?;
        fs::set_permissions(&path, fs::Permissions::from_mode(0o700))?;
        let held = SourcePath::new(&path)?.open_directory()?;
        let metadata = held.metadata()?;
        Ok(Self {
            path,
            identity: (metadata.dev(), metadata.ino()),
        })
    }
}

impl Drop for OwnedRoot {
    fn drop(&mut self) {
        if SourcePath::new(&self.path)
            .and_then(|source| source.metadata())
            .is_ok_and(|metadata| {
                metadata.is_dir()
                    && !metadata.is_symlink()
                    && (metadata.dev(), metadata.ino()) == self.identity
            })
        {
            let _ = fs::remove_dir_all(&self.path);
        }
    }
}

#[test]
fn native_rpc_custom_mode_reaches_actual_managed_capture_without_a_complete_head() -> Result<()> {
    let root = OwnedRoot::create()?;
    let temporary = root.path.join("temporary");
    fs::create_dir(&temporary)?;
    let mut child = Command::new(std::env::current_exe()?)
        .args(["--exact", CHILD, "--nocapture", "--test-threads=1"])
        .env_clear()
        .env(CHILD_ROOT, &root.path)
        .env("TMPDIR", &temporary)
        .env("HOME", &root.path)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()?;
    fn reader(
        pipe: impl Read + Send + 'static,
    ) -> std::thread::JoinHandle<std::io::Result<Vec<u8>>> {
        std::thread::spawn(move || {
            let mut bytes = Vec::new();
            pipe.take(MAX_OUTPUT + 1).read_to_end(&mut bytes)?;
            Ok(bytes)
        })
    }
    let stdout = reader(child.stdout.take().unwrap());
    let stderr = reader(child.stderr.take().unwrap());
    let started = Instant::now();
    let status = loop {
        if let Some(status) = child.try_wait()? {
            break status;
        }
        if started.elapsed() > Duration::from_secs(90) {
            let _ = child.kill();
            let _ = child.wait();
            return Err(StateError::Storage(
                "isolated native RPC test exceeded its deadline".into(),
            ));
        }
        std::thread::sleep(Duration::from_millis(10));
    };
    let stdout = stdout.join().expect("bounded stdout reader")?;
    let stderr = stderr.join().expect("bounded stderr reader")?;
    assert!(stdout.len() <= MAX_OUTPUT as usize && stderr.len() <= MAX_OUTPUT as usize);
    assert!(
        status.success(),
        "isolated local RPC failed:\n{}\n{}",
        String::from_utf8_lossy(&stdout),
        String::from_utf8_lossy(&stderr)
    );
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn native_custom_rpc_local_child() -> Result<()> {
    let Some(root) = std::env::var_os(CHILD_ROOT).map(PathBuf::from) else {
        return Ok(());
    };
    let root = fs::canonicalize(root)?;
    let source = root.join("source");
    let repository = root.join("repository");
    let home = root.join("home");
    for path in [&source, &repository, &home] {
        fs::create_dir(path)?;
        fs::set_permissions(path, fs::Permissions::from_mode(0o700))?;
    }
    let bytes = b"actual custom RPC stable native capture";
    let save = source.join("save.dat");
    fs::write(&save, bytes)?;
    let mut config = AgentConfig::isolated(root.join("agent"));
    config.home = home;
    config.native_host = true;
    config.converge_complete_backups = false;
    config.capture_exclusions = vec![root.join("agent")];
    config.paths.ensure_dirs()?;
    for path in [
        &config.paths.state_root,
        &config.paths.run_root,
        &config.paths.staging,
        &config.paths.snapshots,
        &config.paths.packs,
        &config.paths.restore,
        &config.paths.checkpoints,
        &config.paths.cache,
    ] {
        fs::set_permissions(path, fs::Permissions::from_mode(0o700))?;
    }
    let agent = Arc::new(StateAgent::boot(config)?);
    *agent.roots.lock() = LogicalRootMap::default();
    let app = AppId("quicksave:isolated-native-rpc".into());
    let approved = SourcePath::new(&source)?.metadata()?;
    agent.native_register(
        AppIdentity::new(app.clone(), "Isolated Native RPC"),
        vec![ApprovedNativeRoot {
            id: "payload".into(),
            path: source.clone(),
            allowed_files: None,
            expected_identity: Some((approved.dev(), approved.ino())),
            role: NativeRootRole::Data,
        }],
    )?;
    let operation = Uuid::new_v4();
    let token = native_root_token(&app, "payload");
    let hash = noland_cas::blake3_hex(bytes);
    let selection = NativeSelection::parse(&json!({
        "version":1,"file_keys":[{"logical_root":token,"relative_path":"save.dat"}],
        "roots_fingerprint":agent.native_binding_fingerprint(&app)?,
        "snapshot_identity":"isolated-rpc-known-fixture-bytes",
        "expected_files":[{"id":native_file_id(&token,"save.dat"),"size":bytes.len(),"fileHash":hash}],
        "coverage":"selected_nodes","software_instance_id":"isolated-native-rpc-instance",
    }))?;
    let source_guard = source.clone();
    let held = Arc::new(SourcePath::new(&source)?.open_directory()?);
    let expected = (approved.dev(), approved.ino());
    agent.native_set_publication_guard(
        operation,
        Arc::new(move || {
            let current = SourcePath::new(&source_guard)?.metadata()?;
            let pinned = held.metadata()?;
            if !current.is_dir()
                || current.is_symlink()
                || (current.dev(), current.ino()) != expected
                || (pinned.dev(), pinned.ino()) != expected
            {
                return Err(StateError::Conflict(
                    "synthetic RPC source root replaced".into(),
                ));
            }
            Ok(())
        }),
    )?;
    let helper = root.join("local-helper");
    // The interpreter is explicit trusted test configuration. Never use a PATH
    // lookup or an inherited Python/rclone configuration in the helper process.
    let python = [
        "/usr/bin/python3",
        "/opt/homebrew/bin/python3",
        "/usr/local/bin/python3",
    ]
    .into_iter()
    .find(|path| Path::new(path).is_file())
    .ok_or_else(|| {
        StateError::Invalid(
            "isolated RPC helper requires an explicit local Python 3 interpreter".into(),
        )
    })?;
    let script = format!(
        "#!{python}\nROOT = {}\n{}",
        serde_json::to_string(root.to_str().unwrap())?,
        LOCAL_HELPER
    );
    fs::write(&helper, script)?;
    fs::set_permissions(&helper, fs::Permissions::from_mode(0o700))?;
    noland_storage::install_native_rclone_for_local_tests(&helper, &root)?;
    let master = MasterKey::generate();
    *agent.master_key.lock() = Some(master.clone());
    let session = EphemeralRcloneSession {
        operation_id: operation.to_string(),
        provider: "local".into(),
        backend_type: "local".into(),
        remote_name: "fixture".into(),
        root: repository.to_str().unwrap().into(),
        config_ini: "[fixture]\ntype = local\n".into(),
        expires_at_unix: 0,
        upload_concurrency: None,
    };
    let response = AgentRpc(agent.clone())
        .handle(&RpcRequest {
            id: "native-custom-start-rpc".into(),
            method: "StartBackup".into(),
            params: json!({
                "client_operation_id":operation,"app_id":app,"mode":"custom",
                "performance_mode":"automatic","native_selection":selection,"session":session,
            }),
        })
        .await?;
    assert_eq!(response["operation_id"], operation.to_string());
    assert_eq!(
        agent.db.get_operation(operation)?.unwrap().detail_json["mode"],
        "custom"
    );
    tokio::time::timeout(Duration::from_secs(60), async {
        while agent.operations.is_running(operation) {
            tokio::task::yield_now().await;
        }
    })
    .await
    .map_err(|_| StateError::Storage("isolated managed custom capture did not finish".into()))?;
    let record = agent.db.get_operation(operation)?.unwrap();
    assert_eq!(record.state, "COMPLETED", "{:?}", record.last_error);
    assert_eq!(record.detail_json["mode"], "custom");
    let bundle = Uuid::parse_str(record.detail_json["bundle_id"].as_str().unwrap())
        .map_err(|error| StateError::Integrity(error.to_string()))?;
    let local = LocalStorage::new(repository);
    let manifest = noland_storage::read_committed_manifest(&local, &master, &app, bundle).await?;
    assert_eq!(manifest.mode, BackupMode::Custom);
    assert_eq!(manifest.files.len(), 1);
    assert_eq!(manifest.files[0].file_hash, hash);
    assert!(manifest.tombstones.is_empty());
    let catalog = noland_storage::load_catalog(&local, &master).await?;
    let history = catalog
        .apps
        .iter()
        .find(|entry| entry.app_id == app)
        .unwrap();
    assert!(
        history.latest_complete_bundle_id.is_none(),
        "Custom selection must never create a complete head"
    );
    assert_eq!(fs::read(save)?, bytes);
    assert!(
        root.join("helper-commands.log").is_file(),
        "actual session transport must have executed"
    );
    assert!(
        agent.config.paths.rpc_socket.exists() == false,
        "no server or live application is launched"
    );
    Ok(())
}

// No network, real rclone fallback, deletion of history/payloads, external paths,
// environment credentials, or unsupported commands. All sizes/output are bounded.
const LOCAL_HELPER: &str = r#"
import json, os, shutil, sys
from pathlib import Path
root = Path(ROOT).resolve(strict=True)
repository = root / "repository"
def reject(message):
    print("permission denied: isolated helper " + message, file=sys.stderr)
    sys.exit(1)
def within(value, boundary):
    path = Path(value).resolve()
    try: path.relative_to(boundary)
    except ValueError: reject("operand escaped owned sandbox")
    return path
def operand(value):
    if value.startswith("fixture:"): return within(value[8:], repository)
    if ":" in value or not Path(value).is_absolute(): reject("non-local operand")
    return within(value, root)
def remote(value):
    if not value.startswith("fixture:"): reject("not the synthetic local provider")
    return operand(value)
def missing():
    print("object not found", file=sys.stderr)
    sys.exit(3)
args = sys.argv[1:]
if args and args[0] == "--ask-password=false": args.pop(0)
if len(args) < 4 or args[0] != "--config": reject("explicit private config required")
config = within(args[1], root)
if config.stat().st_size > 4096 or config.read_text() != "[fixture]\ntype = local\n":
    reject("config is not the exact isolated local fixture")
method, args = args[2], args[3:]
values = {"--files-from-raw","--checkers","--transfers","--buffer-size","--retries",
          "--low-level-retries","--stats","--log-level","--multi-thread-streams"}
switches = {"--no-traverse","--immutable","--stats-one-line","--use-json-log",
            "--no-modtime","--no-mimetype","--stat","-R","--error-on-no-transfer"}
operands, index = [], 0
while index < len(args):
    arg = args[index]
    if arg in values:
        if index + 1 >= len(args): reject("missing option value")
        index += 2
    elif arg in switches: index += 1
    elif arg.startswith("-"): reject("unsupported option")
    else:
        operands.append(arg)
        index += 1
if len(operands) != (2 if method in ("copy","copyto") else 1): reject("operand count")
log = root / "helper-commands.log"
if log.exists() and log.stat().st_size > 65536: reject("command count bound")
with log.open("a") as output: output.write(method + "\n")
def read(path):
    if path.stat().st_size > 8 * 1024 * 1024: reject("object size bound")
    return path.read_bytes()
def copied(source, destination, name):
    data = read(source)
    if "--immutable" in args and destination.exists():
        if read(destination) != data: reject("immutable conflict")
        return
    destination.parent.mkdir(parents=True, exist_ok=True)
    destination.write_bytes(data)
    print(json.dumps({"level":"info","object":name,"msg":"Copied (new)"}),file=sys.stderr)
if method == "mkdir": remote(operands[0]).mkdir(parents=True,exist_ok=True)
elif method == "lsjson":
    path = remote(operands[0])
    if not path.exists(): missing()
    if "--stat" in args:
        print(json.dumps({"Path":path.name,"Size":path.stat().st_size,"IsDir":path.is_dir()}))
    else:
        entries = []
        for child in path.rglob("*"):
            child = within(child,repository)
            if len(entries) >= 2048: reject("listing bound")
            entries.append({"Path":child.relative_to(path).as_posix(),"Size":0 if child.is_dir()
                            else child.stat().st_size,"IsDir":child.is_dir()})
        result = json.dumps(entries)
        if len(result) > 256 * 1024: reject("listing output bound")
        print(result)
elif method == "cat":
    path = remote(operands[0])
    if "--files-from-raw" in args:
        keys = sys.stdin.read(32769).splitlines()
        if len(keys) != 1 or len(keys[0]) > 32768 or Path(keys[0]).is_absolute(): reject("literal cat key")
        path = within(path / keys[0],repository)
    if not path.is_file(): missing()
    sys.stdout.buffer.write(read(path))
elif method in ("copy","copyto"):
    source, destination = map(operand,operands)
    if operands[1].startswith("fixture:"):
        if method == "copy":
            for index, child in enumerate(source.rglob("*")):
                if index >= 2048: reject("upload object bound")
                child = within(child,root)
                if child.is_file():
                    relative = child.relative_to(source)
                    copied(child,within(destination / relative,repository),relative.as_posix())
        else: copied(source,destination,destination.relative_to(repository).as_posix())
    else:
        if not operands[0].startswith("fixture:"): reject("invalid local download")
        destination.parent.mkdir(parents=True,exist_ok=True)
        destination.write_bytes(read(source))
elif method == "deletefile":
    path = remote(operands[0])
    if not path.relative_to(repository).as_posix().startswith("maintenance/activity/"):
        reject("payload/history deletion forbidden")
    if not path.is_file(): missing()
    path.unlink()
elif method == "rmdir":
    path = remote(operands[0])
    if not path.relative_to(repository).as_posix().startswith("maintenance/activity/"):
        reject("directory deletion forbidden")
    path.rmdir()
else: reject("unsupported command")
"#;
