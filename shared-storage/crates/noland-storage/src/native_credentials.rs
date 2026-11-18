// SPDX-License-Identifier: GPL-3.0-only
//! Checked native-private rclone token rotation. No serialization/logging APIs.

use crate::{EphemeralRcloneSession, ProviderKind};
use noland_state_core::{Result, StateError};
use serde::Deserialize;
use std::{
    collections::{BTreeMap, BTreeSet},
    fs::File,
    io::Read,
    path::{Path, PathBuf},
    sync::{
        atomic::{AtomicBool, AtomicUsize, Ordering},
        Arc, Mutex, OnceLock, Weak,
    },
};
use zeroize::{Zeroize, Zeroizing};

const MAX_CONFIG: usize = 2 * 1024 * 1024;
const MAX_BINDINGS: usize = 256;
const MAX_CONFIGS: usize = 1024;

fn rejected() -> StateError {
    StateError::Conflict("native credential handoff failed; private session retained; reattach fresh access or reauthorize".into())
}

/// Tokens and routing coordinates stay in Rust; deliberately no Debug/Serialize.
pub struct NativeCredentialRotation {
    pub operation_id: String,
    pub provider: String,
    pub remote_name: String,
    pub root: String,
    pub access_token: String,
    pub refresh_token: Option<String>,
    pub expires_at_unix: i64,
    /// Private revision captured at subprocess start, not a caller-editable ID.
    pub expected_token_fingerprint: [u8; 32],
    pub token_fingerprint: [u8; 32],
}

impl Drop for NativeCredentialRotation {
    fn drop(&mut self) {
        self.access_token.zeroize();
        self.refresh_token.zeroize();
    }
}

/// Return success ONLY after a binding-checked generation-CAS and vault read-back.
/// Callback errors/panics are replaced with static diagnostics at this boundary.
pub type NativePrivateCredentialSink =
    Arc<dyn Fn(&NativeCredentialRotation) -> Result<()> + Send + Sync>;

struct Binding {
    operation_id: String,
    provider: String,
    backend: String,
    remote: String,
    root: String,
    config_hash: blake3::Hash,
    scope_hash: blake3::Hash,
    recovery_scope: Option<[u8; 32]>,
    latest_token: Mutex<TokenSnapshot>,
    sink: NativePrivateCredentialSink,
    active: AtomicBool,
    failed: AtomicBool,
}

static BINDINGS: OnceLock<Mutex<BTreeMap<String, (uuid::Uuid, Arc<Binding>)>>> = OnceLock::new();
static CONFIGS: OnceLock<Mutex<BTreeMap<PathBuf, Weak<NativeConfigHandoff>>>> = OnceLock::new();
#[cfg(not(windows))]
type LiveDirectoryKey = PathBuf;
#[cfg(windows)]
type LiveDirectoryKey = (u64, [u64; 2], String);
static LIVE_DIRECTORIES: OnceLock<Mutex<BTreeSet<LiveDirectoryKey>>> = OnceLock::new();

fn live_key(directory: &Path) -> Result<LiveDirectoryKey> {
    #[cfg(not(windows))]
    return Ok(directory.to_path_buf());
    #[cfg(windows)]
    {
        let parent = directory.parent().ok_or_else(rejected)?;
        let file = noland_snapshot::SourcePath::new(parent)?.open_directory()?;
        let identity = noland_snapshot::native_metadata::identity_from_file(&file)?;
        let leaf = directory
            .file_name()
            .and_then(|name| name.to_str())
            .ok_or_else(rejected)?;
        if leaf.len() > 255 || !leaf.is_ascii() {
            return Err(rejected());
        }
        Ok((identity.volume, identity.file_id, leaf.to_ascii_lowercase()))
    }
}
// If the OS could not confirm termination, dropping the last handoff Arc must
// not make its still-unknown child recoverable. Keep a bounded, process-lifetime
// fail-closed latch; no retry may assume that child stopped.
static UNCONFIRMED_REAP: AtomicBool = AtomicBool::new(false);

pub(crate) fn require_confirmed_reaps() -> Result<()> {
    if UNCONFIRMED_REAP.load(Ordering::Acquire) {
        return Err(StateError::Conflict(
            "native helper exit could not be confirmed; retain private sessions and confirm stopped helpers before restart".into(),
        ));
    }
    Ok(())
}

pub(crate) struct NativeLiveSession {
    directory: LiveDirectoryKey,
}
impl NativeLiveSession {
    pub(crate) fn register(directory: &Path) -> Result<Self> {
        require_confirmed_reaps()?;
        let key = live_key(directory)?;
        let mut live = LIVE_DIRECTORIES
            .get_or_init(Mutex::default)
            .lock()
            .map_err(|_| rejected())?;
        if configs()
            .lock()
            .map_err(|_| rejected())?
            .values()
            .filter_map(Weak::upgrade)
            .any(|handoff| {
                handoff.directory_key == key && handoff.active_attempts.load(Ordering::Acquire) != 0
            })
        {
            return Err(rejected());
        }
        if live.len() >= MAX_CONFIGS || !live.insert(key.clone()) {
            return Err(rejected());
        }
        Ok(Self { directory: key })
    }
}
impl Drop for NativeLiveSession {
    fn drop(&mut self) {
        if let Ok(mut live) = LIVE_DIRECTORIES.get_or_init(Mutex::default).lock() {
            live.remove(&self.directory);
        }
    }
}
pub(crate) fn live_directory(directory: &Path) -> Result<bool> {
    require_confirmed_reaps()?;
    let key = live_key(directory)?;
    if LIVE_DIRECTORIES
        .get_or_init(Mutex::default)
        .lock()
        .map_err(|_| rejected())?
        .contains(&key)
    {
        return Ok(true);
    }
    // A caller that incorrectly drops its outer guard while a child is active
    // must not make that child's directory eligible for startup/recovery cleanup.
    Ok(configs()
        .lock()
        .map_err(|_| rejected())?
        .values()
        .filter_map(Weak::upgrade)
        .any(|handoff| {
            handoff.directory_key == key && handoff.active_attempts.load(Ordering::Acquire) != 0
        }))
}

fn bindings() -> &'static Mutex<BTreeMap<String, (uuid::Uuid, Arc<Binding>)>> {
    BINDINGS.get_or_init(Mutex::default)
}
fn configs() -> &'static Mutex<BTreeMap<PathBuf, Weak<NativeConfigHandoff>>> {
    CONFIGS.get_or_init(Mutex::default)
}

/// Hold with the operation's native ProviderAccess. This is not a global/default
/// rclone config: the registration authorizes exactly ONE immutable session.
pub struct NativeCredentialSinkRegistration {
    id: uuid::Uuid,
    binding: Arc<Binding>,
}

impl NativeCredentialSinkRegistration {
    /// Publication barrier: checkpoint every live config for this exact session.
    /// Reject concurrent subprocess use rather than race a half-written config.
    pub fn checkpoint(&self) -> Result<()> {
        require_confirmed_reaps()?;
        if !self.binding.active.load(Ordering::Acquire)
            || self.binding.failed.load(Ordering::Acquire)
        {
            return Err(rejected());
        }
        let live = configs()
            .lock()
            .map_err(|_| rejected())?
            .values()
            .filter_map(Weak::upgrade)
            .filter(|handoff| {
                handoff
                    .binding
                    .as_ref()
                    .is_some_and(|binding| Arc::ptr_eq(binding, &self.binding))
            })
            .collect::<Vec<_>>();
        for handoff in live {
            handoff.finish()?;
        }
        Ok(())
    }

    /// Only after the owning worker has stopped, before native reauthorization /
    /// checked retained-session recovery creates a fresh binding. Ordinary retry
    /// must retain the existing binding/cache, not clear a persistence failure.
    pub fn invalidate(&self) -> Result<()> {
        self.binding.active.store(false, Ordering::Release);
        let mut registry = bindings().lock().map_err(|_| rejected())?;
        if registry
            .get(&self.binding.operation_id)
            .is_some_and(|(id, _)| *id == self.id)
        {
            registry.remove(&self.binding.operation_id);
        }
        Ok(())
    }
}

impl Drop for NativeCredentialSinkRegistration {
    fn drop(&mut self) {
        self.binding.active.store(false, Ordering::Release);
        if let Ok(mut registry) = bindings().lock() {
            if registry
                .get(&self.binding.operation_id)
                .is_some_and(|(id, _)| *id == self.id)
            {
                registry.remove(&self.binding.operation_id);
            }
        }
    }
}

pub fn register_native_private_credential_sink(
    session: &EphemeralRcloneSession,
    sink: NativePrivateCredentialSink,
) -> Result<NativeCredentialSinkRegistration> {
    register_sink(session, sink, false, None)
}

/// Native host proof bound to its workspace/provider authority revision, not
/// JavaScript input or token text. Persisted only in the private session artifact.
pub fn register_native_private_credential_sink_with_scope(
    session: &EphemeralRcloneSession,
    sink: NativePrivateCredentialSink,
    recovery_scope: [u8; 32],
) -> Result<NativeCredentialSinkRegistration> {
    register_sink(session, sink, false, Some(recovery_scope))
}

/// Only for checked recovery of this app's retained private config, never an
/// ordinary retry that ignores a prior persistence failure.
pub fn register_native_private_credential_sink_for_recovery(
    session: &EphemeralRcloneSession,
    sink: NativePrivateCredentialSink,
) -> Result<NativeCredentialSinkRegistration> {
    register_sink(session, sink, true, None)
}

pub fn register_native_private_credential_sink_for_recovery_with_scope(
    session: &EphemeralRcloneSession,
    sink: NativePrivateCredentialSink,
    recovery_scope: [u8; 32],
) -> Result<NativeCredentialSinkRegistration> {
    register_sink(session, sink, true, Some(recovery_scope))
}

fn register_sink(
    session: &EphemeralRcloneSession,
    sink: NativePrivateCredentialSink,
    recovery: bool,
    recovery_scope: Option<[u8; 32]>,
) -> Result<NativeCredentialSinkRegistration> {
    require_confirmed_reaps()?;
    let kind = ProviderKind::parse(&session.provider).ok_or_else(rejected)?;
    if !kind.is_oauth() || session.operation_id.is_empty() || session.operation_id.len() > 255 {
        return Err(rejected());
    }
    let initial = ConfigDocument::parse(&session.config_ini, &session.remote_name)?;
    initial.validate_backend(session)?;
    let tokens = initial.tokens()?.ok_or_else(rejected)?;
    if tokens.refresh_token.is_none() {
        return Err(rejected());
    }
    let id = uuid::Uuid::new_v4();
    let binding = Arc::new(Binding {
        operation_id: session.operation_id.clone(),
        provider: session.provider.clone(),
        backend: session.backend_type.clone(),
        remote: session.remote_name.clone(),
        root: session.root.clone(),
        config_hash: blake3::hash(session.config_ini.as_bytes()),
        scope_hash: initial.scope_hash(),
        recovery_scope,
        latest_token: Mutex::new(tokens),
        sink,
        active: AtomicBool::new(true),
        failed: AtomicBool::new(false),
    });
    let mut registry = bindings().lock().map_err(|_| rejected())?;
    if let Some((_, old)) = registry.get(&session.operation_id) {
        if !recovery
            || !old.failed.load(Ordering::Acquire)
            || old.provider != binding.provider
            || old.backend != binding.backend
            || old.remote != binding.remote
            || old.root != binding.root
            || old.scope_hash != binding.scope_hash
            || old.recovery_scope != binding.recovery_scope
        {
            return Err(rejected());
        }
        let active = configs()
            .lock()
            .map_err(|_| rejected())?
            .values()
            .filter_map(Weak::upgrade)
            .any(|handoff| {
                handoff
                    .binding
                    .as_ref()
                    .is_some_and(|found| Arc::ptr_eq(found, old))
                    && handoff.active_attempts.load(Ordering::Acquire) != 0
            });
        if active {
            return Err(rejected());
        }
        old.active.store(false, Ordering::Release);
        crate::native_transfer_policy::invalidate_stopped_operation(&session.operation_id)?;
    } else if registry.len() >= MAX_BINDINGS {
        return Err(rejected());
    }
    registry.insert(session.operation_id.clone(), (id, Arc::clone(&binding)));
    Ok(NativeCredentialSinkRegistration { id, binding })
}

/// Native scope comparison permits token changes only, never routing, client,
/// backend, root or static-credential edits. Operation IDs are bound separately
/// by the owning request/registration.
pub fn native_sessions_have_same_scope(
    first: &EphemeralRcloneSession,
    second: &EphemeralRcloneSession,
) -> Result<bool> {
    if first.provider != second.provider
        || first.backend_type != second.backend_type
        || first.remote_name != second.remote_name
        || first.root != second.root
        || first.upload_concurrency != second.upload_concurrency
    {
        return Ok(false);
    }
    let first_config = ConfigDocument::parse(&first.config_ini, &first.remote_name)?;
    let second_config = ConfigDocument::parse(&second.config_ini, &second.remote_name)?;
    first_config.validate_backend(first)?;
    second_config.validate_backend(second)?;
    let kind = ProviderKind::parse(&first.provider).ok_or_else(rejected)?;
    if first_config.0.len() != second_config.0.len() {
        return Ok(false);
    }
    for (key, first_value) in &first_config.0 {
        let Some(second_value) = second_config.0.get(key) else {
            return Ok(false);
        };
        if key == "token" {
            continue;
        }
        let obscured = (key == "pass" && matches!(kind, ProviderKind::Sftp | ProviderKind::Webdav))
            || key == "key_file_pass" && kind == ProviderKind::Sftp;
        if obscured {
            // Separate adapter sessions use random obscure IVs. Compare their
            // native-private plaintext, not randomized encoding. Guard refresh
            // validation itself still permits TOKEN updates ONLY.
            if reveal_rclone_obscured(first_value)?[..] != reveal_rclone_obscured(second_value)?[..]
            {
                return Ok(false);
            }
        } else if first_value != second_value {
            return Ok(false);
        }
    }
    Ok(true)
}

fn reveal_rclone_obscured(value: &str) -> Result<Zeroizing<Vec<u8>>> {
    use aes::cipher::{BlockEncrypt, KeyInit};
    use base64::Engine;
    // Public rclone format-compatibility key, not a repository/device/client key.
    // Same documented format already used by noland-rclone-adapter/providers.rs.
    // Keep the exact public compatibility bytes from the active adapter.
    const COMPAT_KEY: [u8; 32] = [
        0x9c, 0x93, 0x5b, 0x48, 0x73, 0x0a, 0x55, 0x4d, 0x6b, 0xfd, 0x7c, 0x63, 0xc8, 0x86, 0xa9,
        0x2b, 0xd3, 0x90, 0x19, 0x8e, 0xb8, 0x12, 0x8a, 0xfb, 0xf4, 0xde, 0x16, 0x2b, 0x8b, 0x95,
        0xf6, 0x38,
    ];
    if value.len() > MAX_CONFIG {
        return Err(rejected());
    }
    let mut bytes = Zeroizing::new(
        base64::engine::general_purpose::URL_SAFE_NO_PAD
            .decode(value)
            .map_err(|_| rejected())?,
    );
    if bytes.len() < 16 {
        return Err(rejected());
    }
    let iv: [u8; 16] = bytes[..16].try_into().map_err(|_| rejected())?;
    drop(bytes.drain(..16));
    let cipher = aes::Aes256::new_from_slice(&COMPAT_KEY).map_err(|_| rejected())?;
    let mut counter = u128::from_be_bytes(iv);
    for chunk in bytes.chunks_mut(16) {
        let mut block = aes::cipher::Block::<aes::Aes256>::from(counter.to_be_bytes());
        cipher.encrypt_block(&mut block);
        for (byte, key) in chunk.iter_mut().zip(block.iter()) {
            *byte ^= key;
        }
        counter = counter.wrapping_add(1);
    }
    Ok(bytes)
}

/// Opaque native-only revision for the callback's generation-CAS. Never persist
/// it in a public DTO or treat a fingerprint as authorization by itself.
pub fn native_session_token_fingerprint(session: &EphemeralRcloneSession) -> Result<[u8; 32]> {
    ConfigDocument::parse(&session.config_ini, &session.remote_name)?
        .tokens()?
        .ok_or_else(rejected)?
        .fingerprint()
}

fn retained_original_token(
    original: &EphemeralRcloneSession,
    expected: &EphemeralRcloneSession,
) -> Result<TokenSnapshot> {
    if original.operation_id != expected.operation_id
        || original.provider != expected.provider
        || original.backend_type != expected.backend_type
        || original.remote_name != expected.remote_name
        || original.root != expected.root
        || original.upload_concurrency != expected.upload_concurrency
    {
        return Err(rejected());
    }
    let original_config = ConfigDocument::parse(&original.config_ini, &original.remote_name)?;
    let expected_config = ConfigDocument::parse(&expected.config_ini, &expected.remote_name)?;
    original_config.validate_backend(original)?;
    if !original_config.invariants_match(&expected_config) {
        return Err(rejected());
    }
    if expected_config.tokens()?.is_none() {
        return Err(rejected());
    }
    original_config.tokens()?.ok_or_else(rejected)
}

pub(crate) fn recovery_scope_for_session(
    session: &EphemeralRcloneSession,
) -> Result<Option<[u8; 32]>> {
    let kind = ProviderKind::parse(&session.provider).ok_or_else(rejected)?;
    if !kind.is_oauth() {
        return Ok(None);
    }
    let registry = bindings().lock().map_err(|_| rejected())?;
    let (_, binding) = registry.get(&session.operation_id).ok_or_else(rejected)?;
    if binding.provider != session.provider
        || binding.backend != session.backend_type
        || binding.remote != session.remote_name
        || binding.root != session.root
        || binding.config_hash != blake3::hash(session.config_ini.as_bytes())
        || !binding.active.load(Ordering::Acquire)
        || binding.failed.load(Ordering::Acquire)
    {
        return Err(rejected());
    }
    Ok(binding.recovery_scope)
}

struct ConfigDocument(BTreeMap<String, String>);
impl Drop for ConfigDocument {
    fn drop(&mut self) {
        for value in self.0.values_mut() {
            value.zeroize();
        }
    }
}
impl ConfigDocument {
    fn scope_hash(&self) -> blake3::Hash {
        let mut hash = blake3::Hasher::new();
        for (key, value) in &self.0 {
            if key == "token" {
                continue;
            }
            hash.update(&(key.len() as u64).to_le_bytes());
            hash.update(key.as_bytes());
            hash.update(&(value.len() as u64).to_le_bytes());
            hash.update(value.as_bytes());
        }
        hash.finalize()
    }
    fn parse(text: &str, remote: &str) -> Result<Self> {
        if text.len() > MAX_CONFIG
            || text.contains('\0')
            || remote.is_empty()
            || remote.len() > 255
            || remote.contains(['[', ']', '\r', '\n'])
        {
            return Err(rejected());
        }
        let expected = format!("[{remote}]");
        let mut section = false;
        let mut entries = BTreeMap::new();
        for raw in text.lines() {
            let line = raw.trim();
            if line.is_empty() || line.starts_with(['#', ';']) {
                continue;
            }
            if line.starts_with('[') {
                if section || line != expected {
                    return Err(rejected());
                }
                section = true;
                continue;
            }
            if !section || entries.len() >= 128 {
                return Err(rejected());
            }
            let (key, value) = line.split_once('=').ok_or_else(rejected)?;
            let key = key.trim();
            if key.is_empty()
                || key.len() > 128
                || !key
                    .bytes()
                    .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'_')
                || entries
                    .insert(key.to_owned(), value.trim().to_owned())
                    .is_some()
            {
                return Err(rejected());
            }
        }
        if !section || !entries.contains_key("type") {
            return Err(rejected());
        }
        Ok(Self(entries))
    }

    fn validate_backend(&self, session: &EphemeralRcloneSession) -> Result<()> {
        let kind = ProviderKind::parse(&session.provider).ok_or_else(rejected)?;
        if self.0.get("type").map(String::as_str) != Some(session.backend_type.as_str())
            || noland_rclone_adapter::validate_provider_backend(kind, &session.backend_type)
                .is_err()
        {
            return Err(rejected());
        }
        if kind.is_oauth() {
            // Never fall back to rclone's production application registration.
            if self
                .0
                .get("client_id")
                .is_none_or(|id| id.trim().is_empty())
                || (kind == ProviderKind::Box
                    && self
                        .0
                        .get("client_secret")
                        .is_none_or(|secret| secret.trim().is_empty()))
            {
                return Err(rejected());
            }
        } else if self.0.contains_key("token") {
            return Err(rejected());
        }
        Ok(())
    }

    fn invariants_match(&self, expected: &Self) -> bool {
        self.0.len() == expected.0.len()
            && expected
                .0
                .iter()
                .all(|(key, value)| key == "token" || self.0.get(key) == Some(value))
            && self.0.contains_key("token") == expected.0.contains_key("token")
    }

    fn tokens(&self) -> Result<Option<TokenSnapshot>> {
        self.0
            .get("token")
            .map(|value| {
                let token: TokenSnapshot = serde_json::from_str(value).map_err(|_| rejected())?;
                token.validate()?;
                Ok(token)
            })
            .transpose()
    }
}

#[derive(Deserialize, PartialEq, Eq, Clone)]
#[serde(deny_unknown_fields)]
struct TokenSnapshot {
    access_token: String,
    token_type: String,
    #[serde(default)]
    refresh_token: Option<String>,
    expiry: String,
    #[serde(default)]
    expires_in: Option<u64>,
}
impl Drop for TokenSnapshot {
    fn drop(&mut self) {
        self.access_token.zeroize();
        self.refresh_token.zeroize();
        self.expiry.zeroize();
        self.token_type.zeroize();
    }
}
impl TokenSnapshot {
    fn validate(&self) -> Result<()> {
        let valid = |text: &str| {
            !text.is_empty()
                && text.len() <= 64 * 1024
                && text.is_ascii()
                && !text
                    .bytes()
                    .any(|byte| byte.is_ascii_control() || byte.is_ascii_whitespace())
        };
        if !valid(&self.access_token)
            || !self.token_type.eq_ignore_ascii_case("bearer")
            || self
                .refresh_token
                .as_deref()
                .is_some_and(|token| !valid(token))
            || self.expires_in.is_some_and(|value| value > 365 * 24 * 3600)
            || self.expires_at()? <= 0
        {
            return Err(rejected());
        }
        Ok(())
    }
    fn expires_at(&self) -> Result<i64> {
        if self.expiry.len() > 128 {
            return Err(rejected());
        }
        chrono::DateTime::parse_from_rfc3339(&self.expiry)
            .map(|time| time.timestamp())
            .map_err(|_| rejected())
    }
    fn same_tokens(&self, other: &Self) -> Result<bool> {
        Ok(self.access_token == other.access_token
            && self.refresh_token == other.refresh_token
            && self.expires_at()? == other.expires_at()?)
    }
    fn fingerprint(&self) -> Result<[u8; 32]> {
        let mut hash = blake3::Hasher::new();
        hash.update(b"QuickSave native credential revision v1\0");
        for text in [
            self.access_token.as_str(),
            self.refresh_token.as_deref().unwrap_or(""),
        ] {
            hash.update(&(text.len() as u64).to_le_bytes());
            hash.update(text.as_bytes());
        }
        hash.update(&self.expires_at()?.to_le_bytes());
        Ok(*hash.finalize().as_bytes())
    }
    fn config_json(&self) -> Result<Zeroizing<String>> {
        #[derive(serde::Serialize)]
        struct Wire<'a> {
            access_token: &'a str,
            token_type: &'a str,
            #[serde(skip_serializing_if = "Option::is_none")]
            refresh_token: Option<&'a str>,
            expiry: &'a str,
        }
        serde_json::to_string(&Wire {
            access_token: &self.access_token,
            token_type: &self.token_type,
            refresh_token: self.refresh_token.as_deref(),
            expiry: &self.expiry,
        })
        .map(Zeroizing::new)
        .map_err(|_| rejected())
    }
}

pub(crate) struct NativeConfigHandoff {
    path: PathBuf,
    directory_key: LiveDirectoryKey,
    #[cfg(any(unix, windows))]
    source: noland_snapshot::SourcePath,
    #[cfg(any(unix, windows))]
    directory: File,
    expected: ConfigDocument,
    recovery_original_token: Option<TokenSnapshot>,
    last_token: Mutex<Option<TokenSnapshot>>,
    binding: Option<Arc<Binding>>,
    provider: String,
    backend: String,
    remote: String,
    root: String,
    failed: AtomicBool,
    active_attempts: AtomicUsize,
    unreaped_child: AtomicBool,
    closed: AtomicBool,
    retired: AtomicBool,
    admission: Mutex<()>,
    publication_active: AtomicBool,
}

impl NativeConfigHandoff {
    #[cfg(any(unix, windows))]
    pub(crate) fn create(
        path: &Path,
        directory: &File,
        session: &EphemeralRcloneSession,
    ) -> Result<Arc<Self>> {
        Self::create_inner(path, directory, session, None)
    }

    #[cfg(any(unix, windows))]
    pub(crate) fn create_for_recovery(
        path: &Path,
        directory: &File,
        original: &EphemeralRcloneSession,
        original_scope: Option<[u8; 32]>,
        expected: &EphemeralRcloneSession,
    ) -> Result<Arc<Self>> {
        Self::create_inner(path, directory, expected, Some((original, original_scope)))
    }

    #[cfg(any(unix, windows))]
    fn create_inner(
        path: &Path,
        directory: &File,
        session: &EphemeralRcloneSession,
        recovery: Option<(&EphemeralRcloneSession, Option<[u8; 32]>)>,
    ) -> Result<Arc<Self>> {
        let expected = ConfigDocument::parse(&session.config_ini, &session.remote_name)?;
        expected.validate_backend(session)?;
        let mut tokens = expected.tokens()?;
        let binding = if tokens.is_some() {
            let registry = bindings().lock().map_err(|_| rejected())?;
            let (_, binding) = registry.get(&session.operation_id).ok_or_else(rejected)?;
            if binding.provider != session.provider
                || binding.backend != session.backend_type
                || binding.remote != session.remote_name
                || binding.root != session.root
                || binding.config_hash != blake3::hash(session.config_ini.as_bytes())
                || !binding.active.load(Ordering::Acquire)
                || binding.failed.load(Ordering::Acquire)
            {
                return Err(rejected());
            }
            Some(Arc::clone(binding))
        } else {
            None
        };
        if let Some(binding) = &binding {
            tokens = Some(binding.latest_token.lock().map_err(|_| rejected())?.clone());
        }
        let recovery_original_token = recovery
            .map(|(original, scope)| {
                let binding = binding.as_ref().ok_or_else(rejected)?;
                if binding.recovery_scope != scope {
                    return Err(rejected());
                }
                retained_original_token(original, session)
            })
            .transpose()?;
        let handoff = Arc::new(Self {
            path: path.to_path_buf(),
            directory_key: live_key(path.parent().ok_or_else(rejected)?)?,
            source: noland_snapshot::SourcePath::new(path.parent().ok_or_else(rejected)?)?,
            directory: directory.try_clone()?,
            expected,
            recovery_original_token,
            last_token: Mutex::new(tokens),
            binding,
            provider: session.provider.clone(),
            backend: session.backend_type.clone(),
            remote: session.remote_name.clone(),
            root: session.root.clone(),
            failed: AtomicBool::new(false),
            active_attempts: AtomicUsize::new(0),
            unreaped_child: AtomicBool::new(false),
            closed: AtomicBool::new(false),
            retired: AtomicBool::new(false),
            admission: Mutex::new(()),
            publication_active: AtomicBool::new(false),
        });
        let mut registry = configs().lock().map_err(|_| rejected())?;
        registry.retain(|_, value| value.strong_count() > 0);
        if let Some(old) = registry.get(path).and_then(Weak::upgrade) {
            if !old.failed.load(Ordering::Acquire)
                || old.active_attempts.load(Ordering::Acquire) != 0
                || old
                    .binding
                    .as_ref()
                    .is_none_or(|binding| binding.active.load(Ordering::Acquire))
            {
                return Err(rejected());
            }
        } else if registry.len() >= MAX_CONFIGS {
            return Err(rejected());
        }
        registry.insert(path.to_path_buf(), Arc::downgrade(&handoff));
        Ok(handoff)
    }

    /// Reused retry/nested session objects materialize the latest already-CAS-
    /// committed token. No vault read per file/chunk or global config is used.
    #[cfg(any(unix, windows))]
    pub(crate) fn initialize_from_native_cache(&self) -> Result<()> {
        self.write_native_cached_config(false)
    }

    #[cfg(any(unix, windows))]
    fn write_native_cached_config(&self, access_only: bool) -> Result<()> {
        let Some(binding) = &self.binding else {
            return Ok(());
        };
        if !binding.active.load(Ordering::Acquire) {
            return Err(rejected());
        }
        let mut token = binding.latest_token.lock().map_err(|_| rejected())?.clone();
        if access_only {
            token.refresh_token = None;
        }
        let json = token.config_json()?;
        let mut config = Zeroizing::new(format!("[{}]\n", self.remote));
        for (key, value) in &self.expected.0 {
            config.push_str(key);
            config.push_str(" = ");
            config.push_str(if key == "token" { json.as_str() } else { value });
            config.push('\n');
        }
        if config.len() > MAX_CONFIG {
            return Err(rejected());
        }
        self.verify_directory()?;
        let temporary =
            noland_snapshot::SourcePath::child(&self.directory, "rclone-native.tmp".into())?;
        let mut file = temporary.open_partial_private(true)?;
        let published = (|| -> Result<()> {
            use std::io::Write;
            file.write_all(config.as_bytes())?;
            file.sync_all()?;
            drop(file); // Windows rename requires every ordinary writer closed.
            self.verify_directory()?;
            #[cfg(unix)]
            {
                use std::os::fd::AsRawFd;
                let from = std::ffi::CString::new("rclone-native.tmp").map_err(|_| rejected())?;
                let to = std::ffi::CString::new("rclone.conf").map_err(|_| rejected())?;
                // Replace only this owned leaf, never truncate a linked inode.
                if unsafe {
                    libc::renameat(
                        self.directory.as_raw_fd(),
                        from.as_ptr(),
                        self.directory.as_raw_fd(),
                        to.as_ptr(),
                    )
                } != 0
                {
                    return Err(std::io::Error::last_os_error().into());
                }
            }
            #[cfg(windows)]
            crate::native_windows::replace_private_config(&self.directory)?;
            noland_snapshot::native_metadata::flush_directory(&self.directory)?;
            self.verify_directory()?;
            Ok(())
        })();
        if published.is_err() {
            if let Ok(metadata) = temporary.metadata() {
                let _ = temporary.delete_leaf(&metadata);
            }
        }
        published?;
        if !access_only {
            *self.last_token.lock().map_err(|_| rejected())? = Some(token);
        }
        Ok(())
    }

    pub(crate) fn for_storage(
        session: &EphemeralRcloneSession,
        path: &Path,
    ) -> Result<Option<Arc<Self>>> {
        let handoff = configs()
            .lock()
            .map_err(|_| rejected())?
            .get(path)
            .and_then(Weak::upgrade);
        if let Some(handoff) = &handoff {
            if handoff.provider != session.provider
                || handoff.backend != session.backend_type
                || handoff.remote != session.remote_name
                || handoff.root != session.root
            {
                return Err(rejected());
            }
        } else if ProviderKind::parse(&session.provider).is_some_and(|kind| kind.is_oauth()) {
            return Err(rejected());
        }
        Ok(handoff)
    }

    pub(crate) fn verify_storage(
        &self,
        provider: &str,
        backend: &str,
        remote: &str,
        root: &str,
        args: &[String],
    ) -> Result<()> {
        let config_args = args
            .windows(2)
            .filter(|pair| pair[0] == "--config")
            .collect::<Vec<_>>();
        if self.provider != provider
            || self.backend != backend
            || self.remote != remote
            || self.root != root
            || config_args.len() != 1
            || Path::new(&config_args[0][1]) != self.path
            || args
                .iter()
                .any(|arg| arg.starts_with("--config=") || arg == "--password-command")
        {
            return Err(rejected());
        }
        Ok(())
    }

    pub(crate) fn checkpoint(&self) -> Result<()> {
        self.checkpoint_expected(None)
    }

    fn checkpoint_expected(&self, expected_fingerprint: Option<[u8; 32]>) -> Result<()> {
        if self.failed.load(Ordering::Acquire) {
            return Err(rejected());
        }
        let result = self.checkpoint_inner(expected_fingerprint);
        if result.is_err() {
            self.failed.store(true, Ordering::Release);
            if let Some(binding) = &self.binding {
                binding.failed.store(true, Ordering::Release);
            }
        }
        result.map_err(|_| rejected())
    }

    pub(crate) fn must_retain(&self) -> bool {
        self.binding.is_some()
            || self.unreaped_child.load(Ordering::Acquire)
            || self.active_attempts.load(Ordering::Acquire) != 0
    }

    pub(crate) fn retain_after_unreaped_child(&self) {
        UNCONFIRMED_REAP.store(true, Ordering::Release);
        self.unreaped_child.store(true, Ordering::Release);
        self.failed.store(true, Ordering::Release);
        if let Some(binding) = &self.binding {
            binding.failed.store(true, Ordering::Release);
        }
    }

    pub(crate) fn finish(&self) -> Result<()> {
        let _admission = self.admission.lock().map_err(|_| rejected())?;
        if self.retired.load(Ordering::Acquire) {
            return Ok(());
        }
        if self.active_attempts.load(Ordering::Acquire) != 0 {
            return Err(rejected());
        }
        self.checkpoint()
    }

    /// Teardown seals admission before checking tokens or removing owned files.
    /// A consumed/dropped outer guard can never authorize a new subprocess.
    pub(crate) fn close(&self) -> Result<()> {
        let _admission = self.admission.lock().map_err(|_| rejected())?;
        self.closed.store(true, Ordering::Release);
        if self.active_attempts.load(Ordering::Acquire) != 0 {
            self.failed.store(true, Ordering::Release);
            if let Some(binding) = &self.binding {
                binding.failed.store(true, Ordering::Release);
            }
            return Err(rejected());
        }
        self.checkpoint()
    }

    pub(crate) fn retire(&self) {
        self.retired.store(true, Ordering::Release);
    }

    fn checkpoint_inner(&self, expected_fingerprint: Option<[u8; 32]>) -> Result<()> {
        require_confirmed_reaps()?;
        #[cfg(not(any(unix, windows)))]
        return Err(rejected());
        #[cfg(any(unix, windows))]
        {
            if self
                .binding
                .as_ref()
                .is_some_and(|binding| !binding.active.load(Ordering::Acquire))
            {
                return Err(rejected());
            }
            self.verify_directory()?;
            let source = noland_snapshot::SourcePath::child(&self.directory, "rclone.conf".into())?;
            let mut file = source.open_regular()?;
            crate::native_fs::verify_private_file(&file)?;
            let before = crate::native_fs::FileState::read(&file)?;
            if before.len() > MAX_CONFIG as u64 {
                return Err(rejected());
            }
            let mut bytes = Zeroizing::new(Vec::new());
            (&mut file)
                .take(MAX_CONFIG as u64 + 1)
                .read_to_end(&mut bytes)?;
            if bytes.len() > MAX_CONFIG
                || !before.same_file(&file)?
                || !before.same_file(&source.open_regular()?)?
            {
                return Err(rejected());
            }
            // A stable, checked read is enough for the native CAS. Do not hold
            // Windows' no-write/no-delete config reader across native vault IO.
            drop(file);
            let text = std::str::from_utf8(&bytes).map_err(|_| rejected())?;
            let current = ConfigDocument::parse(text, &self.remote)?;
            if !current.invariants_match(&self.expected) {
                return Err(rejected());
            }
            let mut token = current.tokens()?;
            let mut prior = self.last_token.lock().map_err(|_| rejected())?;
            if let Some(original) = &self.recovery_original_token {
                let expected = prior.as_ref().ok_or_else(rejected)?;
                let current = token.as_ref().ok_or_else(rejected)?;
                // Validate the SAME stable read used for the CAS, not an earlier
                // path read that could be swapped before finalization.
                if !original.same_tokens(expected)? && !current.same_tokens(expected)? {
                    return Err(rejected());
                }
            }
            match (&mut token, &*prior, &self.binding) {
                (Some(token), Some(old), Some(binding)) => {
                    // OAuth servers may omit refresh_token on subsequent refresh.
                    if token.refresh_token.is_none() {
                        token.refresh_token = old.refresh_token.clone();
                    }
                    if !token.same_tokens(old)? {
                        let rotation = NativeCredentialRotation {
                            operation_id: binding.operation_id.clone(),
                            provider: binding.provider.clone(),
                            remote_name: binding.remote.clone(),
                            root: binding.root.clone(),
                            access_token: token.access_token.clone(),
                            refresh_token: token.refresh_token.clone(),
                            expires_at_unix: token.expires_at()?,
                            expected_token_fingerprint: expected_fingerprint
                                .unwrap_or(old.fingerprint()?),
                            token_fingerprint: token.fingerprint()?,
                        };
                        std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                            (binding.sink)(&rotation)
                        }))
                        .map_err(|_| rejected())?
                        .map_err(|_| rejected())?;
                        *binding.latest_token.lock().map_err(|_| rejected())? = token.clone();
                    }
                }
                (None, None, None) => {}
                _ => return Err(rejected()),
            }
            *prior = token;
            Ok(())
        }
    }

    #[cfg(any(unix, windows))]
    fn verify_directory(&self) -> Result<()> {
        crate::native_fs::verify_directory(
            &self.source,
            &self.directory,
            self.path.parent().ok_or_else(rejected)?,
        )
    }

    pub(crate) async fn attempt(self: &Arc<Self>) -> Result<NativeCredentialAttempt> {
        self.start_attempt(false)
    }

    pub(crate) async fn publication_attempt(self: &Arc<Self>) -> Result<NativeCredentialAttempt> {
        self.start_attempt(true)
    }

    fn start_attempt(self: &Arc<Self>, publication: bool) -> Result<NativeCredentialAttempt> {
        require_confirmed_reaps()?;
        // Serialize only short command admission/checkpoint IO, never transfers.
        let _admission = self.admission.lock().map_err(|_| rejected())?;
        if self.closed.load(Ordering::Acquire) || self.publication_active.load(Ordering::Acquire) {
            return Err(rejected());
        }
        self.checkpoint()?;
        if let Some(binding) = &self.binding {
            let latest = binding
                .latest_token
                .lock()
                .map_err(|_| rejected())?
                .fingerprint()?;
            let own = self
                .last_token
                .lock()
                .map_err(|_| rejected())?
                .as_ref()
                .ok_or_else(rejected)?
                .fingerprint()?;
            if own != latest {
                if self.active_attempts.load(Ordering::Acquire) != 0 {
                    return Err(rejected());
                }
                #[cfg(any(unix, windows))]
                self.initialize_from_native_cache()?;
            }
        }
        let expected_fingerprint = self
            .last_token
            .lock()
            .map_err(|_| rejected())?
            .as_ref()
            .map(TokenSnapshot::fingerprint)
            .transpose()?;
        let publication = publication && self.binding.is_some();
        if publication {
            if self.active_attempts.load(Ordering::Acquire) != 0 {
                return Err(rejected());
            }
            // COMMITTED/LATEST use an already-CAS-committed access token. The
            // same config temporarily omits refresh capability, so this short
            // visibility helper cannot rotate credentials after publication.
            // Ordinary pack/batch transfer groups remain adaptive and parallel.
            #[cfg(any(unix, windows))]
            self.write_native_cached_config(true)?;
            self.publication_active.store(true, Ordering::Release);
        }
        self.active_attempts.fetch_add(1, Ordering::AcqRel);
        Ok(NativeCredentialAttempt {
            handoff: Arc::clone(self),
            expected_fingerprint,
            publication,
            checked: false,
        })
    }
}

/// Declare before the subprocess so cancellation drops/reaps the child first.
pub(crate) struct NativeCredentialAttempt {
    handoff: Arc<NativeConfigHandoff>,
    expected_fingerprint: Option<[u8; 32]>,
    publication: bool,
    checked: bool,
}
impl NativeCredentialAttempt {
    pub(crate) fn config_handoff(&self) -> Arc<NativeConfigHandoff> {
        Arc::clone(&self.handoff)
    }

    pub(crate) fn finish(mut self) -> Result<()> {
        self.checked = true;
        let result = self.handoff.checkpoint_expected(self.expected_fingerprint);
        if self.publication && result.is_ok() {
            #[cfg(any(unix, windows))]
            if self.handoff.write_native_cached_config(false).is_err() {
                self.handoff.failed.store(true, Ordering::Release);
                if let Some(binding) = &self.handoff.binding {
                    binding.failed.store(true, Ordering::Release);
                }
                return Err(rejected());
            }
        }
        result
    }
}
impl Drop for NativeCredentialAttempt {
    fn drop(&mut self) {
        if !self.checked {
            let checked = self.handoff.checkpoint_expected(self.expected_fingerprint);
            if self.publication && checked.is_ok() {
                #[cfg(any(unix, windows))]
                if self.handoff.write_native_cached_config(false).is_err() {
                    self.handoff.failed.store(true, Ordering::Release);
                    if let Some(binding) = &self.handoff.binding {
                        binding.failed.store(true, Ordering::Release);
                    }
                }
            }
        }
        if self.publication {
            self.handoff
                .publication_active
                .store(false, Ordering::Release);
        }
        self.handoff.active_attempts.fetch_sub(1, Ordering::AcqRel);
    }
}

#[cfg(test)]
mod codec_tests {
    use super::*;
    #[test]
    fn public_rclone_obscure_vectors_are_decoded_without_exposing_a_repository_key() {
        assert_eq!(
            &reveal_rclone_obscured("YWFhYWFhYWFhYWFhYWFhYXMaGgIlEQ").unwrap()[..],
            b"potato"
        );
        assert!(reveal_rclone_obscured("not-an-obscure-value").is_err());
    }
}
