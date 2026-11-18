// SPDX-License-Identifier: GPL-3.0-only
use anyhow::{ensure, Context, Result};
use quicksave_integrations::{profiles::ProductIdentity, AppIdentity};
use quicksave_platform::{FileStamp, RootIdentity, SafeRoot};
use serde::Serialize;
use std::{
    collections::{BTreeMap, BTreeSet},
    path::{Component, Path, PathBuf},
    sync::Arc,
};

use crate::{stable_app_id, NativeFileIdentity, ObservationLimits};

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ObservationRootKind {
    Executable,
    Data,
    /// Explicit approval for installation metadata includes executable images
    /// and observed data leaves within the same exact pinned root.
    Installation,
}

impl ObservationRootKind {
    pub(crate) fn allows(self, requested: Self) -> bool {
        self == requested || self == Self::Installation
    }
}

#[derive(Clone, Debug, Serialize)]
pub struct RootSpec {
    pub id: String,
    pub path: PathBuf,
    pub identity: RootIdentity,
    pub kind: ObservationRootKind,
    /// Exact native-approved leaves. None permits metadata for all safe leaves
    /// under this observation root, never broader tracking or backup authority.
    pub allowed_files: Option<BTreeSet<String>>,
}

#[derive(Clone, Debug, Serialize)]
pub struct ApplicationSpec {
    pub identity: AppIdentity,
    pub executable: PathBuf,
    pub executable_stamp: FileStamp,
}

/// Exact backend-owned identity from an actual materialized Tracker bundle.
/// app_id is the record's appId (possibly installation-specific); source_app_id
/// is integrations' sourceIdentity.app_id. Neither is a display-name heuristic.
#[derive(Clone, Debug, Serialize)]
pub struct NativeApplicationSpec {
    pub app_id: String,
    pub source_app_id: String,
    pub executable: PathBuf,
    pub executable_stamp: FileStamp,
    pub root_ids: BTreeSet<String>,
    pub mac_bundle: Option<MacBundleBinding>,
}

#[derive(Clone, Debug, Serialize)]
pub struct MacBundleBinding {
    pub identifier: String,
    pub path: PathBuf,
}

#[derive(Clone, Debug, Serialize)]
pub struct ScopeRequest {
    pub id: String,
    pub roots: Vec<RootSpec>,
    pub applications: Vec<ApplicationSpec>,
    pub native_applications: Vec<NativeApplicationSpec>,
    /// Exact sensitive directories/files excluded before native metadata opens.
    pub excluded_paths: Vec<PathBuf>,
    /// Native marker/key identities supplied by the service's already-pinned
    /// handles. This also rejects aliases under an innocuous approved filename.
    pub excluded_native_files: Vec<NativeFileIdentity>,
    /// Explicit process-account scope, not a wildcard or a guessed HOME.
    pub uid: u32,
}

impl ScopeRequest {
    /// Streaming digest of this exact metadata-only request, suitable for a
    /// compact native MAC purpose without serializing a huge request to a vault.
    pub fn fingerprint(&self) -> Result<String> {
        let mut hash = ScopeHash {
            hasher: blake3::Hasher::new(),
            bytes: 0,
        };
        serde_json::to_writer(&mut hash, self)?;
        Ok(hash.hasher.finalize().to_hex().to_string())
    }

    pub fn new(
        id: impl Into<String>,
        uid: u32,
        roots: Vec<RootSpec>,
        applications: Vec<ApplicationSpec>,
    ) -> Self {
        Self {
            id: id.into(),
            uid,
            roots,
            applications,
            native_applications: Vec::new(),
            excluded_paths: Vec::new(),
            excluded_native_files: Vec::new(),
        }
    }

    /// Adds exactly the supplied native-owned root. Never unions allowlists or
    /// promotes Some(leaves) into a whole-parent grant. No filesystem I/O.
    pub fn add_exact_root(&mut self, root: RootSpec) -> Result<()> {
        valid_id(&root.id)?;
        validate_absolute(&root.path)?;
        if let Some(existing) = self.roots.iter().find(|old| old.id == root.id) {
            ensure!(
                same_root_spec(existing, &root),
                "observation root ID changed or widened"
            );
            return Ok(());
        }
        ensure!(self.roots.len() < 4096, "too many exact observation roots");
        self.roots.push(root);
        Ok(())
    }

    pub fn add_native_application(&mut self, application: NativeApplicationSpec) -> Result<()> {
        validate_native_application(&application)?;
        ensure!(
            self.applications.len() + self.native_applications.len() < 4096,
            "too many observed applications"
        );
        ensure!(
            !self
                .applications
                .iter()
                .any(|old| old.executable == application.executable)
                && !self
                    .native_applications
                    .iter()
                    .any(|old| old.executable == application.executable),
            "ambiguous native executable-to-app binding"
        );
        ensure!(
            !self
                .native_applications
                .iter()
                .any(|old| old.app_id == application.app_id)
                && !self.applications.iter().any(
                    |old| stable_app_id(&old.identity).is_ok_and(|id| id == application.app_id)
                ),
            "ambiguous native application ID"
        );
        ensure!(
            application
                .root_ids
                .iter()
                .all(|id| self.roots.iter().any(|root| &root.id == id)),
            "native application references an unapproved observation root"
        );
        self.native_applications.push(application);
        Ok(())
    }
}

/// The service must verify an authenticated, native-consented grant over the
/// ENTIRE request. A webview checkbox/string/JSON boolean is not a verifier.
pub trait ScopeConsent: Send + Sync + 'static {
    fn verify(&self, request: &ScopeRequest) -> Result<bool>;
}

impl<F: Fn(&ScopeRequest) -> Result<bool> + Send + Sync + 'static> ScopeConsent for F {
    fn verify(&self, request: &ScopeRequest) -> Result<bool> {
        self(request)
    }
}

pub(crate) struct PinnedRoot {
    pub spec: RootSpec,
    pub handle: Arc<SafeRoot>,
}

#[derive(Clone, Copy)]
enum RegisteredApplication {
    Integration(usize),
    Tracker(usize),
}

/// Pinned, immutable metadata-only observation authority. It is not serializable
/// or deserializable and cannot be expanded by an observed path.
pub struct ObservationScope {
    pub(crate) request: ScopeRequest,
    pub(crate) roots: BTreeMap<String, PinnedRoot>,
    consent: Arc<dyn ScopeConsent>,
    fingerprint: String,
    app_roots: BTreeMap<String, BTreeSet<String>>,
    tree_routes: BTreeMap<PathBuf, Vec<String>>,
    leaf_routes: BTreeMap<PathBuf, Vec<String>>,
    registered: BTreeMap<PathBuf, RegisteredApplication>,
}

impl ObservationScope {
    pub fn approve(request: ScopeRequest, consent: Arc<dyn ScopeConsent>) -> Result<Self> {
        Self::approve_with_limits(request, consent, &ObservationLimits::default())
    }

    pub fn approve_with_limits(
        request: ScopeRequest,
        consent: Arc<dyn ScopeConsent>,
        limits: &ObservationLimits,
    ) -> Result<Self> {
        limits.validate()?;
        valid_id(&request.id)?;
        ensure!(
            !request.roots.is_empty()
                && request.roots.len() <= limits.max_roots
                && request.applications.len() + request.native_applications.len()
                    <= limits.max_applications
                && request.excluded_paths.len() <= 256
                && request.excluded_native_files.len() <= 256,
            "observation scope exceeds the bound"
        );
        // Reject malformed/secret targets BEFORE requesting native metadata.
        for path in &request.excluded_paths {
            validate_absolute(path)?;
        }
        let mut ids = BTreeSet::new();
        let mut native_paths = BTreeMap::new();
        let mut path_bytes = 0_usize;
        let mut leaves = 0_usize;
        for root in &request.roots {
            valid_id(&root.id)?;
            ensure!(ids.insert(root.id.clone()), "duplicate observation root ID");
            if let Some(previous) = native_paths.insert(
                (root.identity.device, root.identity.file_id),
                root.path.as_path(),
            ) {
                ensure!(
                    previous == root.path.as_path(),
                    "native root aliases another observation path"
                );
            }
            validate_absolute(&root.path)?;
            path_bytes = path_bytes
                .checked_add(root.path.as_os_str().len())
                .context("scope size overflow")?;
            ensure!(
                !private_path(&root.path),
                "private observation root is excluded"
            );
            ensure!(
                !request
                    .excluded_paths
                    .iter()
                    .any(|path| root.path.starts_with(path)),
                "observation root is explicitly excluded"
            );
            if let Some(files) = &root.allowed_files {
                ensure!(
                    !files.is_empty() && files.len() <= 4096,
                    "invalid exact-file scope"
                );
                for file in files {
                    leaves += 1;
                    path_bytes = path_bytes
                        .checked_add(file.len())
                        .context("scope size overflow")?;
                    ensure!(
                        leaves <= 16384 && path_bytes <= 16 * 1024 * 1024,
                        "observation scope exceeds the path budget"
                    );
                    validate_relative(file)?;
                    ensure!(
                        !private_path(Path::new(file)),
                        "private observation leaf is excluded"
                    );
                }
            }
        }
        ensure!(
            path_bytes <= 16 * 1024 * 1024,
            "observation scope exceeds the path budget"
        );
        drop(native_paths);
        let mut registered = BTreeMap::new();
        let mut app_ids = BTreeSet::new();
        for (index, app) in request.applications.iter().enumerate() {
            ensure!(
                registered
                    .insert(
                        app.executable.clone(),
                        RegisteredApplication::Integration(index)
                    )
                    .is_none(),
                "ambiguous application executable"
            );
            ensure!(
                app_ids.insert(stable_app_id(&app.identity)?),
                "ambiguous application ID"
            );
            validate_absolute(&app.executable)?;
            validate_absolute(&app.identity.install.metadata_path)?;
            if let Some(location) = &app.identity.install.location {
                validate_absolute(location)?;
            }
            ensure!(
                !private_path(&app.executable),
                "private executable path is excluded"
            );
        }
        for (index, app) in request.native_applications.iter().enumerate() {
            validate_native_application(app)?;
            ensure!(
                registered
                    .insert(
                        app.executable.clone(),
                        RegisteredApplication::Tracker(index)
                    )
                    .is_none(),
                "ambiguous native application executable"
            );
            ensure!(
                app_ids.insert(app.app_id.clone()),
                "ambiguous native application ID"
            );
            ensure!(
                app.root_ids.iter().all(|id| ids.contains(id)),
                "native app has an unknown root ID"
            );
        }
        ensure!(
            consent.verify(&request)?,
            "native observation consent is invalid or revoked"
        );
        // Streaming hash avoids constructing another giant JSON scope buffer.
        let fingerprint = request.fingerprint()?;
        let mut roots = BTreeMap::new();
        let mut handles: BTreeMap<(u64, [u64; 2], PathBuf), Arc<SafeRoot>> = BTreeMap::new();
        let mut tree_routes: BTreeMap<PathBuf, Vec<String>> = BTreeMap::new();
        let mut leaf_routes: BTreeMap<PathBuf, Vec<String>> = BTreeMap::new();
        for spec in &request.roots {
            let key = (
                spec.identity.device,
                spec.identity.file_id,
                spec.path.clone(),
            );
            let handle = if let Some(handle) = handles.get(&key) {
                handle.clone()
            } else {
                let handle = Arc::new(SafeRoot::open(&spec.path)?);
                handles.insert(key, handle.clone());
                handle
            };
            ensure!(
                handle.identity()? == spec.identity,
                "approved observation root identity changed"
            );
            roots.insert(
                spec.id.clone(),
                PinnedRoot {
                    spec: spec.clone(),
                    handle,
                },
            );
            if let Some(leaves) = &spec.allowed_files {
                for leaf in leaves {
                    leaf_routes
                        .entry(spec.path.join(leaf))
                        .or_default()
                        .push(spec.id.clone());
                }
            } else {
                tree_routes
                    .entry(spec.path.clone())
                    .or_default()
                    .push(spec.id.clone());
            }
        }
        let mut app_roots: BTreeMap<String, BTreeSet<String>> = BTreeMap::new();
        for app in &request.native_applications {
            app_roots
                .entry(app.app_id.clone())
                .or_default()
                .extend(app.root_ids.iter().cloned());
        }
        let scope = Self {
            request,
            roots,
            consent,
            fingerprint,
            app_roots,
            tree_routes,
            leaf_routes,
            registered,
        };
        for app in &scope.request.applications {
            let (_, _, stamp) = scope.stamp(&app.executable, ObservationRootKind::Executable)?;
            ensure!(
                stamp == app.executable_stamp,
                "approved executable identity changed"
            );
        }
        for app in &scope.request.native_applications {
            let (_, _, stamp) = scope.stamp_for_app(
                &app.executable,
                ObservationRootKind::Executable,
                Some(&app.app_id),
            )?;
            ensure!(
                stamp == app.executable_stamp,
                "approved native executable changed"
            );
        }
        scope.check()?;
        Ok(scope)
    }

    pub fn id(&self) -> &str {
        &self.request.id
    }
    pub fn uid(&self) -> u32 {
        self.request.uid
    }
    pub fn fingerprint(&self) -> &str {
        &self.fingerprint
    }
    pub fn context(&self) -> crate::integration::ObservationContext {
        crate::integration::ObservationContext {
            fingerprint: self.fingerprint.clone(),
            uid: self.uid(),
        }
    }
    pub fn applications(&self) -> &[ApplicationSpec] {
        &self.request.applications
    }
    pub fn native_applications(&self) -> &[NativeApplicationSpec] {
        &self.request.native_applications
    }
    pub fn application_ids(&self) -> Result<BTreeSet<String>> {
        let mut ids = self
            .applications()
            .iter()
            .map(|app| stable_app_id(&app.identity))
            .collect::<Result<BTreeSet<_>>>()?;
        ids.extend(
            self.native_applications()
                .iter()
                .map(|app| app.app_id.clone()),
        );
        Ok(ids)
    }
    pub(crate) fn has_registered_executable(&self, executable: &Path) -> bool {
        self.registered.contains_key(executable)
    }
    pub(crate) fn application(&self, executable: &Path) -> Option<&ApplicationSpec> {
        match self.registered.get(executable)? {
            RegisteredApplication::Integration(index) => self.applications().get(*index),
            RegisteredApplication::Tracker(_) => None,
        }
    }
    pub(crate) fn native_application(&self, executable: &Path) -> Option<&NativeApplicationSpec> {
        match self.registered.get(executable)? {
            RegisteredApplication::Tracker(index) => self.native_applications().get(*index),
            RegisteredApplication::Integration(_) => None,
        }
    }
    pub(crate) fn registered_stamp_changed(&self, executable: &Path, stamp: &FileStamp) -> bool {
        self.application(executable)
            .is_some_and(|app| &app.executable_stamp != stamp)
            || self
                .native_application(executable)
                .is_some_and(|app| &app.executable_stamp != stamp)
    }
    pub fn roots(&self) -> impl Iterator<Item = &RootSpec> {
        self.roots.values().map(|root| &root.spec)
    }

    pub(crate) fn check(&self) -> Result<()> {
        self.authorized()?;
        self.check_roots()
    }

    pub(crate) fn check_roots(&self) -> Result<()> {
        for root in self.roots.values() {
            ensure!(
                root.handle.identity()? == root.spec.identity,
                "observation root identity changed"
            );
        }
        Ok(())
    }

    /// Pure filtering first. Never stat/canonicalize an outside candidate.
    pub(crate) fn locate(
        &self,
        path: &Path,
        kind: ObservationRootKind,
    ) -> Option<(&PinnedRoot, String)> {
        self.locate_for_app(path, kind, None)
    }

    pub(crate) fn locate_for_app(
        &self,
        path: &Path,
        kind: ObservationRootKind,
        app_id: Option<&str>,
    ) -> Option<(&PinnedRoot, String)> {
        if validate_absolute(path).is_err()
            || private_path(path)
            || self
                .request
                .excluded_paths
                .iter()
                .any(|excluded| path.starts_with(excluded))
        {
            return None;
        }
        let leaves = self.leaf_routes.get(path).into_iter().flatten();
        let trees = path
            .ancestors()
            .skip(1)
            .filter_map(|ancestor| self.tree_routes.get(ancestor))
            .flatten();
        leaves
            .chain(trees)
            .filter_map(|id| self.roots.get(id))
            .filter(|root| root.spec.kind.allows(kind))
            .filter(|root| {
                app_id
                    .and_then(|id| self.app_roots.get(id))
                    .is_none_or(|ids| ids.contains(&root.spec.id))
            })
            .filter_map(|root| {
                let relative = portable_relative(path.strip_prefix(&root.spec.path).ok()?)?;
                if validate_relative(&relative).is_err()
                    || root
                        .spec
                        .allowed_files
                        .as_ref()
                        .is_some_and(|files| !files.contains(&relative))
                {
                    return None;
                }
                Some((root, relative))
            })
            .max_by_key(|(root, _)| root.spec.path.as_os_str().len())
    }

    pub(crate) fn stamp(
        &self,
        path: &Path,
        kind: ObservationRootKind,
    ) -> Result<(String, String, FileStamp)> {
        self.stamp_for_app(path, kind, None)
    }

    pub(crate) fn stamp_for_app(
        &self,
        path: &Path,
        kind: ObservationRootKind,
        app_id: Option<&str>,
    ) -> Result<(String, String, FileStamp)> {
        let (root, relative) = self
            .locate_for_app(path, kind, app_id)
            .context("candidate is outside native observation scope")?;
        // The bounded poll/approval is consent-bracketed. Do not perform a
        // vault/config verification per open FD; final admission rechecks it.
        ensure!(
            root.handle.identity()? == root.spec.identity,
            "observation root identity changed"
        );
        // SafeRoot::read_file OPENS a no-follow native handle and returns fstat;
        // no Read call and no payload byte are requested by the observer.
        let (_metadata_handle, stamp) = root.handle.read_file(&relative)?;
        ensure!(
            !self
                .request
                .excluded_native_files
                .contains(&NativeFileIdentity::from(&stamp)),
            "native root marker or private key identity is excluded"
        );
        ensure!(
            root.handle.identity()? == root.spec.identity,
            "observation root changed during metadata inspection"
        );
        Ok((root.spec.id.clone(), relative, stamp))
    }

    pub(crate) fn resolve_app(
        &self,
        executable: &Path,
        stamp: &FileStamp,
        bundle: Option<&str>,
    ) -> Result<Option<String>> {
        if let Some(app) = self.application(executable) {
            ensure!(
                &app.executable_stamp == stamp,
                "registered executable identity changed"
            );
            if let ProductIdentity::MacBundleIdentifier(expected) = &app.identity.product {
                ensure!(
                    bundle == Some(expected.as_str()),
                    "native bundle identifier is unverified"
                );
            }
            return Ok(Some(stable_app_id(&app.identity)?));
        }
        if let Some(app) = self.native_application(executable) {
            ensure!(
                &app.executable_stamp == stamp,
                "registered native executable changed"
            );
            if let Some(expected) = &app.mac_bundle {
                ensure!(
                    bundle == Some(expected.identifier.as_str()),
                    "native bundle identifier is unverified"
                );
            }
            ensure!(
                self.locate_for_app(
                    executable,
                    ObservationRootKind::Executable,
                    Some(&app.app_id)
                )
                .is_some(),
                "native executable is outside this app's exact roots"
            );
            return Ok(Some(app.app_id.clone()));
        }
        Ok(None)
    }

    pub(crate) fn authorized(&self) -> Result<()> {
        ensure!(
            self.consent.verify(&self.request).unwrap_or(false),
            "native observation consent is invalid or revoked"
        );
        Ok(())
    }

    /// Only touched roots are revalidated during a poll. Inactive applications
    /// do not cause a 4096-root filesystem audit every two seconds. All roots
    /// were pinned at approval, and every actual file metadata open rechecks
    /// its own root before/after; this final fence catches a later remount.
    pub(crate) fn verify_evidence_roots(&self, batch: &crate::EvidenceBatch) -> Result<()> {
        let mut ids = BTreeSet::new();
        for proof in &batch.processes {
            let (root, _) = self
                .locate_for_app(
                    proof.executable(),
                    ObservationRootKind::Executable,
                    Some(proof.app_id()),
                )
                .context("observed executable lost its exact native root")?;
            ids.insert(root.spec.id.as_str());
        }
        ids.extend(batch.files.iter().map(|file| file.root_id()));
        let mut checked = BTreeSet::new();
        for id in ids {
            let root = self
                .roots
                .get(id)
                .context("evidence references an unknown root")?;
            if !checked.insert((
                root.spec.identity.device,
                root.spec.identity.file_id,
                root.spec.path.as_path(),
            )) {
                continue;
            }
            ensure!(
                root.handle.identity()? == root.spec.identity,
                "touched observation root changed"
            );
        }
        Ok(())
    }
}

pub(crate) fn same_root_spec(a: &RootSpec, b: &RootSpec) -> bool {
    a.id == b.id
        && a.path == b.path
        && a.identity == b.identity
        && a.kind == b.kind
        && a.allowed_files == b.allowed_files
}

fn validate_native_application(app: &NativeApplicationSpec) -> Result<()> {
    valid_id(&app.app_id)?;
    valid_id(&app.source_app_id)?;
    ensure!(
        !app.app_id.starts_with("quicksave.observed:")
            && !app.source_app_id.starts_with("quicksave.observed:"),
        "unknown observed identities are diagnostics, not native registrations"
    );
    validate_absolute(&app.executable)?;
    ensure!(
        !private_path(&app.executable),
        "private native executable is excluded"
    );
    ensure!(
        !app.root_ids.is_empty() && app.root_ids.len() <= 64,
        "invalid native app root binding"
    );
    for id in &app.root_ids {
        valid_id(id)?;
    }
    if let Some(bundle) = &app.mac_bundle {
        valid_id(&bundle.identifier)?;
        ensure!(
            app.source_app_id == format!("mac-bundle:{}", bundle.identifier),
            "native bundle identifier differs from sourceIdentity.app_id"
        );
        validate_absolute(&bundle.path)?;
        ensure!(
            app.executable
                .starts_with(bundle.path.join("Contents/MacOS")),
            "native executable is outside the exact bundle metadata binding"
        );
    } else {
        ensure!(
            !app.source_app_id.starts_with("mac-bundle:"),
            "Mac source identity requires native bundle verification"
        );
    }
    Ok(())
}

struct ScopeHash {
    hasher: blake3::Hasher,
    bytes: usize,
}
impl std::io::Write for ScopeHash {
    fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
        self.bytes = self
            .bytes
            .checked_add(bytes.len())
            .filter(|count| *count <= 64 * 1024 * 1024)
            .ok_or_else(|| {
                std::io::Error::new(
                    std::io::ErrorKind::InvalidInput,
                    "observation scope byte bound exceeded",
                )
            })?;
        self.hasher.update(bytes);
        Ok(bytes.len())
    }
    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

pub(crate) fn valid_id(value: &str) -> Result<()> {
    ensure!(
        !value.is_empty() && value.len() <= 512 && !value.chars().any(char::is_control),
        "invalid observation ID"
    );
    Ok(())
}

pub(crate) fn validate_absolute(path: &Path) -> Result<()> {
    let text = path.to_str().context("observation path must be UTF-8")?;
    ensure!(
        path.is_absolute() && text.len() <= 4096 && !text.contains('\0'),
        "invalid observation path"
    );
    #[cfg(not(windows))]
    ensure!(
        !text.contains('\\'),
        "backslash is not an observation path separator"
    );
    ensure!(
        !text
            .split(['/', '\\'])
            .any(|part| part == "." || part == ".."),
        "observation path traversal is forbidden"
    );
    ensure!(
        path.components().count() <= 128,
        "observation path depth exceeded"
    );
    Ok(())
}

pub(crate) fn validate_relative(path: &str) -> Result<()> {
    ensure!(
        !path.is_empty()
            && path.len() <= 4096
            && !path.starts_with('/')
            && !path.contains(['\0', '\\', ':']),
        "invalid relative observation path"
    );
    ensure!(
        path.split('/').count() <= 128,
        "relative observation depth exceeded"
    );
    for part in path.split('/') {
        ensure!(
            !part.is_empty()
                && part != "."
                && part != ".."
                && part.len() <= 255
                && !part.chars().any(char::is_control),
            "unsafe observation component"
        );
    }
    Ok(())
}

pub(crate) fn private_path(path: &Path) -> bool {
    path.components().any(|part| {
        let Component::Normal(part) = part else {
            return false;
        };
        let Some(part) = part.to_str() else {
            return true;
        };
        let lower = part.to_ascii_lowercase();
        matches!(
            lower.as_str(),
            ".ssh"
                | ".gnupg"
                | ".aws"
                | ".azure"
                | ".git"
                | ".env"
                | "keychains"
                | "credentials"
                | "credentials.json"
                | "id_rsa"
                | "id_ed25519"
                | "id_ecdsa"
                | "id_dsa"
                | "rootnativemarker"
                | ".quicksave-root"
                | ".quicksave-root-marker"
                | ".noland"
                | "noland"
                | "no land"
                | "no land.app"
                | "noland-runtime"
                | "noland-state"
                | "noland.app"
                | "com.noland.connect"
                | "recovery.key"
                | "master.key"
        ) || lower.ends_with(".key")
            || lower.ends_with(".pem")
            || lower.ends_with(".p12")
            || lower.ends_with(".pfx")
            || lower.ends_with(".p8")
            || lower.ends_with(".keychain-db")
    })
}

pub(crate) fn portable_relative(path: &Path) -> Option<String> {
    let text = path.to_str()?;
    #[cfg(windows)]
    return Some(text.replace('\\', "/"));
    #[cfg(not(windows))]
    Some(text.to_owned())
}
