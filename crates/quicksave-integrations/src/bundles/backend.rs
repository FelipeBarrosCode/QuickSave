// SPDX-License-Identifier: GPL-3.0-only
//! Trusted read-only metadata adapter. Never implement this from untrusted JSON.
//! Native root grants must still re-open and compare the reported identities.

use super::RootClassification;
use crate::profiles::{Platform, ProfilePath};
use anyhow::{bail, ensure, Context, Result};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum BackendKind {
    NativeReadOnly,
    NativeApprovedBases,
    IsolatedFixture,
    ExplicitPortableAdapter,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum NativeNodeKind {
    Directory,
    RegularFile,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize)]
#[serde(tag = "platform", rename_all = "snake_case")]
pub enum NativeIdentity {
    Unix {
        device: u64,
        inode: u64,
        kind: NativeNodeKind,
    },
    /// Only a real native Windows adapter may issue this variant. Portable
    /// fixtures on Unix deliberately retain Unix IDs, not invented Windows IDs.
    Windows {
        volume_serial: u64,
        file_id: [u8; 16],
        kind: NativeNodeKind,
    },
}

impl NativeIdentity {
    pub fn kind(&self) -> NativeNodeKind {
        match self {
            Self::Unix { kind, .. } | Self::Windows { kind, .. } => *kind,
        }
    }

    pub(crate) fn stable_key(&self) -> String {
        match self {
            Self::Unix {
                device,
                inode,
                kind,
            } => format!("unix:{device}:{inode}:{kind:?}"),
            Self::Windows {
                volume_serial,
                file_id,
                kind,
            } => {
                let hex: String = file_id.iter().map(|value| format!("{value:02x}")).collect();
                format!("windows:{volume_serial}:{hex}:{kind:?}")
            }
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NativeNode {
    pub identity: NativeIdentity,
    pub byte_length: u64,
    pub executable: bool,
    /// Real fstat size/mtime/ctime/mode observation, not an integrity hash or a
    /// substitute for the engine's consent-backed file index.
    pub change_token: String,
}

#[derive(Debug, Clone)]
pub struct MetadataDocument {
    pub bytes: Vec<u8>,
    pub native_identity: NativeIdentity,
}

#[derive(Debug)]
pub struct DirectoryEntries {
    pub names: Vec<String>,
    pub truncated: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MacSigningEvidence {
    /// None means an unsigned/unverifiable installation, never a verified empty
    /// entitlement set. Identifier must exactly match CFBundleIdentifier.
    pub signing_identifier: Option<String>,
    pub application_groups: Vec<String>,
    pub signature_validated: bool,
}

impl MacSigningEvidence {
    pub fn unavailable() -> Self {
        Self {
            signing_identifier: None,
            application_groups: Vec::new(),
            signature_validated: false,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum WindowsKnownFolder {
    LocalAppData,
    RoamingAppData,
    LocalAppDataLow,
    SavedGames,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum WindowsProductIdentity {
    PackageFamily {
        family_name: String,
    },
    /// Exact native registry address, not DisplayName or Publisher matching.
    UninstallRegistry {
        hive: String,
        key: String,
    },
}

impl WindowsProductIdentity {
    pub fn stable_key(&self) -> Result<String> {
        match self {
            Self::PackageFamily { family_name } => {
                let (name, publisher) = family_name
                    .rsplit_once('_')
                    .context("Windows package family lacks publisher identity")?;
                ensure!(
                    (3..=50).contains(&name.len())
                        && name
                            .bytes()
                            .all(|b| b.is_ascii_alphanumeric() || b".-".contains(&b))
                        && publisher.len() == 13
                        && publisher
                            .bytes()
                            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit()),
                    "invalid Windows package family identity"
                );
                Ok(format!("windows-package:{family_name}"))
            }
            Self::UninstallRegistry { hive, key } => {
                ensure!(
                    matches!(hive.as_str(), "HKEY_CURRENT_USER" | "HKEY_LOCAL_MACHINE"),
                    "invalid registry hive"
                );
                let normalized = key.to_ascii_lowercase();
                let leaf = [
                    "software\\microsoft\\windows\\currentversion\\uninstall\\",
                    "software\\wow6432node\\microsoft\\windows\\currentversion\\uninstall\\",
                ]
                .into_iter()
                .find_map(|prefix| normalized.strip_prefix(prefix));
                ensure!(
                    key.len() <= 2048
                        && leaf.is_some_and(|leaf| !leaf.is_empty()
                            && leaf.len() <= 255
                            && !leaf.contains('\\'))
                        && !key.chars().any(char::is_control)
                        && !key
                            .split('\\')
                            .any(|part| part.is_empty() || part == "." || part == ".."),
                    "invalid native uninstall registry address"
                );
                Ok(format!("windows-registry:{hive}:{normalized}"))
            }
        }
    }
}

#[derive(Debug, Clone)]
pub struct WindowsReviewedMapping {
    /// Must equal WindowsProductIdentity::stable_key, not a title or username.
    pub exact_owner_id: String,
    pub known_folder: WindowsKnownFolder,
    pub relative_path: ProfilePath,
    pub classification: RootClassification,
    /// A reviewed portable profile is evidence, not a content/root grant.
    pub profile_id: String,
}

#[derive(Debug, Clone)]
pub struct WindowsInstallation {
    pub identity: WindowsProductIdentity,
    pub display_name: String,
    pub installation_path: Option<PathBuf>,
    pub executable_path: Option<PathBuf>,
    pub reviewed_mappings: Vec<WindowsReviewedMapping>,
}

/// Operations may inspect only bounded installation/platform metadata and root
/// identities. They must never read save/config contents, accounts or vaults.
/// `None` means confirmed missing; denial/unsafe/unsupported must return Err.
pub trait SoftwareBundleBackend {
    fn platform(&self) -> Platform;
    fn kind(&self) -> BackendKind;
    fn inspect_native(&mut self, path: &Path) -> Result<Option<NativeNode>>;
    fn list_directory(&mut self, path: &Path, maximum: usize) -> Result<Option<DirectoryEntries>>;
    fn read_metadata(&mut self, path: &Path, maximum: usize) -> Result<Option<MetadataDocument>>;
    fn mac_signing_evidence(&mut self, _bundle: &Path) -> Result<MacSigningEvidence> {
        Ok(MacSigningEvidence::unavailable())
    }
    fn windows_installations(&mut self, _maximum: usize) -> Result<Vec<WindowsInstallation>> {
        bail!("native Windows registry/package inventory adapter is not implemented")
    }
    /// A VDF may name a library, but cannot authorize it. Native policy backends
    /// must require a separate retained native capability for external roots.
    fn require_discovered_steam_library(&mut self, _library: &Path) -> Result<()> {
        bail!("this backend cannot confirm a discovered external Steam library")
    }
}

pub(crate) fn validate_path(path: &Path) -> Result<()> {
    let text = path.to_str().context("non-UTF8 inventory path")?;
    ensure!(
        path.is_absolute() && text.len() <= 4096 && !text.chars().any(char::is_control),
        "invalid absolute inventory path"
    );
    ensure!(
        !text
            .split(['/', '\\'])
            .any(|part| part == "." || part == ".."),
        "dot components are not permitted"
    );
    for component in path.components() {
        if let std::path::Component::Normal(name) = component {
            let name = name.to_str().context("non-UTF8 path component")?;
            ensure!(
                name.len() <= 255 && !name.contains('\\'),
                "invalid inventory path component"
            );
        }
    }
    Ok(())
}

#[cfg(any(target_os = "macos", target_os = "linux"))]
fn identity(metadata: &std::fs::Metadata) -> Result<NativeIdentity> {
    use std::os::unix::fs::MetadataExt;
    let kind = if metadata.is_dir() {
        NativeNodeKind::Directory
    } else {
        ensure!(metadata.is_file(), "unsupported native node type");
        NativeNodeKind::RegularFile
    };
    Ok(NativeIdentity::Unix {
        device: metadata.dev(),
        inode: metadata.ino(),
        kind,
    })
}

pub(crate) struct NativeFilesystemBackend;

#[cfg(any(target_os = "macos", target_os = "linux"))]
impl SoftwareBundleBackend for NativeFilesystemBackend {
    fn platform(&self) -> Platform {
        Platform::current()
    }
    fn kind(&self) -> BackendKind {
        BackendKind::NativeReadOnly
    }

    fn inspect_native(&mut self, path: &Path) -> Result<Option<NativeNode>> {
        use crate::reader::Directory;
        use std::os::unix::fs::MetadataExt;
        validate_path(path)?;
        let metadata = match Directory::open(path) {
            Ok(directory) => directory.metadata()?,
            Err(error) if is_missing(&error) => return Ok(None),
            Err(_) => {
                let parent = match Directory::open(path.parent().context("path has no parent")?) {
                    Ok(parent) => parent,
                    Err(error) if is_missing(&error) => return Ok(None),
                    Err(error) => return Err(error),
                };
                match parent.regular_file_metadata(
                    path.file_name()
                        .and_then(|s| s.to_str())
                        .context("invalid filename")?,
                ) {
                    Ok(metadata) => metadata,
                    Err(error) if is_missing(&error) => return Ok(None),
                    Err(error) => return Err(error),
                }
            }
        };
        Ok(Some(NativeNode {
            identity: identity(&metadata)?,
            byte_length: metadata.len(),
            executable: metadata.is_file() && metadata.mode() & 0o111 != 0,
            change_token: format!(
                "{}:{}:{}:{}:{}:{}",
                metadata.len(),
                metadata.mtime(),
                metadata.mtime_nsec(),
                metadata.ctime(),
                metadata.ctime_nsec(),
                metadata.mode()
            ),
        }))
    }

    fn list_directory(&mut self, path: &Path, maximum: usize) -> Result<Option<DirectoryEntries>> {
        validate_path(path)?;
        let directory = match crate::reader::Directory::open(path) {
            Ok(directory) => directory,
            Err(error) if is_missing(&error) => return Ok(None),
            Err(error) => return Err(error),
        };
        let entries = directory.entries(maximum)?;
        Ok(Some(DirectoryEntries {
            names: entries.names,
            truncated: entries.truncated,
        }))
    }

    fn read_metadata(&mut self, path: &Path, maximum: usize) -> Result<Option<MetadataDocument>> {
        validate_path(path)?;
        let parent = match crate::reader::Directory::open(
            path.parent().context("metadata has no parent")?,
        ) {
            Ok(parent) => parent,
            Err(error) if is_missing(&error) => return Ok(None),
            Err(error) => return Err(error),
        };
        match parent.read_file_with_metadata(
            path.file_name()
                .and_then(|s| s.to_str())
                .context("invalid metadata filename")?,
            maximum,
        ) {
            Ok((bytes, metadata)) => Ok(Some(MetadataDocument {
                bytes,
                native_identity: identity(&metadata)?,
            })),
            Err(error) if is_missing(&error) => Ok(None),
            Err(error) => Err(error),
        }
    }

    fn mac_signing_evidence(&mut self, bundle: &Path) -> Result<MacSigningEvidence> {
        #[cfg(target_os = "macos")]
        {
            super::mac_security::signing_evidence(bundle)
        }
        #[cfg(not(target_os = "macos"))]
        {
            let _ = bundle;
            Ok(MacSigningEvidence::unavailable())
        }
    }

    fn require_discovered_steam_library(&mut self, library: &Path) -> Result<()> {
        // Legacy/general metadata inventory only, not native policy authority.
        validate_path(library)
    }
}

#[cfg(not(any(target_os = "macos", target_os = "linux")))]
impl SoftwareBundleBackend for NativeFilesystemBackend {
    fn platform(&self) -> Platform {
        Platform::current()
    }
    fn kind(&self) -> BackendKind {
        BackendKind::NativeReadOnly
    }
    fn inspect_native(&mut self, _: &Path) -> Result<Option<NativeNode>> {
        bail!("native no-reparse inventory handles are unsupported")
    }
    fn list_directory(&mut self, _: &Path, _: usize) -> Result<Option<DirectoryEntries>> {
        bail!("native inventory is unsupported")
    }
    fn read_metadata(&mut self, _: &Path, _: usize) -> Result<Option<MetadataDocument>> {
        bail!("native inventory is unsupported")
    }
}

fn is_missing(error: &anyhow::Error) -> bool {
    error
        .downcast_ref::<std::io::Error>()
        .is_some_and(|e| e.kind() == std::io::ErrorKind::NotFound)
}

/// Isolated filesystem fixtures only. All paths, including injected installation
/// and signing records, must remain under the same pinned, no-follow sandbox.
/// No Security APIs, native accounts, environment discovery or vaults are used.
pub struct FixtureBundleBackend {
    root: PathBuf,
    root_identity: NativeIdentity,
    platform: Platform,
    signing: BTreeMap<PathBuf, MacSigningEvidence>,
    windows: Option<Vec<WindowsInstallation>>,
    native: NativeFilesystemBackend,
}

impl FixtureBundleBackend {
    pub fn new(root: &Path, platform: Platform) -> Result<Self> {
        validate_path(root)?;
        // Only the OS temporary-directory anchor is resolved here, never a
        // source app/account/vault path. The supplied child must be an isolated
        // real temp directory and is subsequently opened component-by-component.
        let temporary_base = std::fs::canonicalize(std::env::temp_dir())
            .context("fixture temporary-directory anchor is unavailable")?;
        ensure!(
            root != temporary_base.as_path() && root.starts_with(&temporary_base),
            "fixture sandbox must be an isolated child of the OS temporary directory"
        );
        let mut native = NativeFilesystemBackend;
        let node = native
            .inspect_native(root)?
            .context("fixture sandbox does not exist")?;
        ensure!(
            node.identity.kind() == NativeNodeKind::Directory,
            "fixture sandbox is not a directory"
        );
        Ok(Self {
            root: root.to_owned(),
            root_identity: node.identity,
            platform,
            signing: BTreeMap::new(),
            windows: None,
            native,
        })
    }

    fn confine(&mut self, path: &Path) -> Result<()> {
        validate_path(path)?;
        ensure!(path.starts_with(&self.root), "fixture path escapes sandbox");
        let current = self
            .native
            .inspect_native(&self.root)?
            .context("fixture sandbox disappeared")?;
        ensure!(
            current.identity == self.root_identity,
            "fixture sandbox identity changed"
        );
        Ok(())
    }

    pub fn set_mac_signing(&mut self, bundle: PathBuf, evidence: MacSigningEvidence) -> Result<()> {
        self.confine(&bundle)?;
        ensure!(self.signing.len() < 4096, "too many signing fixtures");
        self.signing.insert(bundle, evidence);
        Ok(())
    }

    pub fn set_windows_installations(
        &mut self,
        installations: Vec<WindowsInstallation>,
    ) -> Result<()> {
        ensure!(installations.len() <= 4096, "too many Windows fixtures");
        for installation in &installations {
            ensure!(
                installation.reviewed_mappings.len() <= 48,
                "too many fixture reviewed mappings"
            );
            if let Some(path) = &installation.installation_path {
                self.confine(path)?;
            }
            if let Some(path) = &installation.executable_path {
                self.confine(path)?;
            }
        }
        self.windows = Some(installations);
        Ok(())
    }
}

impl SoftwareBundleBackend for FixtureBundleBackend {
    fn platform(&self) -> Platform {
        self.platform
    }
    fn kind(&self) -> BackendKind {
        BackendKind::IsolatedFixture
    }
    fn inspect_native(&mut self, path: &Path) -> Result<Option<NativeNode>> {
        self.confine(path)?;
        self.native.inspect_native(path)
    }
    fn list_directory(&mut self, path: &Path, maximum: usize) -> Result<Option<DirectoryEntries>> {
        self.confine(path)?;
        self.native.list_directory(path, maximum)
    }
    fn read_metadata(&mut self, path: &Path, maximum: usize) -> Result<Option<MetadataDocument>> {
        self.confine(path)?;
        self.native.read_metadata(path, maximum)
    }
    fn mac_signing_evidence(&mut self, bundle: &Path) -> Result<MacSigningEvidence> {
        self.confine(bundle)?;
        Ok(self
            .signing
            .get(bundle)
            .cloned()
            .unwrap_or_else(MacSigningEvidence::unavailable))
    }
    fn windows_installations(&mut self, maximum: usize) -> Result<Vec<WindowsInstallation>> {
        let installations = self
            .windows
            .as_ref()
            .context("no explicit Windows fixture adapter was supplied")?;
        ensure!(
            installations.len() <= maximum,
            "Windows inventory exceeds application limit"
        );
        Ok(installations.clone())
    }

    fn require_discovered_steam_library(&mut self, library: &Path) -> Result<()> {
        self.confine(library)
    }
}
