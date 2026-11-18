// SPDX-License-Identifier: GPL-3.0-only
//! Native-only discovery capabilities retained from policy consent. No JSON
//! identity, path string, flag or newly encountered directory grants authority.
//! All metadata bytes are read through the original SafeRoot, never an absolute
//! path reopen. Directory operations use owned handles from the same SafeRoot.

use super::backend::validate_path;
use super::*;
#[cfg(not(any(target_os = "macos", target_os = "linux")))]
use anyhow::bail;
use anyhow::{ensure, Context, Result};
use quicksave_platform::{RootIdentity, SafeRoot};
use std::collections::BTreeSet;
use std::path::{Path, PathBuf};
use std::sync::Arc;

/// Retained native capability. Intentionally neither Serialize nor Deserialize.
/// Construct only from the native gateway's original policy-approved root and
/// expected identity, never from a renderer's incoming JSON claim.
#[derive(Clone)]
pub struct ApprovedDiscoveryBase {
    path: PathBuf,
    root: Arc<SafeRoot>,
    expected: RootIdentity,
}

/// Compatibility name for the initially published native API contract.
pub type ApprovedBundleBase = ApprovedDiscoveryBase;

impl ApprovedDiscoveryBase {
    pub fn from_pinned(path: PathBuf, root: Arc<SafeRoot>, expected: RootIdentity) -> Result<Self> {
        validate_path(&path)?;
        ensure!(
            root.identity()? == expected,
            "retained discovery base no longer matches its approved native identity"
        );
        // This constructor may inspect directory identities only. It never
        // reads metadata contents, and never replaces the retained root.
        let named = SafeRoot::open(&path)?;
        ensure!(
            named.identity()? == expected && root.same_root(&named)?,
            "discovery base path does not name the retained native root"
        );
        let result = Self {
            path,
            root,
            expected,
        };
        result.check_current()?;
        Ok(result)
    }

    pub fn path(&self) -> &Path {
        &self.path
    }

    pub fn expected_identity(&self) -> &RootIdentity {
        &self.expected
    }

    fn check_current(&self) -> Result<()> {
        // SafeRoot::identity checks its original pinned ancestor/name edges
        // before and after collecting the ID; it does not adopt replacements.
        ensure!(
            self.root.identity()? == self.expected,
            "approved discovery base changed; fresh native consent is required"
        );
        Ok(())
    }

    fn relative<'a>(&self, path: &'a Path) -> Result<Option<&'a str>> {
        let relative = path
            .strip_prefix(&self.path)
            .context("metadata path is outside its retained discovery base")?;
        if relative.as_os_str().is_empty() {
            return Ok(None);
        }
        let relative = relative.to_str().context("non-UTF8 native metadata path")?;
        ensure!(
            relative.len() <= 4096,
            "relative metadata path exceeds its bound"
        );
        Ok(Some(relative))
    }
}

/// Service entry point. `scope` is the original MAC-verified native policy scope,
/// including all persisted/native exclusions. Reuse `proofs` unchanged for a
/// Steam allow-list second pass; this function never consults environment paths.
pub fn discover_software_bundles_with_approved_bases(
    scope: &BundleInventoryScope,
    proofs: &[ApprovedDiscoveryBase],
) -> Result<serde_json::Value> {
    let mut backend = NativeApprovedBundleBackend::new(scope, proofs)?;
    discover_software_bundles_with_backend(&mut backend, scope, BundlePlanLimits::default())
}

pub struct NativeApprovedBundleBackend {
    scope: BundleInventoryScope,
    bases: Vec<ApprovedDiscoveryBase>,
    protected: Vec<PathBuf>,
    discovered_steam_libraries: BTreeSet<PathBuf>,
    #[cfg(test)]
    metadata_content_reads: usize,
    #[cfg(test)]
    before_content_guard: Option<Box<dyn FnMut()>>,
}

impl NativeApprovedBundleBackend {
    pub fn new(scope: &BundleInventoryScope, proofs: &[ApprovedDiscoveryBase]) -> Result<Self> {
        ensure!(
            !proofs.is_empty() && proofs.len() <= 128,
            "no retained discovery bases, or base limit exceeded"
        );
        let mut paths = BTreeSet::new();
        for base in proofs {
            validate_path(&base.path)?;
            ensure!(
                paths.insert(base.path.clone()),
                "duplicate discovery base path"
            );
            base.check_current()?;
        }
        ensure!(
            scope.application_directories.len() <= 128
                && scope.desktop_directories.len() <= 128
                && scope.steam_roots.len() <= 128
                && scope.protected_roots.len() <= 128,
            "native inventory scope exceeds bounds"
        );
        let mut protected = scope.protected_roots.clone();
        if let Some(home) = &scope.home {
            for relative in [
                "Library/Keychains",
                "Library/Application Support/com.noland.connect",
                "Library/Application Support/QuickSave",
                "Library/Containers/com.noland.connect",
                ".local/share/com.noland.connect",
                ".config/com.noland.connect",
                ".quicksave",
                ".config/quicksave",
                ".local/share/quicksave",
                ".ssh",
                ".gnupg",
                ".aws",
                ".azure",
                ".config/gcloud",
            ] {
                protected.push(home.join(relative));
            }
        }
        for anchor in scope
            .xdg_data_home
            .iter()
            .chain(scope.xdg_config_home.iter())
            .chain(scope.windows_known_folders.values())
        {
            protected.push(anchor.join("com.noland.connect"));
            protected.push(anchor.join("QuickSave"));
        }
        for path in &protected {
            validate_path(path)?;
        }
        protected.sort();
        protected.dedup();
        Ok(Self {
            scope: scope.clone(),
            bases: proofs.to_vec(),
            protected,
            discovered_steam_libraries: BTreeSet::new(),
            #[cfg(test)]
            metadata_content_reads: 0,
            #[cfg(test)]
            before_content_guard: None,
        })
    }

    fn is_protected(&self, path: &Path) -> bool {
        self.protected
            .iter()
            .any(|excluded| case_insensitive_prefix(path, excluded))
            || path.components().any(|part| {
                let name = part.as_os_str().to_string_lossy().to_lowercase();
                matches!(
                    name.as_str(),
                    "com.noland.connect"
                        | "quicksave"
                        | ".quicksave"
                        | "quicksave.app"
                        | "keychain"
                        | "keychains"
                        | "keyrings"
                        | "vault"
                        | "vaults"
                        | "credentials"
                        | "credentialmanager"
                        | "secrets"
                        | ".password-store"
                        | "cache"
                        | "caches"
                        | "log"
                        | "logs"
                        | ".ssh"
                        | ".gnupg"
                        | ".aws"
                        | ".azure"
                )
            })
    }

    fn select(&self, path: &Path) -> Result<ApprovedDiscoveryBase> {
        validate_path(path)?;
        ensure!(
            !self.is_protected(path),
            "protected source path is excluded before native metadata access"
        );
        // The most-specific capability must validate. Never fall back to a
        // broader valid home/base when a more-specific approved root changed.
        let base = self
            .bases
            .iter()
            .filter(|base| path.starts_with(&base.path))
            .max_by_key(|base| base.path.components().count())
            .context("metadata path has no retained native discovery base")?;
        base.check_current()?;
        Ok(base.clone())
    }

    fn steamapps_known(&self, parent: &Path) -> bool {
        self.scope
            .steam_roots
            .iter()
            .chain(self.discovered_steam_libraries.iter())
            .any(|library| parent == library.join("steamapps"))
    }

    fn metadata_allowed(&self, path: &Path) -> bool {
        let Some(name) = path.file_name().and_then(|name| name.to_str()) else {
            return false;
        };
        let Some(parent) = path.parent() else {
            return false;
        };
        if name == "Info.plist" && parent.file_name().is_some_and(|name| name == "Contents") {
            if let Some(bundle) = parent.parent() {
                return bundle
                    .file_name()
                    .and_then(|name| name.to_str())
                    .is_some_and(|name| name.to_ascii_lowercase().ends_with(".app"))
                    && self
                        .scope
                        .application_directories
                        .iter()
                        .any(|root| bundle.starts_with(root));
            }
        }
        if name.ends_with(".desktop") {
            return self
                .scope
                .desktop_directories
                .iter()
                .any(|root| parent == root);
        }
        if name == ".com.apple.containermanagerd.metadata.plist" {
            return self.scope.home.as_ref().is_some_and(|home| {
                parent.parent().is_some_and(|root| {
                    root == home.join("Library/Containers")
                        || root == home.join("Library/Group Containers")
                })
            });
        }
        if name == "libraryfolders.vdf" {
            return self
                .scope
                .steam_roots
                .iter()
                .any(|root| parent == root.join("steamapps"));
        }
        if self.steamapps_known(parent) {
            if let Some(id) = name
                .strip_prefix("appmanifest_")
                .and_then(|name| name.strip_suffix(".acf"))
            {
                return id
                    .parse::<u32>()
                    .is_ok_and(|parsed| parsed > 0 && parsed.to_string() == id);
            }
        }
        false
    }

    fn listing_allowed(&self, path: &Path) -> bool {
        if self
            .scope
            .desktop_directories
            .iter()
            .any(|root| path == root)
            || self.steamapps_known(path)
        {
            return true;
        }
        if self
            .scope
            .steam_roots
            .iter()
            .any(|root| path == root.join("userdata"))
        {
            return true;
        }
        self.scope.application_directories.iter().any(|root| {
            path.strip_prefix(root).is_ok_and(|relative| {
                // Installation discovery does not walk inside application
                // bundles or turn an installation scope into a file index.
                !relative.components().any(|part| {
                    part.as_os_str()
                        .to_str()
                        .is_some_and(|name| name.to_ascii_lowercase().ends_with(".app"))
                })
            })
        })
    }
}

#[cfg(any(target_os = "macos", target_os = "linux"))]
impl SoftwareBundleBackend for NativeApprovedBundleBackend {
    fn platform(&self) -> crate::profiles::Platform {
        crate::profiles::Platform::current()
    }
    fn kind(&self) -> BackendKind {
        BackendKind::NativeApprovedBases
    }

    fn inspect_native(&mut self, path: &Path) -> Result<Option<NativeNode>> {
        let base = self.select(path)?;
        let relative = base.relative(path)?;
        let result = (|| {
            let file = match open_pinned_directory(&base.root, relative) {
                Ok(file) => file,
                Err(error) if is_missing(&error) => return Ok(None),
                Err(_) => {
                    let relative = relative.context("approved base is not a directory")?;
                    match base.root.read_file(relative) {
                        Ok((file, _stamp)) => file,
                        Err(error) if is_missing(&error) => return Ok(None),
                        Err(error) => return Err(error),
                    }
                }
            };
            Ok(Some(native_node(&file.metadata()?)?))
        })();
        base.check_current()?;
        result
    }

    fn list_directory(&mut self, path: &Path, maximum: usize) -> Result<Option<DirectoryEntries>> {
        use crate::reader::Directory;
        ensure!(
            maximum > 0 && maximum <= 4096,
            "native directory listing exceeds its bound"
        );
        ensure!(
            self.listing_allowed(path),
            "path is not an approved metadata-enumeration source"
        );
        let base = self.select(path)?;
        let relative = base.relative(path)?;
        let result = (|| {
            let file = match open_pinned_directory(&base.root, relative) {
                Ok(file) => file,
                Err(error) if is_missing(&error) => return Ok(None),
                Err(error) => return Err(error),
            };
            let before = native_node(&file.metadata()?)?;
            let directory = Directory::from_pinned(file, path.to_owned())?;
            let listing = directory.entries(maximum)?;
            // Validate the same relative namespace through the original base,
            // not by reopening the absolute directory path.
            let current = open_pinned_directory(&base.root, relative)?;
            ensure!(
                native_node(&current.metadata()?)?.identity == before.identity,
                "relative discovery directory changed during enumeration"
            );
            Ok(Some(DirectoryEntries {
                names: listing.names,
                truncated: listing.truncated,
            }))
        })();
        base.check_current()?;
        result
    }

    fn read_metadata(&mut self, path: &Path, maximum: usize) -> Result<Option<MetadataDocument>> {
        use std::io::Read;
        use std::os::unix::fs::MetadataExt;
        ensure!(
            maximum > 0 && maximum <= 1024 * 1024,
            "metadata byte limit is invalid"
        );
        ensure!(
            self.metadata_allowed(path),
            "not a supported installation/container metadata document"
        );
        let base = self.select(path)?;
        let relative = base
            .relative(path)?
            .context("metadata must be a regular file below its approved base")?;
        let result = (|| {
            let (mut file, before) = match base.root.read_file(relative) {
                Ok(opened) => opened,
                Err(error) if is_missing(&error) => return Ok(None),
                Err(error) => return Err(error),
            };
            let metadata = file.metadata()?;
            ensure!(
                metadata.is_file() && metadata.nlink() == 1,
                "metadata is not a scoped single-link regular file"
            );
            ensure!(
                metadata.len() <= maximum as u64 && metadata.len() == before.size,
                "metadata exceeds its byte limit or changed"
            );
            #[cfg(test)]
            if let Some(mut hook) = self.before_content_guard.take() {
                hook();
            }
            // The last base + relative-file checks happen BEFORE reading any
            // metadata bytes, not only after discovery/materialization.
            base.check_current()?;
            base.root.verify_file(relative, &before)?;
            let mut bytes = Vec::with_capacity(metadata.len() as usize);
            #[cfg(test)]
            {
                self.metadata_content_reads += 1;
            }
            (&mut file)
                .take(maximum as u64 + 1)
                .read_to_end(&mut bytes)?;
            ensure!(
                bytes.len() <= maximum && bytes.len() as u64 == before.size,
                "metadata changed during bounded read"
            );
            let after = file.metadata()?;
            ensure!(
                native_node(&metadata)? == native_node(&after)?,
                "metadata handle changed while reading"
            );
            base.root.verify_file(relative, &before)?;
            Ok(Some(MetadataDocument {
                bytes,
                native_identity: native_node(&after)?.identity,
            }))
        })();
        base.check_current()?;
        result
    }

    fn mac_signing_evidence(&mut self, bundle: &Path) -> Result<MacSigningEvidence> {
        let base = self.select(bundle)?;
        // Do not invoke a public path-only Security API. Pre/post path checks
        // cannot rule out a replacement-and-restore race inside that API.
        base.check_current()?;
        Ok(MacSigningEvidence::unavailable())
    }

    fn require_discovered_steam_library(&mut self, library: &Path) -> Result<()> {
        validate_path(library)?;
        ensure!(!self.is_protected(library), "protected Steam library path");
        let steamapps = library.join("steamapps");
        let base = self
            .bases
            .iter()
            .find(|base| base.path == library || base.path == steamapps)
            .context("external Steam library needs its own retained native base identity")?;
        base.check_current()?;
        ensure!(
            self.discovered_steam_libraries.len() < 64
                || self.discovered_steam_libraries.contains(library),
            "Steam library bound exceeded"
        );
        self.discovered_steam_libraries.insert(library.to_owned());
        Ok(())
    }
}

#[cfg(not(any(target_os = "macos", target_os = "linux")))]
impl SoftwareBundleBackend for NativeApprovedBundleBackend {
    fn platform(&self) -> crate::profiles::Platform {
        crate::profiles::Platform::current()
    }
    fn kind(&self) -> BackendKind {
        BackendKind::NativeApprovedBases
    }
    fn inspect_native(&mut self, _: &Path) -> Result<Option<NativeNode>> {
        bail!("approved native node adapter is unavailable on this platform")
    }
    fn list_directory(&mut self, _: &Path, _: usize) -> Result<Option<DirectoryEntries>> {
        bail!("approved native directory adapter is unavailable on this platform")
    }
    fn read_metadata(&mut self, _: &Path, _: usize) -> Result<Option<MetadataDocument>> {
        bail!("approved native metadata adapter is unavailable on this platform")
    }
}

#[cfg(any(target_os = "macos", target_os = "linux"))]
fn open_pinned_directory(root: &SafeRoot, relative: Option<&str>) -> Result<std::fs::File> {
    match relative {
        Some(relative) => root.open_directory(relative),
        None => root.clone_root_directory_handle(),
    }
}

#[cfg(any(target_os = "macos", target_os = "linux"))]
fn native_node(metadata: &std::fs::Metadata) -> Result<NativeNode> {
    use std::os::unix::fs::MetadataExt;
    let kind = if metadata.is_dir() {
        NativeNodeKind::Directory
    } else {
        ensure!(metadata.is_file(), "unsupported metadata node type");
        NativeNodeKind::RegularFile
    };
    Ok(NativeNode {
        identity: NativeIdentity::Unix {
            device: metadata.dev(),
            inode: metadata.ino(),
            kind,
        },
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
    })
}

fn is_missing(error: &anyhow::Error) -> bool {
    error
        .downcast_ref::<std::io::Error>()
        .is_some_and(|error| error.kind() == std::io::ErrorKind::NotFound)
}

fn case_insensitive_prefix(path: &Path, excluded: &Path) -> bool {
    let mut path = path.components();
    excluded.components().all(|component| {
        path.next().is_some_and(|part| {
            part.as_os_str().to_string_lossy().to_lowercase()
                == component.as_os_str().to_string_lossy().to_lowercase()
        })
    })
}

#[cfg(all(test, any(target_os = "macos", target_os = "linux")))]
mod tests {
    use super::*;
    use std::fs;
    use std::os::unix::fs::{symlink, MetadataExt};

    fn temporary() -> tempfile::TempDir {
        let base = fs::canonicalize(std::env::temp_dir()).unwrap();
        tempfile::tempdir_in(base).unwrap()
    }

    fn pin(path: &Path) -> ApprovedDiscoveryBase {
        let root = Arc::new(SafeRoot::open(path).unwrap());
        let expected = root.identity().unwrap();
        ApprovedDiscoveryBase::from_pinned(path.to_owned(), root, expected).unwrap()
    }

    fn info(bundle: &Path, bytes: &[u8]) -> PathBuf {
        fs::create_dir_all(bundle.join("Contents")).unwrap();
        let path = bundle.join("Contents/Info.plist");
        fs::write(&path, bytes).unwrap();
        path
    }

    fn scope(applications: &Path) -> BundleInventoryScope {
        BundleInventoryScope {
            application_directories: vec![applications.to_owned()],
            ..BundleInventoryScope::default()
        }
    }

    #[test]
    fn retained_base_replacement_before_discovery_or_read_never_reads_new_plist_bytes() {
        let temp = temporary();
        let applications = temp.path().join("Applications");
        let path = info(&applications.join("One.app"), b"original fixture metadata");
        let proof = pin(&applications);
        let approved_id = proof.expected_identity().clone();
        let scope = scope(&applications);
        let mut backend =
            NativeApprovedBundleBackend::new(&scope, std::slice::from_ref(&proof)).unwrap();
        let moved = temp.path().join("moved-approved-applications");
        fs::rename(&applications, &moved).unwrap();
        info(
            &applications.join("One.app"),
            b"foreign replacement fixture secret; must not read",
        );
        assert!(backend.read_metadata(&path, 1024).is_err());
        assert!(backend.list_directory(&applications, 64).is_err());
        assert!(backend.inspect_native(&path).is_err());
        assert_eq!(backend.metadata_content_reads, 0);
        assert!(discover_software_bundles_with_approved_bases(
            &scope,
            std::slice::from_ref(&proof)
        )
        .is_err());
        assert_eq!(proof.expected_identity(), &approved_id);
        assert_eq!(fs::metadata(&moved).unwrap().ino(), approved_id.file_id[0]);
        assert_eq!(
            fs::read(moved.join("One.app/Contents/Info.plist")).unwrap(),
            b"original fixture metadata"
        );
    }

    #[test]
    fn replacement_after_file_handle_open_is_rejected_before_first_content_read() {
        let temp = temporary();
        let applications = temp.path().join("Applications");
        let path = info(&applications.join("One.app"), b"original fixture metadata");
        let proof = pin(&applications);
        let mut backend =
            NativeApprovedBundleBackend::new(&scope(&applications), &[proof]).unwrap();
        let moved = temp.path().join("original-applications");
        let raced_path = applications.clone();
        backend.before_content_guard = Some(Box::new(move || {
            fs::rename(&raced_path, &moved).unwrap();
            info(
                &raced_path.join("One.app"),
                b"raced replacement secret fixture",
            );
        }));
        assert!(backend.read_metadata(&path, 1024).is_err());
        assert_eq!(backend.metadata_content_reads, 0);
    }

    #[test]
    fn child_directory_symlink_race_after_open_cannot_reach_any_content_read() {
        let temp = temporary();
        let applications = temp.path().join("Applications");
        let bundle = applications.join("One.app");
        let path = info(&bundle, b"original fixture metadata");
        let outside = temp.path().join("outside-fixture");
        fs::create_dir_all(&outside).unwrap();
        fs::write(outside.join("Info.plist"), b"foreign fixture secret").unwrap();
        let proof = pin(&applications);
        let mut backend =
            NativeApprovedBundleBackend::new(&scope(&applications), &[proof]).unwrap();
        backend.before_content_guard = Some(Box::new(move || {
            fs::rename(bundle.join("Contents"), bundle.join("old-contents")).unwrap();
            symlink(&outside, bundle.join("Contents")).unwrap();
        }));
        assert!(backend.read_metadata(&path, 1024).is_err());
        assert_eq!(backend.metadata_content_reads, 0);
    }

    #[test]
    fn a_correct_byte_read_and_listing_use_retained_handles_and_known_metadata_only() {
        let temp = temporary();
        let applications = temp.path().join("Applications");
        let path = info(&applications.join("One.app"), b"bounded metadata fixture");
        fs::write(
            applications.join("One.app/Contents/private-save"),
            b"never read this fixture",
        )
        .unwrap();
        let proof = pin(&applications);
        let mut backend =
            NativeApprovedBundleBackend::new(&scope(&applications), &[proof]).unwrap();
        let listing = backend.list_directory(&applications, 32).unwrap().unwrap();
        assert_eq!(listing.names, vec!["One.app"]);
        let document = backend.read_metadata(&path, 1024).unwrap().unwrap();
        assert_eq!(document.bytes, b"bounded metadata fixture");
        assert_eq!(backend.metadata_content_reads, 1);
        assert!(backend
            .read_metadata(&applications.join("One.app/Contents/private-save"), 1024)
            .is_err());
        assert!(backend
            .list_directory(&applications.join("One.app/Contents"), 32)
            .is_err());
        assert_eq!(backend.metadata_content_reads, 1);
    }

    #[test]
    fn child_symlink_and_unapproved_new_base_do_not_reach_metadata_bytes() {
        let temp = temporary();
        let applications = temp.path().join("Applications");
        let outside = temp.path().join("outside");
        fs::create_dir_all(&applications).unwrap();
        let outside_info = info(&outside.join("Foreign.app"), b"outside fixture secret");
        symlink(outside.join("Foreign.app"), applications.join("Linked.app")).unwrap();
        let proof = pin(&applications);
        let mut backend =
            NativeApprovedBundleBackend::new(&scope(&applications), &[proof]).unwrap();
        assert!(backend
            .read_metadata(&applications.join("Linked.app/Contents/Info.plist"), 1024)
            .is_err());
        assert!(backend.read_metadata(&outside_info, 1024).is_err());
        assert!(backend.inspect_native(&outside_info).is_err());
        assert_eq!(backend.metadata_content_reads, 0);
    }

    #[test]
    fn proof_path_and_expected_id_cannot_be_changed_into_another_base() {
        let temp = temporary();
        let first = temp.path().join("first");
        let second = temp.path().join("second");
        fs::create_dir_all(&first).unwrap();
        fs::create_dir_all(&second).unwrap();
        let root = Arc::new(SafeRoot::open(&first).unwrap());
        let expected = root.identity().unwrap();
        assert!(
            ApprovedDiscoveryBase::from_pinned(second.clone(), root.clone(), expected.clone())
                .is_err()
        );
        let other_id = SafeRoot::open(&second).unwrap().identity().unwrap();
        assert!(ApprovedDiscoveryBase::from_pinned(first, root, other_id).is_err());
        assert!(NativeApprovedBundleBackend::new(&BundleInventoryScope::default(), &[]).is_err());
    }

    #[test]
    fn noland_quicksave_and_policy_exclusions_reject_even_whitelisted_metadata_without_reads() {
        let temp = temporary();
        let base = temp.path().join("appdata");
        let noland_apps = base.join("com.noland.connect/Applications");
        let quicksave_apps = base.join("QuickSave/Applications");
        let protected_apps = base.join("UserProtected/Applications");
        let paths = [
            info(
                &noland_apps.join("One.app"),
                b"synthetic No Land state material; must not read",
            ),
            info(
                &quicksave_apps.join("One.app"),
                b"synthetic QuickSave vault material; must not read",
            ),
            info(
                &protected_apps.join("One.app"),
                b"native-policy excluded fixture; must not read",
            ),
        ];
        let scope = BundleInventoryScope {
            application_directories: vec![noland_apps, quicksave_apps, protected_apps.clone()],
            protected_roots: vec![protected_apps],
            ..BundleInventoryScope::default()
        };
        let mut backend = NativeApprovedBundleBackend::new(&scope, &[pin(&base)]).unwrap();
        for path in paths {
            assert!(backend.read_metadata(&path, 1024).is_err());
            assert!(backend.inspect_native(&path).is_err());
        }
        assert_eq!(backend.metadata_content_reads, 0);
    }

    fn steam_app(root: &Path, id: u32) {
        fs::create_dir_all(root.join(format!("steamapps/common/Actual-{id}"))).unwrap();
        fs::write(
            root.join(format!("steamapps/common/Actual-{id}/file")),
            b"fixture installed game",
        )
        .unwrap();
        fs::write(root.join(format!("steamapps/appmanifest_{id}.acf")), format!(
            r#""AppState" {{ "appid" "{id}" "name" "Same untrusted title" "installdir" "Actual-{id}" }}"#
        )).unwrap();
    }

    #[test]
    fn vdf_external_library_needs_its_own_pin_not_a_broader_home_capability() {
        let temp = temporary();
        let home = temp.path().join("home");
        let launcher = home.join("KnownSteam");
        let external = home.join("NewExternalLibrary");
        steam_app(&launcher, 480);
        steam_app(&external, 481);
        fs::write(
            launcher.join("steamapps/libraryfolders.vdf"),
            format!(
                r#""libraryfolders" {{ "0" {{ "path" "{}" }} "1" {{ "path" "{}" }} }}"#,
                launcher.display(),
                external.display()
            ),
        )
        .unwrap();
        let mut scope = BundleInventoryScope {
            steam_roots: vec![launcher],
            ..BundleInventoryScope::default()
        };
        let home_pin = pin(&home);
        let mut backend =
            NativeApprovedBundleBackend::new(&scope, std::slice::from_ref(&home_pin)).unwrap();
        let report = discover_software_bundles_with_backend(
            &mut backend,
            &scope,
            BundlePlanLimits::default(),
        )
        .unwrap();
        assert_eq!(report["bundlePlans"].as_array().unwrap().len(), 1);
        assert_eq!(backend.metadata_content_reads, 2); // Known VDF + known manifest, not the external manifest.
        assert!(report["diagnostics"]
            .as_array()
            .unwrap()
            .iter()
            .any(|diagnostic| diagnostic["code"] == "steam_library_not_separately_approved"));
        let proofs = vec![home_pin, pin(&external)];
        let first = discover_software_bundles_with_approved_bases(&scope, &proofs).unwrap();
        assert_eq!(first["bundlePlans"].as_array().unwrap().len(), 2);
        // Inventory-approved numeric IDs do not replace or expand root proofs.
        scope.inventory_approved_steam_app_ids.extend([480, 481]);
        let second = discover_software_bundles_with_approved_bases(&scope, &proofs).unwrap();
        assert_eq!(second["bundlePlans"].as_array().unwrap().len(), 2);
        let moved = home.join("old-external");
        fs::rename(&external, moved).unwrap();
        steam_app(&external, 999);
        assert!(discover_software_bundles_with_approved_bases(&scope, &proofs).is_err());
    }
}
