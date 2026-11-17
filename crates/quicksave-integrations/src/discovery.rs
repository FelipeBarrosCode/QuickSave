// SPDX-License-Identifier: GPL-3.0-only
use anyhow::Result;
use serde::Serialize;
use std::path::PathBuf;

use crate::profiles::{AppIdentity, Platform, RootScope};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum DiscoverySource {
    MacApplicationBundle,
    XdgDesktopEntry,
    SteamManifest,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum DiscoveryAuthority {
    NotGranted,
}

#[derive(Debug, Clone, Serialize)]
pub struct DiscoveredRoot {
    pub path: PathBuf,
    pub scope: RootScope,
    pub evidence: DiscoverySource,
    pub requires_explicit_approval: bool,
}

#[derive(Debug, Clone, Serialize)]
pub struct DiscoveredApplication {
    pub identity: AppIdentity,
    /// Untrusted display metadata, never an ownership/identity key.
    pub display_name: String,
    pub source: DiscoverySource,
    pub profile_id: &'static str,
    pub root_candidates: Vec<DiscoveredRoot>,
    pub backup_authority: DiscoveryAuthority,
}

#[derive(Debug, Clone, Serialize)]
pub struct DiscoveryDiagnostic {
    pub source: DiscoverySource,
    pub path: Option<PathBuf>,
    pub code: &'static str,
    /// Static messages avoid echoing arbitrary document/command/secret content.
    pub message: &'static str,
}

#[derive(Debug, Clone, Copy, Serialize)]
pub struct DiscoveryLimits {
    pub max_roots: usize,
    pub max_steam_libraries: usize,
    pub max_entries_per_directory: usize,
    pub max_total_entries: usize,
    pub max_applications: usize,
    pub max_metadata_bytes_per_file: usize,
    pub max_total_metadata_bytes: usize,
    pub max_diagnostics: usize,
}

impl Default for DiscoveryLimits {
    fn default() -> Self {
        Self {
            max_roots: 64,
            max_steam_libraries: 32,
            max_entries_per_directory: 4096,
            max_total_entries: 32768,
            max_applications: 2048,
            max_metadata_bytes_per_file: 1024 * 1024,
            max_total_metadata_bytes: 64 * 1024 * 1024,
            max_diagnostics: 128,
        }
    }
}

#[derive(Debug, Serialize)]
pub struct DiscoveryReport {
    pub schema_version: u32,
    pub platform: Platform,
    pub applications: Vec<DiscoveredApplication>,
    pub diagnostics: Vec<DiscoveryDiagnostic>,
    pub omitted_diagnostics: usize,
    pub incomplete: bool,
    pub examined_entries: usize,
    pub limits: DiscoveryLimits,
    pub backup_authority: DiscoveryAuthority,
    pub limitations: Vec<&'static str>,
}

/// Reads bounded installation metadata only. No subprocess, recursive home scan,
/// credentials, save/config contents, executable inspection or backup grant.
/// Windows errors explicitly until a tested native no-reparse reader exists.
pub fn discover_applications() -> Result<serde_json::Value> {
    #[cfg(any(target_os = "macos", target_os = "linux"))]
    {
        let platform = Platform::current();
        let locations = scanning::Locations::from_environment(platform)?;
        Ok(serde_json::to_value(scanning::discover_locations(
            platform,
            locations,
            DiscoveryLimits::default(),
        ))?)
    }
    #[cfg(not(any(target_os = "macos", target_os = "linux")))]
    {
        anyhow::bail!(
            "application discovery is unsupported on this platform: Windows registry, Desktop and Start Menu discovery and native no-reparse reads are not implemented; select an explicit manual folder"
        )
    }
}

pub(crate) fn capabilities() -> serde_json::Value {
    serde_json::json!({
        "platform": Platform::current(),
        "status": if cfg!(any(target_os = "macos", target_os = "linux")) {
            "implemented_read_only"
        } else {
            "unsupported"
        },
        "native_packaging_acceptance": false,
        "backup_authority": DiscoveryAuthority::NotGranted,
        "recursive_home_scan": false,
        "reads_save_or_config_contents": false,
        "runs_subprocesses": false,
        "follows_symlinks_or_reparse_points": false,
        "limits": DiscoveryLimits::default(),
        "plist_limits": {
            "max_expanded_events": crate::parsers::macos::MAX_PLIST_EVENTS,
            "max_nesting_depth": crate::parsers::macos::MAX_PLIST_DEPTH,
            "max_expanded_value_bytes": crate::parsers::macos::MAX_EXPANDED_PLIST_BYTES
        },
        "sources": [
            {
                "kind": "mac_application_bundles",
                "platforms": [Platform::MacOs],
                "status": "implemented",
                "available_on_current_platform": cfg!(target_os = "macos"),
                "search": ["/Applications/*.app", "~/Applications/*.app"],
                "detail": "Top level only, bundle ID from bounded XML/binary Info.plist using Rust plist. Missing IDs are not replaced with title ownership.",
                "reference": "https://developer.apple.com/library/archive/documentation/General/Reference/InfoPlistKeyReference/"
            },
            {
                "kind": "xdg_desktop_entries",
                "platforms": [Platform::Linux],
                "status": "implemented",
                "available_on_current_platform": cfg!(target_os = "linux"),
                "search": ["$XDG_DATA_HOME/applications/*.desktop", "$XDG_DATA_DIRS/applications/*.desktop"],
                "detail": "Top level only with XDG precedence and Hidden masking; Exec never runs and does not confer install/save ownership. Nested desktop entries are not scanned.",
                "reference": "https://specifications.freedesktop.org/desktop-entry-spec/latest/"
            },
            {
                "kind": "steam_manifests",
                "platforms": [Platform::MacOs, Platform::Linux],
                "status": "implemented",
                "available_on_current_platform": cfg!(any(target_os = "macos", target_os = "linux")),
                "detail": "Known Steam roots plus bounded libraryfolders.vdf and top-level appmanifest files; stable app ID plus existing no-follow install directory. No userdata/prefix/save attribution.",
                "parser_platforms": [Platform::MacOs, Platform::Windows, Platform::Linux],
                "windows_native_discovery": "unsupported"
            },
            {
                "kind": "windows_desktop_start_menu_uninstall_registry",
                "platforms": [Platform::Windows],
                "status": "unsupported",
                "available_on_current_platform": false,
                "detail": "Native Windows handles, known folders, .lnk resolution and uninstall registry enumeration are not implemented. Use explicit manual folders.",
                "references": [
                    "https://learn.microsoft.com/en-us/windows/win32/shell/knownfolderid",
                    "https://learn.microsoft.com/en-us/windows/win32/msi/uninstall-registry-key"
                ]
            }
        ]
    })
}

#[cfg(any(target_os = "macos", target_os = "linux"))]
mod scanning {
    use super::*;
    use anyhow::{ensure, Context};
    use std::collections::BTreeSet;
    use std::io;
    use std::path::Path;

    use crate::parsers::{desktop, macos, steam};
    use crate::profiles::{Architecture, InstallIdentity, InstallKind, ProductIdentity};
    use crate::reader::Directory;

    const MAX_XDG_ROOTS: usize = 16;

    #[derive(Default)]
    pub(super) struct Locations {
        bundles: Vec<PathBuf>,
        desktop: Vec<PathBuf>,
        steam: Vec<PathBuf>,
    }

    impl Locations {
        pub(super) fn from_environment(platform: Platform) -> Result<Self> {
            let home = std::env::var_os("HOME").map(PathBuf::from);
            if let Some(home) = &home {
                ensure!(home.is_absolute(), "HOME is not an absolute path");
            }
            let mut locations = Self::default();
            match platform {
                Platform::MacOs => {
                    locations.bundles.push(PathBuf::from("/Applications"));
                    if let Some(home) = home {
                        locations.bundles.push(home.join("Applications"));
                        locations
                            .steam
                            .push(home.join("Library/Application Support/Steam"));
                    }
                }
                Platform::Linux => {
                    let data_home = std::env::var_os("XDG_DATA_HOME")
                        .map(PathBuf::from)
                        .or_else(|| home.as_ref().map(|home| home.join(".local/share")));
                    if let Some(data_home) = data_home {
                        ensure!(data_home.is_absolute(), "XDG_DATA_HOME is not absolute");
                        locations.desktop.push(data_home.join("applications"));
                    }
                    let data_dirs = std::env::var_os("XDG_DATA_DIRS")
                        .filter(|value| !value.is_empty())
                        .unwrap_or_else(|| "/usr/local/share:/usr/share".into());
                    ensure!(
                        data_dirs.len() <= 16384,
                        "XDG_DATA_DIRS exceeds input limit"
                    );
                    for (index, directory) in std::env::split_paths(&data_dirs).enumerate() {
                        ensure!(index < MAX_XDG_ROOTS, "too many XDG data directories");
                        ensure!(
                            directory.is_absolute(),
                            "XDG data directory is not absolute"
                        );
                        let applications = directory.join("applications");
                        if !locations.desktop.contains(&applications) {
                            locations.desktop.push(applications);
                        }
                    }
                    if let Some(home) = home {
                        for relative in [
                            ".local/share/Steam",
                            ".steam/steam",
                            ".steam/debian-installation",
                            ".var/app/com.valvesoftware.Steam/data/Steam",
                        ] {
                            locations.steam.push(home.join(relative));
                        }
                    }
                    locations.steam.push(PathBuf::from("/usr/share/steam"));
                }
                _ => anyhow::bail!("native application discovery is unsupported"),
            }
            Ok(locations)
        }
    }

    struct Collector {
        report: DiscoveryReport,
        remaining_entries: usize,
        remaining_metadata: usize,
        opened_roots: usize,
        identities: BTreeSet<(ProductIdentity, PathBuf)>,
    }

    impl Collector {
        fn new(platform: Platform, limits: DiscoveryLimits) -> Self {
            Self {
                report: DiscoveryReport {
                    schema_version: 1, platform, applications: Vec::new(),
                    diagnostics: Vec::new(), omitted_diagnostics: 0, incomplete: false,
                    examined_entries: 0, limits, backup_authority: DiscoveryAuthority::NotGranted,
                    limitations: vec![
                        "Discovery never authorizes backup or restore.",
                        "Display titles and basenames are not used to infer save/config ownership.",
                        "Only bounded installation metadata is read; no save/config or whole-home scan.",
                        "Symlinked locations are rejected, not canonicalized.",
                        "Game-specific save/config locations require manual mappings and explicit approval.",
                        "Executable architecture is unknown; host OS is not proof of game executable compatibility.",
                        "No application-atomic snapshot, Windows registry discovery or cloud transport is provided.",
                    ],
                },
                remaining_entries: limits.max_total_entries,
                remaining_metadata: limits.max_total_metadata_bytes,
                opened_roots: 0,
                identities: BTreeSet::new(),
            }
        }

        fn diagnostic(
            &mut self,
            source: DiscoverySource,
            path: Option<&Path>,
            code: &'static str,
            message: &'static str,
        ) {
            self.report.incomplete = true;
            if self.report.diagnostics.len() < self.report.limits.max_diagnostics {
                self.report.diagnostics.push(DiscoveryDiagnostic {
                    source,
                    path: path.map(Path::to_path_buf),
                    code,
                    message,
                });
            } else {
                self.report.omitted_diagnostics += 1;
            }
        }

        fn open(&mut self, path: &Path, source: DiscoverySource) -> Option<Directory> {
            if self.opened_roots >= self.report.limits.max_roots {
                self.diagnostic(
                    source,
                    Some(path),
                    "root_limit",
                    "Discovery root count limit reached.",
                );
                return None;
            }
            self.opened_roots += 1;
            match Directory::open(path) {
                Ok(directory) => Some(directory),
                Err(error) if is_not_found(&error) => None,
                Err(_) => {
                    self.diagnostic(source, Some(path), "unsafe_or_unreadable_root",
                        "Root rejected: invalid path, symlink ancestor, unsupported type or read error.");
                    None
                }
            }
        }

        fn child(
            &mut self,
            directory: &Directory,
            name: &str,
            source: DiscoverySource,
        ) -> Option<Directory> {
            match directory.child(name) {
                Ok(child) => Some(child),
                Err(error) if is_not_found(&error) => None,
                Err(_) => {
                    self.diagnostic(source, Some(&directory.path().join(name)), "unsafe_or_unreadable_directory",
                        "Directory rejected: symlink, invalid path, unsupported type or read error.");
                    None
                }
            }
        }

        fn entries(&mut self, directory: &Directory, source: DiscoverySource) -> Vec<String> {
            let maximum = self
                .remaining_entries
                .min(self.report.limits.max_entries_per_directory);
            if maximum == 0 {
                self.diagnostic(
                    source,
                    Some(directory.path()),
                    "entry_limit",
                    "Discovery entry budget exhausted.",
                );
                return Vec::new();
            }
            // Reserve the bound even on a failed enumeration, just as with
            // reads, so invalid filenames cannot repeatedly bypass the budget.
            self.remaining_entries -= maximum;
            match directory.entries(maximum) {
                Ok(listing) => {
                    self.remaining_entries += maximum - listing.names.len();
                    self.report.examined_entries += listing.names.len();
                    if listing.truncated {
                        self.diagnostic(
                            source,
                            Some(directory.path()),
                            "entry_limit",
                            "Directory enumeration truncated at the configured entry bound.",
                        );
                    }
                    listing.names
                }
                Err(_) => {
                    self.diagnostic(
                        source,
                        Some(directory.path()),
                        "directory_read_failed",
                        "Directory enumeration failed or contained an invalid entry.",
                    );
                    Vec::new()
                }
            }
        }

        fn read(
            &mut self,
            directory: &Directory,
            name: &str,
            maximum: usize,
            source: DiscoverySource,
        ) -> Option<Vec<u8>> {
            let maximum = maximum
                .min(self.report.limits.max_metadata_bytes_per_file)
                .min(self.remaining_metadata);
            if maximum == 0 {
                self.diagnostic(
                    source,
                    Some(directory.path()),
                    "metadata_limit",
                    "Metadata read budget exhausted.",
                );
                return None;
            }
            // Charge the maximum on failure too, bounding work even when a
            // malicious file repeatedly changes during the stability check.
            self.remaining_metadata -= maximum;
            match directory.read_file(name, maximum) {
                Ok(bytes) => {
                    self.remaining_metadata += maximum - bytes.len();
                    Some(bytes)
                }
                Err(error) if is_not_found(&error) => {
                    self.remaining_metadata += maximum;
                    None
                }
                Err(_) => {
                    self.diagnostic(source, Some(&directory.path().join(name)), "metadata_read_failed",
                        "Metadata rejected: symlink, size budget, nonregular/changed file or read error.");
                    None
                }
            }
        }

        fn add(&mut self, application: DiscoveredApplication) {
            let key = (
                application.identity.product.clone(),
                application
                    .identity
                    .install
                    .location
                    .as_ref()
                    .unwrap_or(&application.identity.install.metadata_path)
                    .clone(),
            );
            if self.identities.contains(&key) {
                return;
            }
            if self.report.applications.len() >= self.report.limits.max_applications {
                self.diagnostic(
                    application.source,
                    None,
                    "application_limit",
                    "Application result limit reached.",
                );
                return;
            }
            self.identities.insert(key);
            self.report.applications.push(application);
        }

        fn full(&self) -> bool {
            self.report.applications.len() >= self.report.limits.max_applications
        }
    }

    fn is_not_found(error: &anyhow::Error) -> bool {
        error
            .downcast_ref::<io::Error>()
            .is_some_and(|error| error.kind() == io::ErrorKind::NotFound)
    }

    pub(super) fn discover_locations(
        platform: Platform,
        locations: Locations,
        limits: DiscoveryLimits,
    ) -> DiscoveryReport {
        let mut collector = Collector::new(platform, limits);
        scan_bundles(&locations.bundles, &mut collector);
        scan_desktop(&locations.desktop, &mut collector);
        scan_steam(&locations.steam, &mut collector);
        collector.report.applications.sort_by(|left, right| {
            (
                &left.identity.product,
                &left.identity.install.location,
                &left.identity.install.metadata_path,
            )
                .cmp(&(
                    &right.identity.product,
                    &right.identity.install.location,
                    &right.identity.install.metadata_path,
                ))
        });
        collector.report
    }

    fn scan_bundles(roots: &[PathBuf], collector: &mut Collector) {
        let source = DiscoverySource::MacApplicationBundle;
        for root in roots {
            let Some(directory) = collector.open(root, source) else {
                continue;
            };
            for name in collector.entries(&directory, source) {
                if !name.to_ascii_lowercase().ends_with(".app") {
                    continue;
                }
                if collector.full() {
                    collector.diagnostic(
                        source,
                        Some(root),
                        "application_limit",
                        "Application result limit reached.",
                    );
                    return;
                }
                let Some(bundle) = collector.child(&directory, &name, source) else {
                    continue;
                };
                let Some(contents) = collector.child(&bundle, "Contents", source) else {
                    continue;
                };
                let Some(bytes) =
                    collector.read(&contents, "Info.plist", macos::MAX_PLIST_BYTES, source)
                else {
                    continue;
                };
                let metadata = match macos::parse_info_plist(&bytes) {
                    Ok(metadata) => metadata,
                    Err(_) => {
                        collector.diagnostic(source, Some(&contents.path().join("Info.plist")), "invalid_bundle_metadata",
                            "Bundle metadata is invalid or lacks a stable bundle identifier; use manual folder selection.");
                        continue;
                    }
                };
                let location = bundle.path().to_path_buf();
                collector.add(DiscoveredApplication {
                    display_name: metadata
                        .display_name
                        .unwrap_or_else(|| metadata.bundle_identifier.clone()),
                    identity: AppIdentity {
                        product: ProductIdentity::MacBundleIdentifier(metadata.bundle_identifier),
                        install: InstallIdentity {
                            kind: InstallKind::MacApplicationBundle,
                            location: Some(location.clone()),
                            metadata_path: contents.path().join("Info.plist"),
                        },
                        platform: collector.report.platform,
                        architecture: Architecture::Unknown,
                    },
                    source,
                    profile_id: "unknown-manual-folder-v1",
                    root_candidates: vec![DiscoveredRoot {
                        path: location,
                        scope: RootScope::Installation,
                        evidence: source,
                        requires_explicit_approval: true,
                    }],
                    backup_authority: DiscoveryAuthority::NotGranted,
                });
            }
        }
    }

    fn scan_desktop(roots: &[PathBuf], collector: &mut Collector) {
        let source = DiscoverySource::XdgDesktopEntry;
        let mut seen_ids = BTreeSet::new();
        for root in roots {
            let Some(directory) = collector.open(root, source) else {
                continue;
            };
            for name in collector.entries(&directory, source) {
                if !name.ends_with(".desktop") || !seen_ids.insert(name.clone()) {
                    continue;
                }
                if collector.full() {
                    collector.diagnostic(
                        source,
                        Some(root),
                        "application_limit",
                        "Application result limit reached.",
                    );
                    return;
                }
                let Some(bytes) =
                    collector.read(&directory, &name, desktop::MAX_DESKTOP_BYTES, source)
                else {
                    continue;
                };
                let parsed = std::str::from_utf8(&bytes)
                    .context("non-UTF8 desktop entry")
                    .and_then(desktop::parse_desktop_entry);
                let metadata = match parsed {
                    Ok(metadata) => metadata,
                    Err(_) => {
                        collector.diagnostic(
                            source,
                            Some(&directory.path().join(&name)),
                            "invalid_desktop_metadata",
                            "Desktop entry is invalid or is not an application.",
                        );
                        continue;
                    }
                };
                if metadata.hidden {
                    continue;
                }
                collector.add(DiscoveredApplication {
                    identity: AppIdentity {
                        product: ProductIdentity::DesktopEntryId(name.clone()),
                        install: InstallIdentity {
                            kind: InstallKind::DesktopLauncher,
                            location: None,
                            metadata_path: directory.path().join(&name),
                        },
                        platform: collector.report.platform,
                        architecture: Architecture::Unknown,
                    },
                    display_name: metadata.display_name.unwrap_or(name),
                    source,
                    profile_id: "unknown-manual-folder-v1",
                    root_candidates: Vec::new(),
                    backup_authority: DiscoveryAuthority::NotGranted,
                });
            }
        }
    }

    fn scan_steam(roots: &[PathBuf], collector: &mut Collector) {
        let source = DiscoverySource::SteamManifest;
        let mut libraries = Vec::new();
        let mut seen_libraries = BTreeSet::new();
        for root in roots {
            let Some(directory) = collector.open(root, source) else {
                continue;
            };
            let Some(steamapps) = collector.child(&directory, "steamapps", source) else {
                continue;
            };
            let mut paths = vec![steamapps.path().to_path_buf()];
            if let Some(bytes) = collector.read(
                &steamapps,
                "libraryfolders.vdf",
                steam::MAX_VDF_BYTES,
                source,
            ) {
                let parsed = std::str::from_utf8(&bytes)
                    .context("non-UTF8 Steam library metadata")
                    .and_then(steam::parse_libraryfolders);
                match parsed {
                    Ok(entries) => {
                        for entry in entries {
                            let path = PathBuf::from(entry.path);
                            if path.is_absolute() {
                                paths.push(path.join("steamapps"));
                            } else {
                                collector.diagnostic(source, Some(steamapps.path()), "foreign_library_path",
                                    "Library path is not absolute for this host OS; it was not scanned.");
                            }
                        }
                    }
                    Err(_) => collector.diagnostic(
                        source,
                        Some(&steamapps.path().join("libraryfolders.vdf")),
                        "invalid_library_metadata",
                        "Steam library metadata is invalid or exceeds parser bounds.",
                    ),
                }
            }
            for path in paths {
                if seen_libraries.contains(&path) {
                    continue;
                }
                if seen_libraries.len() >= collector.report.limits.max_steam_libraries {
                    collector.diagnostic(
                        source,
                        Some(&path),
                        "library_limit",
                        "Steam library count limit reached.",
                    );
                    break;
                }
                seen_libraries.insert(path.clone());
                if let Some(library) = collector.open(&path, source) {
                    libraries.push(library);
                }
            }
        }
        for library in libraries {
            let Some(common) = collector.child(&library, "common", source) else {
                continue;
            };
            for name in collector.entries(&library, source) {
                let Some(raw_id) = name
                    .strip_prefix("appmanifest_")
                    .and_then(|tail| tail.strip_suffix(".acf"))
                else {
                    continue;
                };
                if !raw_id.bytes().all(|byte| byte.is_ascii_digit()) {
                    continue;
                }
                let Ok(filename_id) = raw_id.parse::<u32>() else {
                    continue;
                };
                if collector.full() {
                    collector.diagnostic(
                        source,
                        Some(library.path()),
                        "application_limit",
                        "Application result limit reached.",
                    );
                    return;
                }
                let Some(bytes) = collector.read(&library, &name, steam::MAX_VDF_BYTES, source)
                else {
                    continue;
                };
                let parsed = std::str::from_utf8(&bytes)
                    .context("non-UTF8 Steam app metadata")
                    .and_then(steam::parse_appmanifest);
                let metadata = match parsed {
                    Ok(metadata) if metadata.app_id == filename_id => metadata,
                    _ => {
                        collector.diagnostic(source, Some(&library.path().join(&name)), "invalid_appmanifest",
                            "Steam manifest is invalid, unsafe or does not match the filename app ID.");
                        continue;
                    }
                };
                let Some(install) =
                    collector.child(&common, metadata.install_subdirectory.as_str(), source)
                else {
                    continue;
                };
                let location = install.path().to_path_buf();
                collector.add(DiscoveredApplication {
                    identity: AppIdentity {
                        product: ProductIdentity::SteamAppId(metadata.app_id),
                        install: InstallIdentity {
                            kind: InstallKind::SteamApplication,
                            location: Some(location.clone()),
                            metadata_path: library.path().join(&name),
                        },
                        platform: collector.report.platform,
                        architecture: Architecture::Unknown,
                    },
                    display_name: metadata.display_name,
                    source,
                    profile_id: "steam-manual-data-v1",
                    root_candidates: vec![DiscoveredRoot {
                        path: location,
                        scope: RootScope::Installation,
                        evidence: source,
                        requires_explicit_approval: true,
                    }],
                    backup_authority: DiscoveryAuthority::NotGranted,
                });
            }
        }
    }

    #[cfg(test)]
    mod tests {
        use super::*;
        use std::fs;
        use std::os::unix::fs::symlink;

        fn temporary() -> tempfile::TempDir {
            let base = fs::canonicalize(std::env::temp_dir()).unwrap();
            tempfile::tempdir_in(base).unwrap()
        }

        fn bundle(path: &Path, id: &str) {
            fs::create_dir_all(path.join("Contents")).unwrap();
            fs::write(path.join("Contents/Info.plist"), format!(
                "<plist version=\"1.0\"><dict><key>CFBundleIdentifier</key><string>{id}</string><key>CFBundleName</key><string>Same Name</string></dict></plist>"
            )).unwrap();
        }

        fn app(library: &Path, id: u32, directory: &str) {
            fs::create_dir_all(library.join("steamapps/common").join(directory)).unwrap();
            fs::write(library.join(format!("steamapps/appmanifest_{id}.acf")), format!(
                r#""AppState" {{ "appid" "{id}" "name" "Same Name" "installdir" "{directory}" }}"#
            )).unwrap();
        }

        #[test]
        fn bundle_discovery_is_top_level_and_bundle_id_plus_install_path_based() {
            let temp = temporary();
            let applications = temp.path().join("Applications");
            bundle(&applications.join("One.app"), "org.fixture.one");
            bundle(&applications.join("Two.app"), "org.fixture.two");
            bundle(&applications.join("AnotherInstall.app"), "org.fixture.one");
            bundle(
                &applications.join("nested/Hidden.app"),
                "org.fixture.hidden",
            );
            symlink(applications.join("One.app"), applications.join("Alias.app")).unwrap();
            let report = discover_locations(
                Platform::MacOs,
                Locations {
                    bundles: vec![applications],
                    ..Locations::default()
                },
                DiscoveryLimits::default(),
            );
            assert_eq!(report.applications.len(), 3);
            assert!(report.incomplete); // Rejected symlink is explicit.
            assert!(report
                .diagnostics
                .iter()
                .any(|item| item.code == "unsafe_or_unreadable_directory"));
            for application in report.applications {
                assert_eq!(application.backup_authority, DiscoveryAuthority::NotGranted);
                assert!(application
                    .root_candidates
                    .iter()
                    .all(|root| root.requires_explicit_approval));
                assert_eq!(application.identity.architecture, Architecture::Unknown);
            }
        }

        #[test]
        fn desktop_precedence_masks_entries_without_guessing_install_or_save_roots() {
            let temp = temporary();
            let user = temp.path().join("user/applications");
            let system = temp.path().join("system/applications");
            fs::create_dir_all(&user).unwrap();
            fs::create_dir_all(&system).unwrap();
            fs::write(
                user.join("hidden.desktop"),
                "[Desktop Entry]\nHidden=true\n",
            )
            .unwrap();
            fs::write(
                system.join("hidden.desktop"),
                include_str!("../fixtures/sample.desktop"),
            )
            .unwrap();
            for id in ["org.fixture.one.desktop", "org.fixture.two.desktop"] {
                fs::write(system.join(id), include_str!("../fixtures/sample.desktop")).unwrap();
            }
            fs::create_dir_all(system.join("nested")).unwrap();
            fs::write(
                system.join("nested/ignored.desktop"),
                include_str!("../fixtures/sample.desktop"),
            )
            .unwrap();
            let report = discover_locations(
                Platform::Linux,
                Locations {
                    desktop: vec![user, system],
                    ..Locations::default()
                },
                DiscoveryLimits::default(),
            );
            assert_eq!(report.applications.len(), 2);
            for application in report.applications {
                assert!(application.identity.install.location.is_none());
                assert!(application.root_candidates.is_empty());
                assert_eq!(application.backup_authority, DiscoveryAuthority::NotGranted);
            }
        }

        #[test]
        fn steam_discovers_owned_install_roots_not_userdata_or_title_matches() {
            let temp = temporary();
            let first = temp.path().join("Steam");
            let second = temp.path().join("External");
            app(&first, 480, "InstallOne");
            app(&first, 481, "InstallTwo");
            app(&second, 480, "DifferentInstall");
            fs::create_dir_all(first.join("userdata/123/480")).unwrap();
            fs::write(
                first.join("userdata/123/480/private-save"),
                b"must not read",
            )
            .unwrap();
            fs::write(
                first.join("steamapps/libraryfolders.vdf"),
                format!(
                    r#""libraryfolders" {{ "0" {{ "path" "{}" }} "1" {{ "path" "{}" }} }}"#,
                    first.display(),
                    second.display()
                ),
            )
            .unwrap();
            let report = discover_locations(
                Platform::Linux,
                Locations {
                    steam: vec![first],
                    ..Locations::default()
                },
                DiscoveryLimits::default(),
            );
            assert_eq!(report.applications.len(), 3);
            assert!(!report.incomplete);
            for application in report.applications {
                assert!(matches!(
                    application.identity.product,
                    ProductIdentity::SteamAppId(_)
                ));
                assert_eq!(application.root_candidates.len(), 1);
                assert_eq!(
                    application.root_candidates[0].scope,
                    RootScope::Installation
                );
                assert_eq!(application.backup_authority, DiscoveryAuthority::NotGranted);
            }
        }

        #[test]
        fn steam_rejects_linked_install_and_mismatched_manifest_id() {
            let temp = temporary();
            let steam = temp.path().join("Steam");
            app(&steam, 480, "Real");
            symlink("Real", steam.join("steamapps/common/Linked")).unwrap();
            fs::write(
                steam.join("steamapps/appmanifest_481.acf"),
                r#""AppState" { "appid" "481" "installdir" "Linked" }"#,
            )
            .unwrap();
            fs::write(
                steam.join("steamapps/appmanifest_482.acf"),
                r#""AppState" { "appid" "999" "installdir" "Real" }"#,
            )
            .unwrap();
            symlink(
                "appmanifest_480.acf",
                steam.join("steamapps/appmanifest_483.acf"),
            )
            .unwrap();
            let report = discover_locations(
                Platform::Linux,
                Locations {
                    steam: vec![steam],
                    ..Locations::default()
                },
                DiscoveryLimits::default(),
            );
            assert_eq!(report.applications.len(), 1);
            assert!(report.incomplete);
            assert!(report
                .diagnostics
                .iter()
                .any(|item| item.code == "invalid_appmanifest"));
            assert!(report
                .diagnostics
                .iter()
                .any(|item| item.code == "metadata_read_failed"));
        }

        #[test]
        fn output_entry_and_metadata_budgets_are_enforced() {
            let temp = temporary();
            let root = temp.path().join("Applications");
            bundle(&root.join("One.app"), "org.fixture.one");
            bundle(&root.join("Two.app"), "org.fixture.two");
            let locations = || Locations {
                bundles: vec![root.clone()],
                ..Locations::default()
            };
            let limits = DiscoveryLimits {
                max_entries_per_directory: 1,
                max_total_entries: 1,
                ..DiscoveryLimits::default()
            };
            let report = discover_locations(Platform::MacOs, locations(), limits);
            assert_eq!(report.examined_entries, 1);
            assert!(report.incomplete);
            assert!(report.applications.len() <= 1);
            let limits = DiscoveryLimits {
                max_total_metadata_bytes: 1,
                max_diagnostics: 1,
                ..DiscoveryLimits::default()
            };
            let report = discover_locations(Platform::MacOs, locations(), limits);
            assert!(report.applications.is_empty());
            assert_eq!(report.diagnostics.len(), 1);
            assert!(report.omitted_diagnostics > 0);
        }
    }
}
