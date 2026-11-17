// SPDX-License-Identifier: GPL-3.0-only
//! Pure integration profiles. None of these types authorizes or performs I/O.

use anyhow::{bail, ensure, Result};
use serde::{Deserialize, Serialize};
use std::path::PathBuf;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Platform {
    MacOs,
    Windows,
    Linux,
    Unknown,
}

impl Platform {
    pub const fn current() -> Self {
        if cfg!(target_os = "macos") {
            Self::MacOs
        } else if cfg!(target_os = "windows") {
            Self::Windows
        } else if cfg!(target_os = "linux") {
            Self::Linux
        } else {
            Self::Unknown
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Architecture {
    Unknown,
    X86,
    X86_64,
    Arm64,
    Universal,
}

/// Product keys are launcher/bundle identities, never display names.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(tag = "kind", content = "id", rename_all = "snake_case")]
pub enum ProductIdentity {
    MacBundleIdentifier(String),
    SteamAppId(u32),
    DesktopEntryId(String),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum InstallKind {
    MacApplicationBundle,
    SteamApplication,
    DesktopLauncher,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct InstallIdentity {
    pub kind: InstallKind,
    /// A .desktop file does not prove an installation directory; this is None
    /// for those entries. Executable paths are never guessed from Exec or names.
    pub location: Option<PathBuf>,
    pub metadata_path: PathBuf,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AppIdentity {
    pub product: ProductIdentity,
    pub install: InstallIdentity,
    /// Discovery host, not an inference about a Steam game's executable format.
    pub platform: Platform,
    /// Unknown until executable metadata is actually inspected.
    pub architecture: Architecture,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RootScope {
    Installation,
    Save,
    Config,
    Cache,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RootAnchor {
    Installation,
    ExplicitSaveDirectory,
    ExplicitConfigDirectory,
    ExplicitCacheDirectory,
}

/// Portable relative paths deliberately use a strict common subset. A profile
/// cannot escape an explicitly approved anchor or supply another drive/stream.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(try_from = "String", into = "String")]
pub struct ProfilePath(String);

impl ProfilePath {
    pub fn new(value: impl Into<String>) -> Result<Self> {
        let value = value.into();
        ensure!(
            !value.is_empty() && value.len() <= 4096,
            "invalid profile path length"
        );
        ensure!(
            !value.contains('\\') && !value.starts_with('/'),
            "profile paths must be relative and use forward slashes"
        );
        for segment in value.split('/') {
            validate_segment(segment)?;
        }
        Ok(Self(value))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl TryFrom<String> for ProfilePath {
    type Error = anyhow::Error;

    fn try_from(value: String) -> Result<Self> {
        Self::new(value)
    }
}

impl From<ProfilePath> for String {
    fn from(value: ProfilePath) -> Self {
        value.0
    }
}

pub(crate) fn validate_segment(segment: &str) -> Result<()> {
    ensure!(
        !segment.is_empty() && segment.len() <= 255 && segment != "." && segment != "..",
        "invalid path component"
    );
    ensure!(
        !segment.ends_with([' ', '.'])
            && !segment
                .chars()
                .any(|c| c.is_control() || r#"\/:*?"<>|"#.contains(c)),
        "unsafe or non-portable path component"
    );
    let stem = segment
        .split('.')
        .next()
        .unwrap_or("")
        .trim_end_matches(' ')
        .to_ascii_uppercase();
    let reserved = matches!(
        stem.as_str(),
        "CON" | "PRN" | "AUX" | "NUL" | "CONIN$" | "CONOUT$"
    ) || stem
        .strip_prefix("COM")
        .or_else(|| stem.strip_prefix("LPT"))
        .is_some_and(|n| {
            matches!(
                n,
                "1" | "2" | "3" | "4" | "5" | "6" | "7" | "8" | "9" | "¹" | "²" | "³"
            )
        });
    ensure!(!reserved, "reserved device path component");
    Ok(())
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(try_from = "RootMappingWire", into = "RootMappingWire")]
pub struct RootMapping {
    scope: RootScope,
    anchor: RootAnchor,
    /// None means the explicitly approved anchor itself, not an implicit home.
    relative_path: Option<ProfilePath>,
    optional: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct RootMappingWire {
    scope: RootScope,
    anchor: RootAnchor,
    relative_path: Option<ProfilePath>,
    optional: bool,
}

impl RootMapping {
    pub fn new(
        scope: RootScope,
        anchor: RootAnchor,
        relative_path: Option<ProfilePath>,
        optional: bool,
    ) -> Result<Self> {
        let expected = match scope {
            RootScope::Installation => RootAnchor::Installation,
            RootScope::Save => RootAnchor::ExplicitSaveDirectory,
            RootScope::Config => RootAnchor::ExplicitConfigDirectory,
            RootScope::Cache => RootAnchor::ExplicitCacheDirectory,
        };
        ensure!(
            anchor == expected,
            "root scope does not match its approved anchor"
        );
        ensure!(
            scope != RootScope::Cache || optional,
            "cache mappings must be optional"
        );
        Ok(Self {
            scope,
            anchor,
            relative_path,
            optional,
        })
    }

    pub fn scope(&self) -> RootScope {
        self.scope
    }

    pub fn relative_path(&self) -> Option<&ProfilePath> {
        self.relative_path.as_ref()
    }
}

impl TryFrom<RootMappingWire> for RootMapping {
    type Error = anyhow::Error;

    fn try_from(value: RootMappingWire) -> Result<Self> {
        Self::new(
            value.scope,
            value.anchor,
            value.relative_path,
            value.optional,
        )
    }
}

impl From<RootMapping> for RootMappingWire {
    fn from(value: RootMapping) -> Self {
        Self {
            scope: value.scope,
            anchor: value.anchor,
            relative_path: value.relative_path,
            optional: value.optional,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Prerequisite {
    ExplicitApprovalForEveryRoot,
    NativePinnedRootValidation,
    CloseApplicationOrAcceptStableFileLimitations,
    ManualSaveMapping,
    ManualConfigMapping,
    VerifyDataFormatCompatibility,
    MatchingPlatformAndArchitectureForExecutables,
    ExternalRecoveryKeyFile,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Consistency {
    /// A requirement of the engine, NOT a guarantee supplied by discovery.
    ValidatedStableFilesNotApplicationAtomic,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum GrantPolicy {
    ExplicitApprovalPerRoot,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SaveCompatibility {
    NotDeclared,
    /// Must be selected only after a game/data-specific format review.
    PortableDataRequiresValidation,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum ProfileSelector {
    SteamLauncherAppId,
    UniversalUnknownManualFolder,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AppProfile {
    pub id: String,
    pub selector: ProfileSelector,
    pub supported_platforms: Vec<Platform>,
    pub root_mappings: Vec<RootMapping>,
    pub prerequisites: Vec<Prerequisite>,
    pub consistency: Consistency,
    pub grant_policy: GrantPolicy,
    pub saves: SaveCompatibility,
    pub automatic_app_backup_supported: bool,
}

/// Templates describe unresolved, separately approved mappings. They are not a
/// database of game save locations or a declaration that every app is supported.
pub fn static_profiles() -> Vec<AppProfile> {
    let platforms = vec![Platform::MacOs, Platform::Windows, Platform::Linux];
    let prerequisites = vec![
        Prerequisite::ExplicitApprovalForEveryRoot,
        Prerequisite::NativePinnedRootValidation,
        Prerequisite::CloseApplicationOrAcceptStableFileLimitations,
        Prerequisite::ManualSaveMapping,
        Prerequisite::ManualConfigMapping,
        Prerequisite::VerifyDataFormatCompatibility,
        Prerequisite::MatchingPlatformAndArchitectureForExecutables,
        Prerequisite::ExternalRecoveryKeyFile,
    ];
    let mappings = || {
        [
            (RootScope::Installation, RootAnchor::Installation, false),
            (RootScope::Save, RootAnchor::ExplicitSaveDirectory, false),
            (
                RootScope::Config,
                RootAnchor::ExplicitConfigDirectory,
                false,
            ),
            (RootScope::Cache, RootAnchor::ExplicitCacheDirectory, true),
        ]
        .into_iter()
        .map(|(scope, anchor, optional)| {
            // Fixed validated constants; no external path input.
            RootMapping {
                scope,
                anchor,
                relative_path: None,
                optional,
            }
        })
        .collect()
    };
    vec![
        AppProfile {
            id: "steam-manual-data-v1".into(),
            selector: ProfileSelector::SteamLauncherAppId,
            supported_platforms: platforms.clone(),
            root_mappings: mappings(),
            prerequisites: prerequisites.clone(),
            consistency: Consistency::ValidatedStableFilesNotApplicationAtomic,
            grant_policy: GrantPolicy::ExplicitApprovalPerRoot,
            saves: SaveCompatibility::NotDeclared,
            automatic_app_backup_supported: false,
        },
        AppProfile {
            id: "unknown-manual-folder-v1".into(),
            selector: ProfileSelector::UniversalUnknownManualFolder,
            supported_platforms: platforms,
            root_mappings: vec![],
            prerequisites,
            consistency: Consistency::ValidatedStableFilesNotApplicationAtomic,
            grant_policy: GrantPolicy::ExplicitApprovalPerRoot,
            saves: SaveCompatibility::NotDeclared,
            automatic_app_backup_supported: false,
        },
    ]
}

/// A pure compatibility check, not restore permission. Even a successful check
/// still requires explicit approval, pinned-path validation and format review.
pub fn check_restore_compatibility(
    scope: RootScope,
    source_platform: Platform,
    source_architecture: Architecture,
    target_platform: Platform,
    target_architecture: Architecture,
    saves: SaveCompatibility,
) -> Result<Vec<Prerequisite>> {
    ensure!(
        source_platform != Platform::Unknown && target_platform != Platform::Unknown,
        "unknown platform requires manual review"
    );
    let mut prerequisites = vec![
        Prerequisite::ExplicitApprovalForEveryRoot,
        Prerequisite::NativePinnedRootValidation,
    ];
    match scope {
        RootScope::Installation => {
            ensure!(
                source_platform == target_platform,
                "cross-OS executable restore is unsupported"
            );
            ensure!(
                source_architecture != Architecture::Unknown
                    && target_architecture != Architecture::Unknown
                    && source_architecture == target_architecture,
                "executable architecture must be known and match"
            );
            prerequisites.push(Prerequisite::MatchingPlatformAndArchitectureForExecutables);
        }
        RootScope::Save => {
            if source_platform != target_platform {
                ensure!(
                    saves == SaveCompatibility::PortableDataRequiresValidation,
                    "cross-OS saves require a declared, reviewed portable data format"
                );
            }
            prerequisites.push(Prerequisite::VerifyDataFormatCompatibility);
        }
        RootScope::Config if source_platform != target_platform => {
            bail!("cross-OS config restore is unsupported without a specific migration")
        }
        RootScope::Cache => bail!("cache restore is not supported"),
        RootScope::Config => prerequisites.push(Prerequisite::VerifyDataFormatCompatibility),
    }
    Ok(prerequisites)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rejects_unsafe_profile_paths_including_deserialization() {
        for unsafe_path in [
            "",
            "/",
            "/etc",
            "..",
            "../save",
            "a/../b",
            "./a",
            "a//b",
            "a/",
            r"C:\Games",
            r"\\server\share",
            r"a\b",
            "C:save",
            "a:stream",
            "a\0b",
            "name.",
            "name ",
            "a\nb",
            "CON",
            "aux.json",
            "LPT9",
            "COM1.txt",
            "CONIN$",
            "CONOUT$",
            "con .txt",
            "COM¹",
            "LPT².log",
        ] {
            assert!(ProfilePath::new(unsafe_path).is_err(), "{unsafe_path:?}");
            let json = serde_json::to_string(unsafe_path).unwrap();
            assert!(
                serde_json::from_str::<ProfilePath>(&json).is_err(),
                "{unsafe_path:?}"
            );
        }
        assert_eq!(
            ProfilePath::new("saves/slot 1.dat").unwrap().as_str(),
            "saves/slot 1.dat"
        );
    }

    #[test]
    fn mappings_cannot_cross_scope_or_make_cache_mandatory() {
        assert!(RootMapping::new(RootScope::Save, RootAnchor::Installation, None, false).is_err());
        assert!(RootMapping::new(
            RootScope::Cache,
            RootAnchor::ExplicitCacheDirectory,
            None,
            false
        )
        .is_err());
        let malicious = serde_json::json!({
            "scope": "save", "anchor": "installation", "relative_path": null, "optional": false
        });
        assert!(serde_json::from_value::<RootMapping>(malicious).is_err());
    }

    #[test]
    fn portable_saves_do_not_make_executables_portable() {
        let saves = SaveCompatibility::PortableDataRequiresValidation;
        let requirements = check_restore_compatibility(
            RootScope::Save,
            Platform::Windows,
            Architecture::X86_64,
            Platform::Linux,
            Architecture::Arm64,
            saves,
        )
        .unwrap();
        assert!(requirements.contains(&Prerequisite::ExplicitApprovalForEveryRoot));
        assert!(requirements.contains(&Prerequisite::VerifyDataFormatCompatibility));
        assert!(check_restore_compatibility(
            RootScope::Installation,
            Platform::Windows,
            Architecture::X86_64,
            Platform::Linux,
            Architecture::X86_64,
            saves,
        )
        .is_err());
        assert!(check_restore_compatibility(
            RootScope::Installation,
            Platform::MacOs,
            Architecture::Unknown,
            Platform::MacOs,
            Architecture::Unknown,
            saves,
        )
        .is_err());
        assert!(check_restore_compatibility(
            RootScope::Save,
            Platform::Windows,
            Architecture::X86_64,
            Platform::Linux,
            Architecture::X86_64,
            SaveCompatibility::NotDeclared,
        )
        .is_err());
    }

    #[test]
    fn templates_never_grant_complete_backup_support() {
        for profile in static_profiles() {
            assert!(!profile.automatic_app_backup_supported);
            assert_eq!(profile.grant_policy, GrantPolicy::ExplicitApprovalPerRoot);
            assert_eq!(profile.saves, SaveCompatibility::NotDeclared);
        }
    }

    #[test]
    fn each_profile_and_platform_has_conservative_restore_compatibility() {
        for profile in static_profiles() {
            for source in &profile.supported_platforms {
                for target in &profile.supported_platforms {
                    let saves = check_restore_compatibility(
                        RootScope::Save,
                        *source,
                        Architecture::Unknown,
                        *target,
                        Architecture::Unknown,
                        profile.saves,
                    );
                    assert_eq!(saves.is_ok(), source == target, "{}", profile.id);
                    let installation = check_restore_compatibility(
                        RootScope::Installation,
                        *source,
                        Architecture::X86_64,
                        *target,
                        Architecture::X86_64,
                        profile.saves,
                    );
                    assert_eq!(installation.is_ok(), source == target, "{}", profile.id);
                    let config = check_restore_compatibility(
                        RootScope::Config,
                        *source,
                        Architecture::Unknown,
                        *target,
                        Architecture::Unknown,
                        profile.saves,
                    );
                    assert_eq!(config.is_ok(), source == target, "{}", profile.id);
                }
            }
        }
    }
}
