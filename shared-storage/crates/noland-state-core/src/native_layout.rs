// SPDX-License-Identifier: GPL-3.0-only
//! Authenticated native root-layout contract. Call only after manifest AEAD
//! authentication. Source path hints and host HOME never participate in mapping.
//! New code for the audited No Land e81238a7536aae201540956ce76981364fd36595 fork.
use std::{
    collections::{BTreeMap, BTreeSet},
    io::Write,
    path::{Component, Path, PathBuf},
};

use serde::{Deserialize, Serialize};
use unicode_normalization::UnicodeNormalization;

use crate::{BundleManifest, LogicalRoot, LogicalRootMap, Result, StateError};

pub const NATIVE_ROOT_LAYOUTS_KEY: &str = "quicksave_native_root_layouts";
pub const MAX_NATIVE_LAYOUT_ROOTS: usize = 64;
pub const MAX_NATIVE_LAYOUT_BYTES: usize = 512 * 1024;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum NativeLayoutPlatform {
    Macos,
    Windows,
    Linux,
}

impl NativeLayoutPlatform {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Macos => "macos",
            Self::Windows => "windows",
            Self::Linux => "linux",
        }
    }
    pub fn is_current(self) -> bool {
        matches!(
            (self, std::env::consts::OS),
            (Self::Macos, "macos") | (Self::Windows, "windows") | (Self::Linux, "linux")
        )
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum NativeLayoutRole {
    Installation,
    Save,
    Config,
    Runtime,
    Container,
    GroupContainer,
    Data,
    Manual,
    Installer,
}

impl NativeLayoutRole {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Installation => "installation",
            Self::Save => "save",
            Self::Config => "config",
            Self::Runtime => "runtime",
            Self::Container => "container",
            Self::GroupContainer => "group_container",
            Self::Data => "data",
            Self::Manual => "manual",
            Self::Installer => "installer",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum NativeLayoutSourceKind {
    Directory,
    File,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NativeRootLayout {
    pub logical_root: String,
    pub root_id: String,
    pub role: NativeLayoutRole,
    pub source_kind: NativeLayoutSourceKind,
    pub leaf_name: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NativeRootLayouts {
    pub version: u32,
    pub platform: NativeLayoutPlatform,
    pub app_id: String,
    pub software_instance_id: String,
    pub roots: Vec<NativeRootLayout>,
}

#[derive(Debug, Clone)]
pub struct NativeRestoreLayout {
    /// Native-private. Never expose source logical tokens/root IDs over IPC.
    pub roots: BTreeMap<String, PathBuf>,
    pub metadata: Option<NativeRootLayouts>,
}

/// Conservative portable basename, including Windows device/stream aliases.
/// Unicode normalization is used for collision checks, never to rename a leaf.
pub fn validate_native_layout_leaf(leaf: &str) -> Result<()> {
    let stem = leaf
        .split('.')
        .next()
        .unwrap_or("")
        .trim_end_matches(' ')
        .nfkc()
        .flat_map(char::to_uppercase)
        .collect::<String>();
    if leaf.is_empty()
        || leaf.len() > 255
        || leaf == "."
        || leaf == ".."
        || leaf.ends_with(['.', ' '])
        || leaf.starts_with(' ')
        || leaf
            .chars()
            .any(|c| c.is_control() || "/\\:\0<>\"|?*".contains(c))
        || matches!(
            stem.as_str(),
            "CON" | "PRN" | "AUX" | "NUL" | "CONIN$" | "CONOUT$"
        )
        || (stem.len() == 4
            && (stem.starts_with("COM") || stem.starts_with("LPT"))
            && matches!(stem.as_bytes()[3], b'1'..=b'9'))
        || collision_key(leaf).starts_with(".quicksave-")
        || collision_key(leaf).starts_with(".noland-")
    {
        return Err(StateError::UnsafePath(
            "invalid native root layout basename".into(),
        ));
    }
    Ok(())
}

fn collision_key(text: &str) -> String {
    text.nfkc()
        .flat_map(char::to_uppercase)
        .flat_map(char::to_lowercase)
        .collect()
}

fn canonical_logical(token: &str) -> Result<LogicalRoot> {
    let root = LogicalRoot::parse(token).ok_or_else(|| {
        StateError::Integrity("native root layout uses an unknown logical root".into())
    })?;
    if token.len() > 4096 || root.as_token() != token || token.chars().any(char::is_control) {
        return Err(StateError::Integrity(
            "noncanonical native root layout token".into(),
        ));
    }
    Ok(root)
}

fn selected_tokens(manifest: &BundleManifest) -> Result<BTreeSet<&str>> {
    let mut tokens = BTreeSet::new();
    for token in manifest
        .files
        .iter()
        .map(|file| file.logical_root.as_str())
        .chain(
            manifest
                .tombstones
                .iter()
                .map(|entry| entry.logical_root.as_str()),
        )
    {
        canonical_logical(token)?;
        tokens.insert(token);
        if tokens.len() > 128 {
            return Err(StateError::Integrity(
                "native restore logical-root bound exceeded".into(),
            ));
        }
    }
    // Full captures can authenticate an actually empty directory root without
    // inventing ManifestFile placeholders. A reduced exact-file selection does
    // not acquire those otherwise-unselected roots.
    if manifest.environment["quicksave_native_download"]["whole_bundle"].as_bool() != Some(false) {
        if let Some(captures) =
            manifest.environment["quicksave_native"]["full_scope"]["rootCaptures"].as_array()
        {
            if captures.len() > 128
                || manifest.environment["quicksave_native"]["full_scope"]["version"].as_u64()
                    != Some(1)
            {
                return Err(StateError::Integrity(
                    "native captured-root metadata bound exceeded".into(),
                ));
            }
            let mut captured_tokens = BTreeSet::new();
            for capture in captures {
                let token = capture["logicalRoot"].as_str().ok_or_else(|| {
                    StateError::Integrity("native root capture is missing its logical root".into())
                })?;
                let id = capture["id"]
                    .as_str()
                    .filter(|id| !id.is_empty() && id.len() <= 256)
                    .ok_or_else(|| {
                        StateError::Integrity("native root capture ID is invalid".into())
                    })?;
                let expected = format!(
                    "$NOLAND_CUSTOM_ROOT:quicksave-v1-{}-{}",
                    hex::encode(manifest.app.app_id.as_str()),
                    hex::encode(id)
                );
                canonical_logical(token)?;
                if expected != token || !captured_tokens.insert(token) {
                    return Err(StateError::Integrity(
                        "native captured-root identity is inconsistent or duplicated".into(),
                    ));
                }
                tokens.insert(token);
                if tokens.len() > 128 {
                    return Err(StateError::Integrity(
                        "native restore logical-root bound exceeded".into(),
                    ));
                }
            }
        }
    }
    Ok(tokens)
}

fn bounded_metadata(value: &serde_json::Value) -> Result<()> {
    struct Limit(usize);
    impl Write for Limit {
        fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
            self.0 = self
                .0
                .checked_add(bytes.len())
                .filter(|n| *n <= MAX_NATIVE_LAYOUT_BYTES)
                .ok_or_else(|| {
                    std::io::Error::other("native root layout metadata bound exceeded")
                })?;
            Ok(bytes.len())
        }
        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }
    serde_json::to_writer(&mut Limit(0), value)?;
    Ok(())
}

/// Strict parse and exact selected-root coverage. A present-but-invalid layout
/// never falls through to a legacy/source-path-hint mapping.
pub fn native_root_layouts(manifest: &BundleManifest) -> Result<Option<NativeRootLayouts>> {
    if !manifest.environment.is_object() && !manifest.environment.is_null() {
        return Err(StateError::Integrity(
            "native manifest environment is not an object".into(),
        ));
    }
    let Some(value) = manifest.environment.get(NATIVE_ROOT_LAYOUTS_KEY) else {
        return Ok(None);
    };
    bounded_metadata(value)?;
    let mut layouts: NativeRootLayouts = serde_json::from_value(value.clone())
        .map_err(|_| StateError::Integrity("invalid authenticated native root layout".into()))?;
    if layouts.version != 1
        || layouts.app_id != manifest.app.app_id.as_str()
        || layouts.app_id.is_empty()
        || layouts.app_id.len() > 512
        || layouts.app_id.chars().any(char::is_control)
        || layouts.software_instance_id.is_empty()
        || layouts.software_instance_id.len() > 256
        || layouts.software_instance_id.chars().any(char::is_control)
        || layouts.roots.is_empty()
        || layouts.roots.len() > MAX_NATIVE_LAYOUT_ROOTS
        || manifest.environment["quicksave_native"]["software_instance_id"]
            .as_str()
            .is_some_and(|id| id != layouts.software_instance_id)
        || manifest.environment["quicksave_native"]["platform"]
            .as_str()
            .is_some_and(|platform| platform != layouts.platform.as_str())
    {
        return Err(StateError::Integrity(
            "native root layout identity/version/bounds mismatch".into(),
        ));
    }
    let mut roots = BTreeSet::new();
    let mut ids = BTreeSet::new();
    for layout in &layouts.roots {
        canonical_logical(&layout.logical_root)?;
        validate_native_layout_leaf(&layout.leaf_name)?;
        if layout.root_id.is_empty()
            || layout.root_id.len() > 256
            || layout
                .root_id
                .chars()
                .any(|c| c.is_control() || "/\\\0".contains(c))
            || !roots.insert(layout.logical_root.as_str())
            || !ids.insert(layout.root_id.as_str())
        {
            return Err(StateError::Integrity(
                "duplicate or invalid native layout root identity".into(),
            ));
        }
        let expected_token = format!(
            "$NOLAND_CUSTOM_ROOT:quicksave-v1-{}-{}",
            hex::encode(layouts.app_id.as_bytes()),
            hex::encode(layout.root_id.as_bytes())
        );
        if layout.logical_root != expected_token {
            return Err(StateError::Integrity(
                "native layout does not match its original app/root identity".into(),
            ));
        }
        if layout.role == NativeLayoutRole::Installation
            && !manifest
                .files
                .iter()
                .any(|file| file.logical_root == layout.logical_root)
        {
            return Err(StateError::Integrity(
                "an empty installation root cannot become a placeholder application".into(),
            ));
        }
        if layout.source_kind == NativeLayoutSourceKind::File
            && (manifest
                .files
                .iter()
                .filter(|file| file.logical_root == layout.logical_root)
                .any(|file| file.relative_path != layout.leaf_name || file.file_type != "file")
                || manifest
                    .tombstones
                    .iter()
                    .filter(|entry| entry.logical_root == layout.logical_root)
                    .any(|entry| entry.relative_path != layout.leaf_name))
        {
            return Err(StateError::Integrity(
                "native single-file layout widened its captured leaf".into(),
            ));
        }
    }
    if roots != selected_tokens(manifest)? {
        return Err(StateError::Integrity(
            "native root layout omits or adds selected logical roots".into(),
        ));
    }
    drop(roots);
    drop(ids);
    layouts
        .roots
        .sort_by(|a, b| a.logical_root.cmp(&b.logical_root));
    Ok(Some(layouts))
}

/// Use only after `native_root_layouts` validated the ORIGINAL authenticated
/// manifest, and after native exact-key filtering. Preserve selected layout rows;
/// never invent roots from source_path_hint or a UI mapping.
pub fn project_native_root_layouts(manifest: &mut BundleManifest) -> Result<()> {
    let Some(value) = manifest.environment.get(NATIVE_ROOT_LAYOUTS_KEY) else {
        return Ok(());
    };
    bounded_metadata(value)?;
    let mut layouts: NativeRootLayouts = serde_json::from_value(value.clone())
        .map_err(|_| StateError::Integrity("invalid native layout selection projection".into()))?;
    let tokens = selected_tokens(manifest)?;
    layouts
        .roots
        .retain(|root| tokens.contains(root.logical_root.as_str()));
    drop(tokens);
    manifest.environment[NATIVE_ROOT_LAYOUTS_KEY] = serde_json::to_value(layouts)?;
    native_root_layouts(manifest)?;
    Ok(())
}

pub fn native_restore_layout(
    manifest: &BundleManifest,
    destination: &Path,
) -> Result<NativeRestoreLayout> {
    if !destination.is_absolute()
        || destination
            .components()
            .any(|part| matches!(part, Component::ParentDir | Component::CurDir))
        || destination
            .to_str()
            .is_none_or(|text| text.len() > 32768 || text.chars().any(char::is_control))
    {
        return Err(StateError::UnsafePath(
            "invalid selected native restore destination".into(),
        ));
    }
    let metadata = native_root_layouts(manifest)?;
    let roots = if let Some(layouts) = &metadata {
        native_root_layout_mappings(layouts, destination)?
    } else {
        let mut roots = BTreeMap::new();
        for token in selected_tokens(manifest)? {
            let hash = blake3::hash(token.as_bytes()).to_hex().to_string();
            roots.insert(
                token.to_owned(),
                destination.join(format!("root-{}", &hash[..16])),
            );
        }
        roots
    };
    validate_native_root_mappings(destination, &roots)?;
    Ok(NativeRestoreLayout { roots, metadata })
}

/// Rebuilds the SAME deterministic frame when checking a device-MAC-bound
/// preview after restart. This does not authenticate a manifest or grant access.
pub fn native_root_layout_mappings(
    layouts: &NativeRootLayouts,
    destination: &Path,
) -> Result<BTreeMap<String, PathBuf>> {
    if layouts.version != 1 || layouts.roots.len() > MAX_NATIVE_LAYOUT_ROOTS {
        return Err(StateError::Integrity(
            "invalid native root-layout frame".into(),
        ));
    }
    let mut roots = BTreeMap::new();
    for layout in &layouts.roots {
        validate_native_layout_leaf(&layout.leaf_name)?;
        let mapped = if layout.role == NativeLayoutRole::Installation
            && layout.source_kind == NativeLayoutSourceKind::Directory
        {
            destination.join(&layout.leaf_name)
        } else {
            let mut hash = blake3::Hasher::new();
            hash.update(b"QuickSave native root placement v1\0");
            hash.update(&(layouts.software_instance_id.len() as u64).to_le_bytes());
            hash.update(layouts.software_instance_id.as_bytes());
            hash.update(layout.logical_root.as_bytes());
            let guard = hash.finalize().to_hex().to_string();
            let parent = destination
                .join(layout.role.as_str())
                .join(format!("root-{guard}"));
            match layout.source_kind {
                NativeLayoutSourceKind::Directory => parent.join(&layout.leaf_name),
                // Single-file capture entries already include the real leaf.
                NativeLayoutSourceKind::File => parent,
            }
        };
        if roots.insert(layout.logical_root.clone(), mapped).is_some() {
            return Err(StateError::Integrity(
                "duplicate native root-layout frame token".into(),
            ));
        }
    }
    validate_native_root_mappings(destination, &roots)?;
    Ok(roots)
}

pub fn validate_native_root_mappings(
    destination: &Path,
    roots: &BTreeMap<String, PathBuf>,
) -> Result<()> {
    if roots.len() > 128 {
        return Err(StateError::Integrity(
            "native mapping root bound exceeded".into(),
        ));
    }
    let mut destinations = Vec::new();
    for (token, path) in roots {
        canonical_logical(token)?;
        let relative = path.strip_prefix(destination).map_err(|_| {
            StateError::UnsafePath("native logical mapping escapes selected destination".into())
        })?;
        if relative.as_os_str().is_empty() {
            return Err(StateError::UnsafePath(
                "native mapping cannot overwrite its selected parent".into(),
            ));
        }
        let mut components = Vec::new();
        for component in relative.components() {
            let Component::Normal(leaf) = component else {
                return Err(StateError::UnsafePath(
                    "noncanonical native root mapping".into(),
                ));
            };
            let leaf = leaf
                .to_str()
                .ok_or_else(|| StateError::UnsafePath("non-UTF8 native mapping".into()))?;
            validate_native_layout_leaf(leaf)?;
            components.push(collision_key(leaf));
        }
        if destinations.iter().any(|prior: &Vec<String>| {
            prior.starts_with(&components) || components.starts_with(prior)
        }) {
            return Err(StateError::Conflict(
                "native installation/root leaf collision or nested root overlap".into(),
            ));
        }
        destinations.push(components);
    }
    Ok(())
}

/// Exact typed adapter for both native preview and the original pack pipeline.
pub fn logical_root_map(mappings: &BTreeMap<String, PathBuf>) -> Result<LogicalRootMap> {
    let mut roots = LogicalRootMap::default();
    for (token, mapped) in mappings {
        let mapped = mapped.clone();
        match canonical_logical(token)? {
            LogicalRoot::Home => roots.home = Some(mapped),
            LogicalRoot::XdgConfigHome => roots.xdg_config_home = Some(mapped),
            LogicalRoot::XdgDataHome => roots.xdg_data_home = Some(mapped),
            LogicalRoot::XdgCacheHome => roots.xdg_cache_home = Some(mapped),
            LogicalRoot::Documents => roots.documents = Some(mapped),
            LogicalRoot::Downloads => roots.downloads = Some(mapped),
            LogicalRoot::Games => roots.games = Some(mapped),
            LogicalRoot::SteamRoot => roots.steam_root = Some(mapped),
            LogicalRoot::SteamUserdata => roots.steam_userdata = Some(mapped),
            LogicalRoot::SteamLibrary { id } => {
                roots.steam_libraries.insert(id, mapped);
            }
            LogicalRoot::ProtonPrefix { steam_app_id } => {
                roots.proton_prefixes.insert(steam_app_id, mapped);
            }
            LogicalRoot::WinePrefix { id } => {
                roots.wine_prefixes.insert(id, mapped);
            }
            LogicalRoot::BottlesPrefix { id } => {
                roots.bottles_prefixes.insert(id, mapped);
            }
            LogicalRoot::AppInstallRoot { app_id } => {
                roots.app_install_roots.insert(app_id.0, mapped);
            }
            LogicalRoot::NolandCustomRoot { id } => {
                roots.custom_roots.insert(id, mapped);
            }
        }
    }
    Ok(roots)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{AppId, BackupMode, ManifestApp, ManifestFile, ManifestSource};
    use serde_json::json;

    fn token(root: &str) -> String {
        format!(
            "$NOLAND_CUSTOM_ROOT:quicksave-v1-{}-{}",
            hex::encode(b"quicksave:layout-fixture"),
            hex::encode(root)
        )
    }

    fn manifest() -> BundleManifest {
        let mut manifest = BundleManifest::new(
            ManifestApp {
                app_id: AppId("quicksave:layout-fixture".into()),
                display_name: "Display name is not a package basename".into(),
                aliases: vec![],
                desktop_entry_id: None,
                steam_app_id: None,
                launcher: None,
                canonical_executable: Some(PathBuf::from("/original/not-authority")),
                icon_path: None,
            },
            ManifestSource {
                instance_id: uuid::Uuid::new_v4(),
                image_id: "isolated".into(),
                captured_at: chrono::Utc::now(),
            },
            BackupMode::CompleteApplication,
        );
        manifest.files = ["installation","saves"].iter().map(|root|
            serde_json::from_value::<ManifestFile>(json!({
                "logical_root":token(root),"relative_path":"captured.dat","file_type":"file",
                "size":0,"file_hash":format!("blake3:{}",blake3::hash(b"").to_hex()),
                "source_path_hint":"/absolute/source/is/not/authority",
                "persistence_class":"PERSISTENT_STATE","semantic_role":"USER_STATE","association_confidence":1.0,
            })).unwrap()).collect();
        manifest.environment[NATIVE_ROOT_LAYOUTS_KEY] = json!({
            "version":1,"platform":"macos","app_id":manifest.app.app_id.as_str(),
            "software_instance_id":"synthetic-instance","roots":[
                {"logical_root":token("installation"),"root_id":"installation","role":"installation",
                    "source_kind":"directory","leaf_name":"Actual Application.app"},
                {"logical_root":token("saves"),"root_id":"saves","role":"save",
                    "source_kind":"directory","leaf_name":"Original Saves"},
            ],
        });
        manifest
    }

    #[test]
    fn exact_basename_and_role_guard_mapping_never_uses_source_absolute_hints() {
        let manifest = manifest();
        let destination = std::env::temp_dir().join("layout-mapping-only-no-fs-access");
        let layout = native_restore_layout(&manifest, &destination).unwrap();
        assert_eq!(
            layout.roots[&token("installation")],
            destination.join("Actual Application.app")
        );
        assert!(layout.roots[&token("saves")].starts_with(destination.join("save")));
        assert!(layout
            .roots
            .values()
            .all(|path| path.starts_with(&destination)));
        let typed = logical_root_map(&layout.roots).unwrap();
        assert_eq!(
            typed
                .resolve(&LogicalRoot::parse(&token("installation")).unwrap())
                .unwrap(),
            destination.join("Actual Application.app")
        );
    }

    #[test]
    fn invalid_layout_never_falls_back_or_accepts_missing_roots_or_leaf_aliases() {
        let base = manifest();
        let destination = std::env::temp_dir().join("layout-pure-validation");
        for leaf in [
            "..",
            "../outside",
            "/absolute",
            r"bad\leaf",
            "stream:alias",
            "NUL",
            "COM1.txt",
            "COM¹",
            "trailing.",
        ] {
            let mut manifest = base.clone();
            manifest.environment[NATIVE_ROOT_LAYOUTS_KEY]["roots"][0]["leaf_name"] = json!(leaf);
            assert!(
                native_restore_layout(&manifest, &destination).is_err(),
                "{leaf}"
            );
        }
        let mut missing = base.clone();
        missing.environment[NATIVE_ROOT_LAYOUTS_KEY]["roots"]
            .as_array_mut()
            .unwrap()
            .pop();
        assert!(native_restore_layout(&missing, &destination).is_err());
        let mut injected = base.clone();
        injected.environment[NATIVE_ROOT_LAYOUTS_KEY]["roots"][0]["source_path"] =
            json!("/outside");
        assert!(native_restore_layout(&injected, &destination).is_err());
        let mut collision = base;
        collision.environment[NATIVE_ROOT_LAYOUTS_KEY]["roots"][1]["role"] = json!("installation");
        collision.environment[NATIVE_ROOT_LAYOUTS_KEY]["roots"][1]["leaf_name"] =
            json!("ACTUAL APPLICATION.APP");
        assert!(native_restore_layout(&collision, &destination).is_err());
    }

    #[test]
    fn native_selection_projects_only_validated_root_rows_and_legacy_remains_files_only() {
        let mut manifest = manifest();
        native_root_layouts(&manifest).unwrap();
        let destination = std::env::temp_dir().join("layout-selection-only");
        let before = native_restore_layout(&manifest, &destination).unwrap();
        manifest
            .files
            .retain(|file| file.logical_root == token("installation"));
        project_native_root_layouts(&mut manifest).unwrap();
        let selected = native_restore_layout(&manifest, &destination).unwrap();
        assert_eq!(selected.roots.len(), 1);
        assert_eq!(
            selected.roots[&token("installation")],
            before.roots[&token("installation")]
        );
        manifest
            .environment
            .as_object_mut()
            .unwrap()
            .remove(NATIVE_ROOT_LAYOUTS_KEY);
        let legacy = native_restore_layout(&manifest, &destination).unwrap();
        assert!(legacy.metadata.is_none());
        assert!(legacy.roots[&token("installation")]
            .file_name()
            .unwrap()
            .to_str()
            .unwrap()
            .starts_with("root-"));
    }
}
