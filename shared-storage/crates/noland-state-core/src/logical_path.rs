use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};
use unicode_normalization::UnicodeNormalization;

use crate::error::{Result, StateError};
use crate::identity::AppId;

/// Logical roots used in committed manifests. Never commit only raw absolute paths.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum LogicalRoot {
    Home,
    XdgConfigHome,
    XdgDataHome,
    XdgCacheHome,
    Documents,
    Downloads,
    Games,
    SteamRoot,
    SteamLibrary { id: String },
    SteamUserdata,
    ProtonPrefix { steam_app_id: u32 },
    WinePrefix { id: String },
    BottlesPrefix { id: String },
    AppInstallRoot { app_id: AppId },
    NolandCustomRoot { id: String },
}

impl LogicalRoot {
    pub fn as_token(&self) -> String {
        match self {
            Self::Home => "$HOME".into(),
            Self::XdgConfigHome => "$XDG_CONFIG_HOME".into(),
            Self::XdgDataHome => "$XDG_DATA_HOME".into(),
            Self::XdgCacheHome => "$XDG_CACHE_HOME".into(),
            Self::Documents => "$DOCUMENTS".into(),
            Self::Downloads => "$DOWNLOADS".into(),
            Self::Games => "$GAMES".into(),
            Self::SteamRoot => "$STEAM_ROOT".into(),
            Self::SteamLibrary { id } => format!("$STEAM_LIBRARY:{id}"),
            Self::SteamUserdata => "$STEAM_USERDATA".into(),
            Self::ProtonPrefix { steam_app_id } => format!("$PROTON_PREFIX:{steam_app_id}"),
            Self::WinePrefix { id } => format!("$WINE_PREFIX:{id}"),
            Self::BottlesPrefix { id } => format!("$BOTTLES_PREFIX:{id}"),
            Self::AppInstallRoot { app_id } => format!("$APP_INSTALL_ROOT:{}", app_id.as_str()),
            Self::NolandCustomRoot { id } => format!("$NOLAND_CUSTOM_ROOT:{id}"),
        }
    }

    pub fn parse(token: &str) -> Option<Self> {
        let token = token.trim();
        if let Some(rest) = token.strip_prefix("$STEAM_LIBRARY:") {
            return Some(Self::SteamLibrary { id: rest.into() });
        }
        if let Some(rest) = token.strip_prefix("$PROTON_PREFIX:") {
            return rest
                .parse()
                .ok()
                .map(|steam_app_id| Self::ProtonPrefix { steam_app_id });
        }
        if let Some(rest) = token.strip_prefix("$WINE_PREFIX:") {
            return Some(Self::WinePrefix { id: rest.into() });
        }
        if let Some(rest) = token.strip_prefix("$BOTTLES_PREFIX:") {
            return Some(Self::BottlesPrefix { id: rest.into() });
        }
        if let Some(rest) = token.strip_prefix("$APP_INSTALL_ROOT:") {
            return Some(Self::AppInstallRoot {
                app_id: AppId(rest.into()),
            });
        }
        if let Some(rest) = token.strip_prefix("$NOLAND_CUSTOM_ROOT:") {
            return Some(Self::NolandCustomRoot { id: rest.into() });
        }
        Some(match token {
            "$HOME" => Self::Home,
            "$XDG_CONFIG_HOME" => Self::XdgConfigHome,
            "$XDG_DATA_HOME" => Self::XdgDataHome,
            "$XDG_CACHE_HOME" => Self::XdgCacheHome,
            "$DOCUMENTS" => Self::Documents,
            "$DOWNLOADS" => Self::Downloads,
            "$GAMES" => Self::Games,
            "$STEAM_ROOT" => Self::SteamRoot,
            "$STEAM_USERDATA" => Self::SteamUserdata,
            _ => return None,
        })
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LogicalPath {
    pub logical_root: LogicalRoot,
    pub relative_path: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub source_path_hint: Option<String>,
}

impl LogicalPath {
    pub fn new(logical_root: LogicalRoot, relative_path: impl Into<String>) -> Self {
        Self {
            logical_root,
            relative_path: normalize_relative(relative_path.into()),
            source_path_hint: None,
        }
    }

    /// Native filesystem names are exact signed data, not legacy portable path
    /// input. In particular, Unix backslashes must never become separators.
    /// New GPL-3.0-only integration for the audited e81238a source fork.
    pub fn new_native(logical_root: LogicalRoot, relative_path: impl Into<String>) -> Result<Self> {
        let relative_path = relative_path.into();
        validate_native_relative_path(&relative_path)?;
        Ok(Self {
            logical_root,
            relative_path,
            source_path_hint: None,
        })
    }

    pub fn with_hint(mut self, hint: impl Into<String>) -> Self {
        self.source_path_hint = Some(hint.into());
        self
    }
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct LogicalRootMap {
    pub home: Option<PathBuf>,
    pub xdg_config_home: Option<PathBuf>,
    pub xdg_data_home: Option<PathBuf>,
    pub xdg_cache_home: Option<PathBuf>,
    pub documents: Option<PathBuf>,
    pub downloads: Option<PathBuf>,
    pub games: Option<PathBuf>,
    pub steam_root: Option<PathBuf>,
    pub steam_userdata: Option<PathBuf>,
    pub steam_libraries: BTreeMap<String, PathBuf>,
    pub proton_prefixes: BTreeMap<u32, PathBuf>,
    pub wine_prefixes: BTreeMap<String, PathBuf>,
    pub bottles_prefixes: BTreeMap<String, PathBuf>,
    pub app_install_roots: BTreeMap<String, PathBuf>,
    pub custom_roots: BTreeMap<String, PathBuf>,
}

impl LogicalRootMap {
    pub fn from_home(home: impl Into<PathBuf>) -> Self {
        let home = home.into();
        Self {
            xdg_config_home: Some(home.join(".config")),
            xdg_data_home: Some(home.join(".local/share")),
            xdg_cache_home: Some(home.join(".cache")),
            documents: Some(home.join("Documents")),
            downloads: Some(home.join("Downloads")),
            games: Some(home.join("Games")),
            steam_root: Some(home.join(".steam/steam")),
            steam_userdata: Some(home.join(".steam/steam/userdata")),
            home: Some(home),
            ..Self::default()
        }
    }

    pub fn resolve(&self, root: &LogicalRoot) -> Option<PathBuf> {
        match root {
            LogicalRoot::Home => self.home.clone(),
            LogicalRoot::XdgConfigHome => self.xdg_config_home.clone(),
            LogicalRoot::XdgDataHome => self.xdg_data_home.clone(),
            LogicalRoot::XdgCacheHome => self.xdg_cache_home.clone(),
            LogicalRoot::Documents => self.documents.clone(),
            LogicalRoot::Downloads => self.downloads.clone(),
            LogicalRoot::Games => self.games.clone(),
            LogicalRoot::SteamRoot => self.steam_root.clone(),
            LogicalRoot::SteamLibrary { id } => self.steam_libraries.get(id).cloned(),
            LogicalRoot::SteamUserdata => self.steam_userdata.clone(),
            LogicalRoot::ProtonPrefix { steam_app_id } => {
                self.proton_prefixes.get(steam_app_id).cloned()
            }
            LogicalRoot::WinePrefix { id } => self.wine_prefixes.get(id).cloned(),
            LogicalRoot::BottlesPrefix { id } => self.bottles_prefixes.get(id).cloned(),
            LogicalRoot::AppInstallRoot { app_id } => {
                self.app_install_roots.get(app_id.as_str()).cloned()
            }
            LogicalRoot::NolandCustomRoot { id } => self.custom_roots.get(id).cloned(),
        }
    }

    pub fn classify(&self, path: &Path) -> Option<LogicalPath> {
        let candidates: Vec<(usize, LogicalRoot, PathBuf)> = [
            self.xdg_config_home
                .as_ref()
                .map(|p| (p.as_os_str().len(), LogicalRoot::XdgConfigHome, p.clone())),
            self.xdg_data_home
                .as_ref()
                .map(|p| (p.as_os_str().len(), LogicalRoot::XdgDataHome, p.clone())),
            self.xdg_cache_home
                .as_ref()
                .map(|p| (p.as_os_str().len(), LogicalRoot::XdgCacheHome, p.clone())),
            self.steam_userdata
                .as_ref()
                .map(|p| (p.as_os_str().len(), LogicalRoot::SteamUserdata, p.clone())),
            self.steam_root
                .as_ref()
                .map(|p| (p.as_os_str().len(), LogicalRoot::SteamRoot, p.clone())),
            self.documents
                .as_ref()
                .map(|p| (p.as_os_str().len(), LogicalRoot::Documents, p.clone())),
            self.downloads
                .as_ref()
                .map(|p| (p.as_os_str().len(), LogicalRoot::Downloads, p.clone())),
            self.games
                .as_ref()
                .map(|p| (p.as_os_str().len(), LogicalRoot::Games, p.clone())),
            self.home
                .as_ref()
                .map(|p| (p.as_os_str().len(), LogicalRoot::Home, p.clone())),
        ]
        .into_iter()
        .flatten()
        .chain(self.steam_libraries.iter().map(|(id, p)| {
            (
                p.as_os_str().len(),
                LogicalRoot::SteamLibrary { id: id.clone() },
                p.clone(),
            )
        }))
        .chain(self.proton_prefixes.iter().map(|(id, p)| {
            (
                p.as_os_str().len(),
                LogicalRoot::ProtonPrefix { steam_app_id: *id },
                p.clone(),
            )
        }))
        .chain(self.wine_prefixes.iter().map(|(id, p)| {
            (
                p.as_os_str().len(),
                LogicalRoot::WinePrefix { id: id.clone() },
                p.clone(),
            )
        }))
        .chain(self.bottles_prefixes.iter().map(|(id, p)| {
            (
                p.as_os_str().len(),
                LogicalRoot::BottlesPrefix { id: id.clone() },
                p.clone(),
            )
        }))
        .chain(self.app_install_roots.iter().map(|(id, p)| {
            (
                p.as_os_str().len(),
                LogicalRoot::AppInstallRoot {
                    app_id: AppId(id.clone()),
                },
                p.clone(),
            )
        }))
        .chain(self.custom_roots.iter().map(|(id, p)| {
            (
                p.as_os_str().len(),
                LogicalRoot::NolandCustomRoot { id: id.clone() },
                p.clone(),
            )
        }))
        .collect();

        let mut best: Option<(usize, LogicalRoot, PathBuf)> = None;
        for (len, root, base) in candidates {
            if path_is_within(path, &base)
                && best
                    .as_ref()
                    .map(|(best_len, _, _)| len > *best_len)
                    .unwrap_or(true)
            {
                best = Some((len, root, base));
            }
        }
        best.map(|(_, root, base)| {
            let rel = path.strip_prefix(&base).unwrap_or(path);
            LogicalPath::new(root, rel.to_string_lossy().as_ref())
                .with_hint(path.display().to_string())
        })
    }
}

pub fn normalize_relative(path: impl AsRef<str>) -> String {
    path.as_ref()
        .replace('\\', "/")
        .trim_start_matches("./")
        .trim_start_matches('/')
        .to_string()
}

pub fn path_is_within(path: &Path, root: &Path) -> bool {
    path.starts_with(root)
}

/// Reject traversal, NUL, and absolute relative paths.
pub fn validate_relative_path(relative: &str) -> Result<()> {
    let normalized = relative.replace('\\', "/");
    if normalized.is_empty() {
        return Err(StateError::UnsafePath("empty relative path".into()));
    }
    if normalized.starts_with('/') || normalized.contains('\0') {
        return Err(StateError::UnsafePath(relative.into()));
    }
    for component in normalized.split('/') {
        if component == ".." {
            return Err(StateError::UnsafePath(format!(
                "path traversal in '{relative}'"
            )));
        }
    }
    Ok(())
}

pub fn join_validated(root: &Path, relative: &str) -> Result<PathBuf> {
    validate_relative_path(relative)?;
    let joined = root.join(relative.replace('\\', "/"));
    let canonical_root = root;
    if !joined.starts_with(canonical_root) {
        return Err(StateError::UnsafePath(format!(
            "resolved path {} escapes {}",
            joined.display(),
            root.display()
        )));
    }
    Ok(joined)
}

// Native filename API: original GPL-3.0-only integration, derived from the
// audited No Land e81238a path confinement boundary. Legacy functions above,
// control identifiers, remote object keys and the serialized format are unchanged.
const NATIVE_PATH_BYTES: usize = 32_768;
const NATIVE_COMPONENT_BYTES: usize = 255;
const NATIVE_PATH_DEPTH: usize = 128;

fn validate_unix_component(component: &str) -> Result<()> {
    if component.is_empty()
        || matches!(component, "." | "..")
        || component.len() > NATIVE_COMPONENT_BYTES
        || component.contains(['/', '\0'])
        || component.chars().any(char::is_control)
    {
        return Err(StateError::UnsafePath(
            "invalid bounded native filename component".into(),
        ));
    }
    Ok(())
}

fn validate_windows_component(component: &str) -> Result<()> {
    validate_unix_component(component)?;
    // Examine normalized aliases only to reject them; never rename signed data.
    let alias = component.nfkc().collect::<String>();
    for name in [component, alias.as_str()] {
        let stem = name
            .split('.')
            .next()
            .unwrap_or("")
            .trim_end_matches(' ')
            .to_uppercase();
        if matches!(name, "." | "..")
            || name.ends_with(['.', ' '])
            || name
                .chars()
                .any(|c| c.is_control() || r#"/\:<>"|?*"#.contains(c))
            || matches!(
                stem.as_str(),
                "CON" | "PRN" | "AUX" | "NUL" | "CONIN$" | "CONOUT$"
            )
            || ((stem.starts_with("COM") || stem.starts_with("LPT"))
                && stem.chars().count() == 4
                && stem
                    .chars()
                    .last()
                    .is_some_and(|c| c.is_ascii_digit() || matches!(c, '¹' | '²' | '³')))
        {
            return Err(StateError::UnsafePath(
                "native filename is incompatible with Windows: device, stream, separator or alias"
                    .into(),
            ));
        }
    }
    Ok(())
}

fn validate_native_relative_for(relative: &str, windows: bool) -> Result<()> {
    if relative.is_empty()
        || relative.len() > NATIVE_PATH_BYTES
        || relative.starts_with('/')
        || relative.contains('\0')
        || relative.split('/').count() > NATIVE_PATH_DEPTH
    {
        return Err(StateError::UnsafePath(
            "invalid bounded native relative path".into(),
        ));
    }
    for component in relative.split('/') {
        if windows {
            validate_windows_component(component)?;
        } else {
            validate_unix_component(component)?;
        }
    }
    Ok(())
}

/// Exact UTF-8 Unix filename syntax. Slash alone separates components; colon
/// and backslash are ordinary data. This performs no I/O or normalization.
pub fn validate_unix_relative_path(relative: &str) -> Result<()> {
    validate_native_relative_for(relative, false)
}

/// Pure Windows target compatibility check, callable on Unix before any target
/// mutation. Rejects drive/UNC/device/ADS spellings rather than reinterpreting
/// Unix names. On the wire, slash is the only directory separator.
pub fn validate_windows_relative_path(relative: &str) -> Result<()> {
    validate_native_relative_for(relative, true)
}

pub fn validate_native_component(component: &str) -> Result<()> {
    #[cfg(windows)]
    return validate_windows_component(component);
    #[cfg(unix)]
    return validate_unix_component(component);
    #[cfg(not(any(unix, windows)))]
    Err(StateError::UnsafePath(
        "native filename rules are unsupported on this platform".into(),
    ))
}

pub fn validate_native_relative_path(relative: &str) -> Result<()> {
    #[cfg(windows)]
    return validate_windows_relative_path(relative);
    #[cfg(unix)]
    return validate_unix_relative_path(relative);
    #[cfg(not(any(unix, windows)))]
    Err(StateError::UnsafePath(
        "native path rules are unsupported on this platform".into(),
    ))
}

/// Join exact native dataset names, never replacing backslashes or guessing a
/// source parent. Native filesystem handles must still enforce no-follow access.
pub fn join_native_relative(root: &Path, relative: &str) -> Result<PathBuf> {
    validate_native_relative_path(relative)?;
    if !root.is_absolute() {
        return Err(StateError::UnsafePath(
            "native logical root must be absolute".into(),
        ));
    }
    let joined = root.join(relative);
    if !joined.starts_with(root) {
        return Err(StateError::UnsafePath(
            "native relative target escaped its logical root".into(),
        ));
    }
    Ok(joined)
}

/// Link text is never followed during capture/publication. Leading parent steps
/// (e.g. Proton dosdevices/c: -> ../drive_c) may ascend only within the link's
/// logical root. A parent step after a named component is unsafe: that component
/// could itself be a symlink, making lexical normalization misleading.
pub fn validate_symlink_target_within_root(relative_path: &str, target: &str) -> Result<()> {
    validate_relative_path(relative_path)?;
    let rejected = || StateError::UnsafePath(format!("symlink target rejected: {target}"));
    if target.is_empty()
        || target.contains('\0')
        || target.starts_with("/proc")
        || target.starts_with("/sys")
        || target.starts_with("/dev")
    {
        return Err(rejected());
    }
    if !target.contains("..") {
        return Ok(());
    }
    if target.starts_with('/') || target.contains('\\') {
        return Err(rejected());
    }
    let mut depth = relative_path
        .split('/')
        .filter(|part| !part.is_empty() && *part != ".")
        .count()
        .saturating_sub(1);
    let mut leading = true;
    for component in target.split('/') {
        match component {
            "" | "." => {}
            ".." if leading && depth > 0 => depth -= 1,
            ".." => return Err(rejected()),
            part if part.contains("..") => return Err(rejected()),
            _ => leading = false,
        }
    }
    Ok(())
}

/// Native app bundles preserve relative link text only. The original Linux
/// engine's absolute system-link policy is deliberately NOT native authority.
/// Nothing resolves or reads the target here.
pub fn validate_relative_symlink_target_within_root(
    relative_path: &str,
    target: &str,
) -> Result<()> {
    validate_native_relative_path(relative_path)?;
    validate_native_link_for(relative_path, target, cfg!(windows))
}

/// The same lexical link confinement using Windows target-name rules, without
/// opening a Windows filesystem or changing original Unix link text.
pub fn validate_windows_relative_symlink_target_within_root(
    relative_path: &str,
    target: &str,
) -> Result<()> {
    validate_windows_relative_path(relative_path)?;
    validate_native_link_for(relative_path, target, true)
}

fn validate_native_link_for(relative_path: &str, target: &str, windows: bool) -> Result<()> {
    if target.is_empty()
        || target.len() > NATIVE_PATH_BYTES
        || target.starts_with('/')
        || target.contains('\0')
        || target.split('/').count() > NATIVE_PATH_DEPTH
    {
        return Err(StateError::UnsafePath(
            "native symbolic link needs a bounded confined relative target".into(),
        ));
    }
    let mut depth = relative_path.split('/').count() - 1;
    let mut leading = true;
    for component in target.split('/') {
        match component {
            "." => {}
            ".." if leading && depth > 0 => depth -= 1,
            ".." => {
                return Err(StateError::UnsafePath(
                    "native symbolic link escapes its root or crosses a named traversal edge"
                        .into(),
                ))
            }
            name => {
                if windows {
                    validate_windows_component(name)?;
                } else {
                    validate_unix_component(name)?;
                }
                leading = false;
                depth += 1;
                if depth > NATIVE_PATH_DEPTH {
                    return Err(StateError::UnsafePath(
                        "native symbolic link exceeds its depth bound".into(),
                    ));
                }
            }
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn native_relative_links_never_inherit_absolute_linux_system_link_permission() {
        assert!(validate_symlink_target_within_root("link", "/usr/lib/libc.so").is_ok());
        for target in [
            "/usr/lib/libc.so",
            "../outside",
            "child/../outside",
            "a//b",
            "",
        ] {
            assert!(validate_relative_symlink_target_within_root("link", target).is_err());
        }
        assert!(validate_relative_symlink_target_within_root("Versions/Current", "A").is_ok());
        assert!(validate_relative_symlink_target_within_root("a/link", "../sibling").is_ok());
    }

    #[test]
    fn native_target_rules_preserve_unix_names_and_reject_windows_aliases() {
        for path in [
            "com.apple.iMovie:project",
            r"a\b",
            r"directory:one\literal/child:two",
            r"C:\one-native-unix-filename",
            "C:relative",
        ] {
            validate_unix_relative_path(path).unwrap();
            assert!(validate_windows_relative_path(path).is_err(), "{path}");
        }
        for path in [
            r"\\server\share",
            r"\??\C:\device",
            r"..\escape",
            "C:/outside",
            "stream:ads",
            "NUL.txt",
            "com0",
            "LPT9.bin",
            "COM¹",
            "ｃｏｎ.txt",
            "trailing.",
            "trailing ",
            "bad*name",
            "bad?name",
            "fullwidth：stream",
        ] {
            assert!(validate_windows_relative_path(path).is_err(), "{path}");
        }
        validate_windows_relative_path("safe directory/data.bin").unwrap();
        for path in [
            "",
            "/absolute",
            "//unc/share",
            ".",
            "..",
            "a/../b",
            "a/./b",
            "a//b",
            "a/",
            "nul\0byte",
        ] {
            assert!(validate_unix_relative_path(path).is_err(), "{path:?}");
            assert!(validate_windows_relative_path(path).is_err(), "{path:?}");
        }
        for path in ["x".repeat(256), vec!["x"; 129].join("/"), "x".repeat(32769)] {
            assert!(validate_unix_relative_path(&path).is_err());
            assert!(validate_windows_relative_path(&path).is_err());
        }
    }

    #[cfg(unix)]
    #[test]
    fn native_constructor_join_and_json_are_exact_without_changing_legacy_normalization() {
        let root = LogicalRoot::NolandCustomRoot {
            id: "control-scope-unchanged".into(),
        };
        let literal = LogicalPath::new_native(root.clone(), r"a\b").unwrap();
        let nested = LogicalPath::new_native(root.clone(), "a/b").unwrap();
        assert_ne!(literal.relative_path, nested.relative_path);
        assert_eq!(literal.logical_root.as_token(), root.as_token());
        let restored: LogicalPath =
            serde_json::from_slice(&serde_json::to_vec(&literal).unwrap()).unwrap();
        assert_eq!(restored.relative_path, r"a\b");
        let base = Path::new("/synthetic-native-no-io");
        assert_eq!(
            join_native_relative(base, r"a\b").unwrap(),
            base.join(r"a\b")
        );
        assert_ne!(
            join_native_relative(base, r"a\b").unwrap(),
            join_native_relative(base, "a/b").unwrap()
        );
        assert_eq!(LogicalPath::new(root, r"a\b").relative_path, "a/b");
        assert_eq!(join_validated(base, r"a\b").unwrap(), base.join("a/b"));
        for relative in ["../escape", "/escape", "a/../b", "nul\0byte"] {
            assert!(LogicalPath::new_native(LogicalRoot::Home, relative).is_err());
            assert!(join_native_relative(base, relative).is_err());
        }
        // Backslash and colon here are filename data, not traversal or a drive.
        validate_relative_symlink_target_within_root(r"dir:one\literal/link", r"../a\b").unwrap();
        validate_relative_symlink_target_within_root("link", r"..\one-literal-leaf").unwrap();
        assert!(
            validate_windows_relative_symlink_target_within_root("dir/link", r"../a\b").is_err()
        );
        assert!(
            validate_windows_relative_symlink_target_within_root("link", r"C:\outside").is_err()
        );
        assert!(
            validate_relative_symlink_target_within_root("dir/link", r"a\b/../../outside").is_err()
        );
    }

    #[test]
    fn symlink_parent_steps_stay_inside_root_and_precede_named_components() {
        for (path, target) in [
            ("dosdevices/c:", "../drive_c"),
            (
                "drive_c/users/steamuser/Local Settings/Application Data",
                "../AppData/Local",
            ),
            ("a/b/c", "../../sibling"),
            ("link", "sibling"),
            ("link", "/usr/lib/libc.so"),
        ] {
            assert!(
                validate_symlink_target_within_root(path, target).is_ok(),
                "{path} -> {target}"
            );
        }
        for (path, target) in [
            ("link", "../outside"),
            ("a/link", "../../outside"),
            ("a/link", "child/../outside"),
            ("a/link", "../child/../outside"),
            ("a/link", "/tmp/../outside"),
            ("a/link", "..\\outside"),
            ("link", "/proc/self/mem"),
            ("link", "/dev/null"),
            ("link", "/sys/kernel"),
            ("../link", "safe"),
        ] {
            assert!(
                validate_symlink_target_within_root(path, target).is_err(),
                "{path} -> {target}"
            );
        }
    }

    #[test]
    fn rejects_traversal() {
        assert!(validate_relative_path("../etc/passwd").is_err());
        assert!(validate_relative_path("ok/../secret").is_err());
        assert!(validate_relative_path("saves/world.dat").is_ok());
    }

    #[test]
    fn classifies_xdg_over_home() {
        let map = LogicalRootMap::from_home("/home/gamer");
        let classified = map
            .classify(Path::new("/home/gamer/.local/share/example-game/save1.db"))
            .unwrap();
        assert_eq!(classified.logical_root.as_token(), "$XDG_DATA_HOME");
        assert_eq!(classified.relative_path, "example-game/save1.db");
    }
}
