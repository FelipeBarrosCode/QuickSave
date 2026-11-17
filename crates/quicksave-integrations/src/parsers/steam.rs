// SPDX-License-Identifier: GPL-3.0-only
// Adapted from No Land commit e81238a7536aae201540956ce76981364fd36595,
// state-agent/crates/noland-discovery/src/steam.rs. See PROVENANCE.md for the
// unresolved upstream root/manifest license discrepancy and adaptation details.
//! Portable bounded ACF/VDF parsing, deliberately separated from discovery I/O.
//! No symlink canonicalization, title-based install fallback or save attribution.

use anyhow::{bail, ensure, Context, Result};
use std::collections::BTreeMap;

use crate::profiles::{validate_segment, ProfilePath};

pub const MAX_VDF_BYTES: usize = 1024 * 1024;
pub const MAX_LIBRARIES: usize = 32;
const MAX_TOKENS: usize = 32768;
const MAX_TOKEN_BYTES: usize = 8192;
const MAX_DEPTH: usize = 16;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SteamLibraryEntry {
    pub id: u32,
    /// Absolute native path text, preserving Windows paths on other hosts.
    pub path: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SteamAppManifest {
    pub app_id: u32,
    pub display_name: String,
    /// A validated single directory component under steamapps/common.
    pub install_subdirectory: ProfilePath,
}

#[derive(Debug)]
enum Token {
    Word(String),
    Open,
    Close,
}

#[derive(Debug)]
enum Value {
    Text(String),
    Object(BTreeMap<String, Value>),
}

type Object = BTreeMap<String, Value>;

/// Supports the legacy numeric path pairs and current nested path/apps format.
/// The nested apps inventory is metadata only, not proof of installed files.
pub fn parse_libraryfolders(text: &str) -> Result<Vec<SteamLibraryEntry>> {
    let parsed = parse_keyvalues(text)?;
    let root = root_object(&parsed, "libraryfolders")?;
    let mut libraries = Vec::new();
    for (id, value) in root {
        // Steam also writes nonnumeric bookkeeping fields in the legacy format.
        if !id.bytes().all(|byte| byte.is_ascii_digit()) || id.is_empty() {
            continue;
        }
        let id: u32 = id.parse().context("invalid Steam library ID")?;
        let path = match value {
            Value::Text(path) => path,
            Value::Object(object) => text_field(object, "path")?,
        };
        validate_library_path(path)?;
        ensure!(
            libraries.len() < MAX_LIBRARIES,
            "Steam library count exceeds limit"
        );
        libraries.push(SteamLibraryEntry {
            id,
            path: path.clone(),
        });
    }
    libraries.sort_by_key(|entry| entry.id);
    ensure!(
        !libraries.windows(2).any(|pair| pair[0].id == pair[1].id),
        "ambiguous Steam library IDs"
    );
    Ok(libraries)
}

/// Does not accept missing installdir, a title-derived directory, traversal,
/// duplicate keys or nonnumeric IDs.
pub fn parse_appmanifest(text: &str) -> Result<SteamAppManifest> {
    let parsed = parse_keyvalues(text)?;
    let root = root_object(&parsed, "AppState")?;
    let raw_id = text_field(root, "appid")?;
    ensure!(
        !raw_id.is_empty() && raw_id.bytes().all(|byte| byte.is_ascii_digit()),
        "invalid Steam app ID"
    );
    let app_id: u32 = raw_id.parse().context("invalid Steam app ID")?;
    ensure!(app_id > 0, "Steam app ID must be positive");
    let install_subdirectory = text_field(root, "installdir")?;
    validate_segment(install_subdirectory)?;
    let install_subdirectory = ProfilePath::new(install_subdirectory.clone())?;
    let display_name = match root.get("name") {
        Some(Value::Text(name)) if !name.is_empty() => {
            ensure!(
                name.len() <= 4096 && !name.chars().any(char::is_control),
                "invalid Steam display name"
            );
            name.clone()
        }
        None => format!("Steam {app_id}"),
        _ => bail!("invalid Steam display name"),
    };
    Ok(SteamAppManifest {
        app_id,
        display_name,
        install_subdirectory,
    })
}

fn root_object<'a>(object: &'a Object, name: &str) -> Result<&'a Object> {
    ensure!(object.len() == 1, "ambiguous KeyValues root");
    match object.iter().next() {
        Some((key, Value::Object(root))) if key.eq_ignore_ascii_case(name) => Ok(root),
        _ => bail!("unexpected KeyValues root"),
    }
}

fn text_field<'a>(object: &'a Object, key: &str) -> Result<&'a String> {
    match object.get(key) {
        Some(Value::Text(value)) => Ok(value),
        _ => bail!("missing or invalid required Steam field"),
    }
}

/// Path syntax check is independent of the host OS; native opening separately
/// rejects symlinks/reparse points and checks that the path matches the host.
fn validate_library_path(path: &str) -> Result<()> {
    ensure!(
        !path.is_empty() && path.len() <= 4096,
        "invalid Steam library path length"
    );
    ensure!(
        !path.chars().any(char::is_control),
        "invalid Steam library path"
    );
    let tail = if let Some(tail) = path.strip_prefix('/') {
        ensure!(!path.contains('\\'), "mixed Steam library path separators");
        tail
    } else {
        let bytes = path.as_bytes();
        ensure!(
            bytes.len() >= 3
                && bytes[0].is_ascii_alphabetic()
                && bytes[1] == b':'
                && matches!(bytes[2], b'\\' | b'/'),
            "Steam library path must be absolute"
        );
        &path[3..]
    };
    ensure!(!tail.is_empty(), "filesystem root is not a Steam library");
    // A trailing separator is conventional in some Steam versions.
    let tail = tail.trim_end_matches(['/', '\\']);
    ensure!(!tail.is_empty(), "filesystem root is not a Steam library");
    for segment in tail.split(['/', '\\']) {
        validate_segment(segment)?;
    }
    Ok(())
}

fn parse_keyvalues(text: &str) -> Result<Object> {
    let tokens = tokenize(text)?;
    let mut frames: Vec<(Option<String>, Object)> = vec![(None, BTreeMap::new())];
    let mut tokens = tokens.into_iter();
    while let Some(token) = tokens.next() {
        match token {
            Token::Word(key) => {
                ensure!(!key.is_empty(), "empty KeyValues key");
                match tokens.next() {
                    Some(Token::Word(value)) => {
                        let object = &mut frames.last_mut().context("missing KeyValues frame")?.1;
                        ensure!(
                            object.insert(key, Value::Text(value)).is_none(),
                            "duplicate KeyValues key"
                        );
                    }
                    Some(Token::Open) => {
                        ensure!(frames.len() < MAX_DEPTH, "KeyValues nesting exceeds limit");
                        frames.push((Some(key), BTreeMap::new()));
                    }
                    _ => bail!("missing KeyValues value"),
                }
            }
            Token::Close => {
                ensure!(frames.len() > 1, "unexpected KeyValues closing brace");
                let (key, child) = frames.pop().context("missing KeyValues frame")?;
                let parent = &mut frames.last_mut().context("missing KeyValues parent")?.1;
                ensure!(
                    parent
                        .insert(
                            key.context("missing KeyValues object key")?,
                            Value::Object(child)
                        )
                        .is_none(),
                    "duplicate KeyValues key"
                );
            }
            Token::Open => bail!("unexpected KeyValues opening brace"),
        }
    }
    ensure!(frames.len() == 1, "unterminated KeyValues object");
    Ok(frames.pop().context("missing KeyValues root")?.1)
}

fn tokenize(text: &str) -> Result<Vec<Token>> {
    ensure!(text.len() <= MAX_VDF_BYTES, "VDF/ACF exceeds input limit");
    ensure!(!text.contains('\0'), "VDF/ACF contains NUL");
    let mut chars = text.trim_start_matches('\u{feff}').chars().peekable();
    let mut tokens = Vec::new();
    while let Some(c) = chars.next() {
        if c.is_whitespace() {
            continue;
        }
        if c == '/' && chars.peek() == Some(&'/') {
            for c in chars.by_ref() {
                if c == '\n' {
                    break;
                }
            }
            continue;
        }
        ensure!(
            tokens.len() < MAX_TOKENS,
            "VDF/ACF token count exceeds limit"
        );
        let token = match c {
            '{' => Token::Open,
            '}' => Token::Close,
            '"' => {
                let mut value = String::new();
                let mut closed = false;
                while let Some(c) = chars.next() {
                    match c {
                        '"' => {
                            closed = true;
                            break;
                        }
                        '\\' => {
                            let escaped = chars.next().context("unterminated KeyValues escape")?;
                            match escaped {
                                '\\' | '"' => value.push(escaped),
                                // Preserve legacy unescaped Windows separators.
                                other => {
                                    value.push('\\');
                                    value.push(other);
                                }
                            }
                        }
                        c => value.push(c),
                    }
                    ensure!(
                        value.len() <= MAX_TOKEN_BYTES,
                        "VDF/ACF token exceeds limit"
                    );
                }
                ensure!(closed, "unterminated KeyValues string");
                Token::Word(value)
            }
            other => {
                let mut value = String::from(other);
                while chars
                    .peek()
                    .is_some_and(|c| !c.is_whitespace() && !matches!(*c, '{' | '}' | '"'))
                {
                    value.push(chars.next().context("invalid KeyValues token")?);
                    ensure!(
                        value.len() <= MAX_TOKEN_BYTES,
                        "VDF/ACF token exceeds limit"
                    );
                }
                Token::Word(value)
            }
        };
        tokens.push(token);
    }
    Ok(tokens)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_current_and_legacy_libraries_portably() {
        let modern =
            parse_libraryfolders(include_str!("../../fixtures/libraryfolders.vdf")).unwrap();
        assert_eq!(modern[0].path, "/games/Steam");
        assert_eq!(modern[1].path, r"D:\Games\SteamLibrary");
        let legacy = parse_libraryfolders(
            "\"LibraryFolders\" { \"TimeNextStatsReport\" \"0\" \"1\" \"/mnt/SteamLibrary\" }",
        )
        .unwrap();
        assert_eq!(
            legacy,
            vec![SteamLibraryEntry {
                id: 1,
                path: "/mnt/SteamLibrary".into()
            }]
        );
    }

    #[test]
    fn stable_app_id_and_explicit_install_dir_do_not_depend_on_title() {
        let fixture = include_str!("../../fixtures/appmanifest_480.acf");
        let app = parse_appmanifest(fixture).unwrap();
        assert_eq!(app.app_id, 480);
        assert_eq!(app.install_subdirectory.as_str(), "FixtureInstall");
        assert_ne!(app.display_name, app.install_subdirectory.as_str());
        assert!(
            parse_appmanifest("\"AppState\" { \"appid\" \"480\" \"name\" \"Title\" }").is_err()
        );
    }

    #[test]
    fn rejects_traversal_ambiguous_keys_and_bad_documents() {
        for directory in [
            "../other",
            "/absolute",
            r"C:\Games",
            "a/b",
            r"a\b",
            ".",
            "CON",
        ] {
            let text = format!(r#""AppState" {{ "appid" "480" "installdir" "{directory}" }}"#);
            assert!(parse_appmanifest(&text).is_err(), "{directory}");
        }
        for text in [
            "\"AppState\" { \"appid\" \"480\" \"appid\" \"481\" \"installdir\" \"App\" }",
            "\"AppState\" { \"appid\" \"0\" \"installdir\" \"App\" }",
            "\"AppState\" { \"appid\" \"480\" \"installdir\" \"App\" ",
            "\"AppState\" { \"appid\" \"480\" \"installdir\" \"App\" }}",
            "\"AppState\" { \"appid\" \"480\" \"installdir\" \"App\" } \"extra\" \"value\"",
        ] {
            assert!(parse_appmanifest(text).is_err());
        }
        for path in ["relative", "/", "/games/../other", "/games//other"] {
            let text = format!(r#""libraryfolders" {{ "0" "{path}" }}"#);
            assert!(parse_libraryfolders(&text).is_err(), "{path}");
        }
    }

    #[test]
    fn limits_document_tokens_and_nesting() {
        assert!(parse_appmanifest(&"x".repeat(MAX_VDF_BYTES + 1)).is_err());
        let nested = format!("{}{}", "\"a\" {".repeat(MAX_DEPTH), "}".repeat(MAX_DEPTH));
        assert!(parse_keyvalues(&nested).is_err());
        assert!(parse_keyvalues(&"\"k\" \"v\" ".repeat(MAX_TOKENS)).is_err());
        assert!(
            parse_keyvalues(&format!("\"{}\" \"v\"", "x".repeat(MAX_TOKEN_BYTES + 1))).is_err()
        );
    }
}
