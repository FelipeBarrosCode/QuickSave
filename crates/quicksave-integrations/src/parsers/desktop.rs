// SPDX-License-Identifier: GPL-3.0-only
//! Bounded .desktop metadata only. Exec, TryExec and DBus activation are never
//! evaluated, and their values are never used to infer filesystem ownership.

use anyhow::{bail, ensure, Result};
use std::collections::BTreeMap;

pub const MAX_DESKTOP_BYTES: usize = 256 * 1024;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DesktopMetadata {
    pub display_name: Option<String>,
    pub hidden: bool,
    pub no_display: bool,
}

pub fn parse_desktop_entry(text: &str) -> Result<DesktopMetadata> {
    ensure!(
        text.len() <= MAX_DESKTOP_BYTES,
        "desktop entry exceeds input limit"
    );
    ensure!(!text.contains('\0'), "desktop entry contains NUL");
    let mut in_desktop = false;
    let mut saw_desktop = false;
    let mut fields = BTreeMap::new();
    for (index, line) in text.lines().enumerate() {
        ensure!(index < 16384, "desktop entry exceeds line limit");
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        if line.starts_with('[') {
            ensure!(line.ends_with(']'), "invalid desktop section");
            in_desktop = line == "[Desktop Entry]";
            if in_desktop {
                ensure!(!saw_desktop, "duplicate Desktop Entry section");
                saw_desktop = true;
            }
            continue;
        }
        if in_desktop {
            let (key, value) = line
                .split_once('=')
                .ok_or_else(|| anyhow::anyhow!("invalid desktop field"))?;
            let key = key.trim();
            // Only retain bounded metadata. Never interpret shell commands.
            if matches!(key, "Type" | "Name" | "Hidden" | "NoDisplay") {
                ensure!(
                    fields.insert(key, value.trim()).is_none(),
                    "duplicate desktop field"
                );
            }
        }
    }
    ensure!(saw_desktop, "missing Desktop Entry section");
    let hidden = parse_boolean(fields.get("Hidden").copied())?;
    if !hidden {
        ensure!(
            fields.get("Type") == Some(&"Application"),
            "not an Application desktop entry"
        );
    }
    let display_name = fields
        .get("Name")
        .map(|name| decode_name(name))
        .transpose()?;
    Ok(DesktopMetadata {
        display_name,
        hidden,
        no_display: parse_boolean(fields.get("NoDisplay").copied())?,
    })
}

fn parse_boolean(value: Option<&str>) -> Result<bool> {
    match value {
        None | Some("false") => Ok(false),
        Some("true") => Ok(true),
        _ => bail!("invalid desktop boolean"),
    }
}

fn decode_name(value: &str) -> Result<String> {
    ensure!(value.len() <= 4096, "desktop name exceeds limit");
    let mut out = String::new();
    let mut chars = value.chars();
    while let Some(c) = chars.next() {
        match c {
            '\\' => match chars.next() {
                Some('s') => out.push(' '),
                Some('\\') => out.push('\\'),
                // Control characters do not belong in discovery display names.
                _ => bail!("unsupported desktop name escape"),
            },
            c if c.is_control() => bail!("control character in desktop name"),
            c => out.push(c),
        }
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn command_text_is_never_executed_or_used_as_an_installation() {
        let parsed = parse_desktop_entry(include_str!("../../fixtures/sample.desktop")).unwrap();
        assert_eq!(parsed.display_name.as_deref(), Some("Fixture App"));
        assert!(!parsed.hidden);
        assert!(!parsed.no_display);
    }

    #[test]
    fn hidden_override_can_mask_a_system_entry() {
        assert!(
            parse_desktop_entry("[Desktop Entry]\nHidden=true\n")
                .unwrap()
                .hidden
        );
        assert!(parse_desktop_entry("[Desktop Entry]\nType=Link\n").is_err());
        assert!(
            parse_desktop_entry("[Desktop Entry]\nType=Application\nType=Application\n").is_err()
        );
        assert!(parse_desktop_entry(&"x".repeat(MAX_DESKTOP_BYTES + 1)).is_err());
    }
}
