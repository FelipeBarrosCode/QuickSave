// SPDX-License-Identifier: GPL-3.0-only
//! XML/binary Info.plist parsing using Rust plist; no plutil subprocess.

use anyhow::{ensure, Context, Result};
use plist::stream::{Event, Reader};
use std::collections::BTreeSet;
use std::io::Cursor;

pub const MAX_PLIST_BYTES: usize = 1024 * 1024;
pub const MAX_PLIST_EVENTS: usize = 16384;
pub const MAX_PLIST_DEPTH: usize = 32;
pub const MAX_EXPANDED_PLIST_BYTES: usize = 4 * 1024 * 1024;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BundleMetadata {
    pub bundle_identifier: String,
    pub display_name: Option<String>,
    pub executable_name: Option<String>,
}

pub fn parse_info_plist(bytes: &[u8]) -> Result<BundleMetadata> {
    ensure!(
        bytes.len() <= MAX_PLIST_BYTES,
        "Info.plist exceeds the input limit"
    );
    let value = bounded_value(bytes)?;
    let dictionary = value
        .as_dictionary()
        .context("Info.plist is not a dictionary")?;
    let id = dictionary
        .get("CFBundleIdentifier")
        .and_then(plist::Value::as_string)
        .context("Info.plist has no string CFBundleIdentifier")?;
    validate_identifier(id)?;
    let name = dictionary
        .get("CFBundleDisplayName")
        .or_else(|| dictionary.get("CFBundleName"))
        .and_then(plist::Value::as_string);
    if let Some(name) = name {
        ensure!(
            name.len() <= 4096 && !name.chars().any(char::is_control),
            "invalid bundle display name"
        );
    }
    let executable_name = dictionary
        .get("CFBundleExecutable")
        .map(|value| {
            let name = value
                .as_string()
                .context("CFBundleExecutable is not a string")?;
            crate::profiles::validate_segment(name)?;
            Ok::<_, anyhow::Error>(name.to_owned())
        })
        .transpose()?;
    Ok(BundleMetadata {
        bundle_identifier: id.to_owned(),
        display_name: name.filter(|name| !name.is_empty()).map(str::to_owned),
        executable_name,
    })
}

pub fn validate_identifier(id: &str) -> Result<()> {
    ensure!(
        !id.is_empty()
            && id.len() <= 255
            && id
                .split('.')
                .all(|part| !part.is_empty() && part != "-" && part != "_")
            && id
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || b".-_".contains(&byte)),
        "invalid platform identifier"
    );
    Ok(())
}

/// Only the exact container-manager identifier is evidence. The directory's
/// basename is deliberately not a fallback.
pub fn parse_container_identifier(bytes: &[u8]) -> Result<String> {
    let value = bounded_value(bytes)?;
    let id = value
        .as_dictionary()
        .context("container metadata is not a dictionary")?
        .get("MCMMetadataIdentifier")
        .and_then(plist::Value::as_string)
        .context("container metadata lacks MCMMetadataIdentifier")?;
    validate_identifier(id)?;
    Ok(id.to_owned())
}

/// Pure signed-entitlement fixture parser. Calling this parser does NOT validate
/// a signature; native validation belongs to the Security backend.
pub fn parse_application_groups(bytes: &[u8]) -> Result<Vec<String>> {
    let value = bounded_value(bytes)?;
    let dictionary = value
        .as_dictionary()
        .context("entitlements are not a dictionary")?;
    let Some(groups) = dictionary.get("com.apple.security.application-groups") else {
        return Ok(Vec::new());
    };
    let array = groups
        .as_array()
        .context("application groups are not an array")?;
    ensure!(array.len() <= 64, "too many signed application groups");
    let mut result = BTreeSet::new();
    for item in array {
        let id = item
            .as_string()
            .context("application group is not a string")?;
        validate_identifier(id)?;
        ensure!(result.insert(id.to_owned()), "duplicate application group");
    }
    Ok(result.into_iter().collect())
}

pub(crate) fn bounded_value(bytes: &[u8]) -> Result<plist::Value> {
    ensure!(
        bytes.len() <= MAX_PLIST_BYTES,
        "plist exceeds the input limit"
    );
    let mut events = Vec::new();
    let mut depth = 0usize;
    let mut expanded_bytes = 0usize;
    let mut declared_items = 0u64;
    let mut top_keys = BTreeSet::new();
    let mut expecting_top_key = true;
    // Binary plists can repeatedly reference the same objects, expanding a
    // small document into an enormous Value. Guard the expanded event stream
    // BEFORE constructing the tree or trusting collection capacity hints.
    for event in Reader::new(Cursor::new(bytes)) {
        ensure!(
            events.len() < MAX_PLIST_EVENTS,
            "plist event count exceeds limit"
        );
        let event = event.context("invalid Info.plist event")?;
        if events.is_empty() {
            ensure!(
                matches!(&event, Event::StartDictionary(_)),
                "Info.plist is not a dictionary"
            );
        } else {
            ensure!(depth > 0, "Info.plist has multiple roots");
        }
        if depth == 1 {
            match &event {
                Event::EndCollection => {
                    ensure!(expecting_top_key, "plist dictionary has an unmatched key")
                }
                Event::String(key) if expecting_top_key => {
                    ensure!(top_keys.insert(key.to_string()), "duplicate Info.plist key");
                    expecting_top_key = false;
                }
                _ if expecting_top_key => {
                    anyhow::bail!("Info.plist dictionary key is not a string")
                }
                _ => expecting_top_key = true,
            }
        }
        match &event {
            Event::StartArray(length) | Event::StartDictionary(length) => {
                depth += 1;
                ensure!(depth <= MAX_PLIST_DEPTH, "plist nesting exceeds limit");
                let multiplier = if matches!(&event, Event::StartDictionary(_)) {
                    2
                } else {
                    1
                };
                declared_items =
                    declared_items.saturating_add(length.unwrap_or(0).saturating_mul(multiplier));
                ensure!(
                    declared_items <= MAX_PLIST_EVENTS as u64,
                    "plist declared collection sizes exceed limit"
                );
            }
            Event::EndCollection => {
                ensure!(depth > 0, "unexpected plist collection end");
                depth -= 1;
            }
            Event::String(value) => {
                expanded_bytes = expanded_bytes.saturating_add(value.len());
            }
            Event::Data(value) => {
                expanded_bytes = expanded_bytes.saturating_add(value.len());
            }
            _ => {}
        }
        ensure!(
            expanded_bytes <= MAX_EXPANDED_PLIST_BYTES,
            "expanded plist values exceed limit"
        );
        events.push(event);
    }
    ensure!(depth == 0 && !events.is_empty(), "incomplete Info.plist");
    plist::Value::from_events(events.into_iter().map(Ok)).context("invalid Info.plist")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reads_xml_fixture_and_binary_with_no_subprocess() {
        let fixture = include_bytes!("../../fixtures/Info.plist");
        let metadata = parse_info_plist(fixture).unwrap();
        assert_eq!(metadata.bundle_identifier, "org.quicksave.fixture");
        let value = plist::Value::from_reader(Cursor::new(fixture)).unwrap();
        let mut binary = Vec::new();
        value.to_writer_binary(&mut binary).unwrap();
        assert_eq!(parse_info_plist(&binary).unwrap(), metadata);
    }

    #[test]
    fn a_title_does_not_substitute_for_a_bundle_id() {
        assert!(parse_info_plist(b"<plist version=\"1.0\"><dict><key>CFBundleName</key><string>Title</string></dict></plist>").is_err());
        assert!(parse_info_plist(&vec![b'x'; MAX_PLIST_BYTES + 1]).is_err());
    }

    #[test]
    fn rejects_duplicate_identity_keys_and_deep_or_expanded_documents() {
        let duplicate = br#"<plist version="1.0"><dict><key>CFBundleIdentifier</key><string>org.fixture.one</string><key>CFBundleIdentifier</key><string>org.fixture.two</string></dict></plist>"#;
        assert!(parse_info_plist(duplicate).is_err());
        let nested = format!(
            "<plist version=\"1.0\"><dict><key>nested</key>{}{}{}</dict></plist>",
            "<array>".repeat(MAX_PLIST_DEPTH),
            "<string>x</string>",
            "</array>".repeat(MAX_PLIST_DEPTH)
        );
        assert!(parse_info_plist(nested.as_bytes()).is_err());
        let many = format!(
            "<plist version=\"1.0\"><dict><key>many</key><array>{}</array></dict></plist>",
            "<true/>".repeat(MAX_PLIST_EVENTS)
        );
        assert!(parse_info_plist(many.as_bytes()).is_err());
    }
}
