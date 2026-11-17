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
    ensure!(
        !id.is_empty()
            && id.len() <= 255
            && id.split('.').all(|part| !part.is_empty())
            && id
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || b".-_".contains(&byte)),
        "invalid bundle identifier"
    );
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
    Ok(BundleMetadata {
        bundle_identifier: id.to_owned(),
        display_name: name.filter(|name| !name.is_empty()).map(str::to_owned),
    })
}

fn bounded_value(bytes: &[u8]) -> Result<plist::Value> {
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
