// SPDX-License-Identifier: GPL-3.0-only
//! Linked public NSWorkspace/Launch Services and Spotlight metadata discovery.
//! No shell, private Launch Services enumeration, app launch or content grant.
use super::backend::{validate_path, MacApplicationInventory};
#[cfg(not(test))]
use anyhow::Context;
use anyhow::{ensure, Result};
use serde::Deserialize;
#[cfg(not(test))]
use std::ffi::CString;
use std::path::PathBuf;

const MAX_OUTPUT: usize = 4 * 1024 * 1024;

unsafe extern "C" {
    fn quicksave_mac_inventory(
        scopes: *const *const std::ffi::c_char,
        count: usize,
        maximum: usize,
        output: *mut u8,
        capacity: usize,
        written: *mut usize,
    ) -> std::ffi::c_int;
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct Response {
    paths: Vec<PathBuf>,
    index_complete: bool,
    limited: bool,
    rejected: usize,
}

pub(crate) fn discover(scopes: &[PathBuf], maximum: usize) -> Result<MacApplicationInventory> {
    // Unit tests must inject candidate records, never inspect the user's native
    // application registry or running process inventory.
    #[cfg(test)]
    {
        let _ = (scopes, maximum);
        anyhow::bail!("native application inventory requires an isolated injected fixture");
    }
    #[cfg(not(test))]
    {
        ensure!(
            !scopes.is_empty() && scopes.len() <= 128 && (1..=4096).contains(&maximum),
            "native application inventory scope exceeds bounds"
        );
        let strings = scopes
            .iter()
            .map(|path| {
                validate_path(path)?;
                Ok(CString::new(path.to_str().unwrap())?)
            })
            .collect::<Result<Vec<_>>>()?;
        let pointers = strings
            .iter()
            .map(|value| value.as_ptr())
            .collect::<Vec<_>>();
        let mut output = vec![0; MAX_OUTPUT];
        let mut written = 0;
        // SAFETY: bounded live C strings, pointer array and exact writable buffer.
        // The linked helper catches Objective-C exceptions and never retains inputs.
        let status = unsafe {
            quicksave_mac_inventory(
                pointers.as_ptr(),
                pointers.len(),
                maximum,
                output.as_mut_ptr(),
                output.len(),
                &mut written,
            )
        };
        if status != 0 || written > output.len() {
            return Err(super::backend::MacInventoryFailure(match status {
                10..=12 => "native_inventory_workspace",
                20..=22 => "native_inventory_metadata",
                2 | 30 => "native_inventory_encode",
                _ => "native_inventory_bridge",
            })
            .into());
        }
        decode(&output[..written], maximum).context(super::backend::MacInventoryFailure(
            "native_inventory_response_decode",
        ))
    }
}

fn decode(bytes: &[u8], maximum: usize) -> Result<MacApplicationInventory> {
    ensure!(
        bytes.len() <= MAX_OUTPUT,
        "native application response exceeds bounds"
    );
    let response: Response = serde_json::from_slice(bytes)?;
    ensure!(
        response.paths.len() <= maximum,
        "native application count exceeds bounds"
    );
    let mut paths = std::collections::BTreeSet::new();
    let mut total = 0usize;
    for path in response.paths {
        validate_path(&path)?;
        ensure!(
            path.extension()
                .is_some_and(|ext| ext.eq_ignore_ascii_case("app")),
            "native application candidate is not an app bundle"
        );
        total = total
            .checked_add(path.as_os_str().len())
            .ok_or_else(|| anyhow::anyhow!("native application path budget overflow"))?;
        ensure!(
            total <= 2 * 1024 * 1024,
            "native application paths exceed bounds"
        );
        paths.insert(path);
    }
    Ok(MacApplicationInventory {
        paths: paths.into_iter().collect(),
        incomplete: !response.index_complete || response.limited || response.rejected > 0,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    unsafe extern "C" {
        fn quicksave_mac_inventory_protocol_fixture(
            output: *mut u8,
            capacity: usize,
            written: *mut usize,
        ) -> std::ffi::c_int;
    }
    #[test]
    fn linked_native_encoder_emits_real_json_booleans_without_native_discovery() {
        let mut output = [0u8; 1024];
        let mut written = 0;
        let status = unsafe {
            quicksave_mac_inventory_protocol_fixture(
                output.as_mut_ptr(),
                output.len(),
                &mut written,
            )
        };
        assert_eq!(status, 0);
        assert!(written <= output.len());
        let inventory = decode(&output[..written], 4096).unwrap();
        assert!(!inventory.incomplete);
        assert!(inventory.paths.is_empty());
        assert!(decode(
            br#"{"paths":[],"indexComplete":1,"limited":false,"rejected":0}"#,
            4096
        )
        .is_err());
    }
    #[test]
    fn linked_bridge_rejects_invalid_arguments_before_any_native_inventory_call() {
        let mut output = [0u8; 32];
        let mut written = 17usize;
        // No scope/pointer array: the C entry guard returns before creating any
        // Objective-C object, querying Spotlight, or accessing NSWorkspace.
        let status = unsafe {
            quicksave_mac_inventory(
                std::ptr::null(),
                0,
                1,
                output.as_mut_ptr(),
                output.len(),
                &mut written,
            )
        };
        assert_eq!(status, 1);
        assert_eq!(written, 17);
        assert_eq!(output, [0; 32]);
    }
    #[test]
    fn native_wire_validation_never_runs_workspace_or_queries_real_apps() {
        let value = br#"{"paths":["/isolated/One.app","/isolated/One.app"],"indexComplete":true,"limited":false,"rejected":0}"#;
        assert_eq!(decode(value, 4).unwrap().paths.len(), 1);
        assert!(decode(value, 1).is_err());
        assert!(decode(br#"{"paths":["/isolated/../Bad.app"],"indexComplete":true,"limited":false,"rejected":0}"#,4).is_err());
        assert!(decode(
            br#"{"paths":["/isolated/Bad.txt"],"indexComplete":true,"limited":false,"rejected":0}"#,
            4
        )
        .is_err());
        assert!(
            decode(
                br#"{"paths":[],"indexComplete":false,"limited":false,"rejected":0}"#,
                4
            )
            .unwrap()
            .incomplete
        );
    }
}
