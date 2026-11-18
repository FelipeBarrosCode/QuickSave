// SPDX-License-Identifier: GPL-3.0-only
//! In-process, private native-host bridge to the pinned No Land shared-storage
//! engine. No socket, provisioning, SSH or lifecycle process is started.

#[cfg(unix)]
pub mod capture_control;
pub mod catalog_control;
#[cfg(unix)]
mod native;
pub mod operation_control;
#[cfg(any(unix, windows))]
pub mod provider_lifecycle;
#[cfg(windows)]
mod windows;
#[cfg(windows)]
pub use windows::capture as capture_control;
#[cfg(windows)]
pub use windows::{native_capture_root_token, NativeEngine, SourceRuntime};
#[cfg(unix)]
pub fn native_capture_root_token(app: &str, root: &str) -> anyhow::Result<String> {
    anyhow::ensure!(
        !app.is_empty() && app.len() <= 512 && !root.is_empty() && root.len() <= 512,
        "Native application/root identity exceeds its bound"
    );
    Ok(noland_state_agent::native_host::native_root_token(
        &noland_state_core::AppId(app.into()),
        root,
    ))
}
#[cfg(unix)]
pub use native::observation_control;
#[cfg(unix)]
pub use native::{NativeEngine, SourceRuntime};

#[cfg(not(any(unix, windows)))]
mod unsupported;
#[cfg(not(any(unix, windows)))]
pub use unsupported::NativeEngine;
