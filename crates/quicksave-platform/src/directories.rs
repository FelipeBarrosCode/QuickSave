// SPDX-License-Identifier: GPL-3.0-only

use anyhow::{ensure, Context, Result};
use std::path::{Component, Path, PathBuf};

#[allow(clippy::needless_return)]
pub(crate) fn home_directory() -> Result<PathBuf> {
    #[cfg(any(target_os = "macos", target_os = "linux"))]
    return native_home();
    #[cfg(windows)]
    return known_folder(&windows_sys::Win32::UI::Shell::FOLDERID_Profile);
    #[cfg(not(any(target_os = "macos", target_os = "linux", windows)))]
    anyhow::bail!("native account-home discovery is unsupported on this platform")
}

// Each target's early return deliberately keeps platform branches independent.
#[allow(clippy::needless_return)]
pub(crate) fn app_directories() -> Result<serde_json::Value> {
    #[cfg(target_os = "macos")]
    {
        // getpwuid_r is native account discovery, not a possibly overridden HOME.
        let home = native_home()?;
        let library = home.join("Library");
        let data = library.join("Application Support/QuickSave");
        return paths(
            "macos",
            "native-account-home-and-Apple-directory-layout",
            &data,
            &library.join("Preferences/QuickSave"),
            &library.join("Caches/QuickSave"),
            &data,
            &library.join("Logs/QuickSave"),
            &data.join("Runtime"),
        );
    }
    #[cfg(target_os = "linux")]
    {
        let home = native_home()?;
        let data = xdg("XDG_DATA_HOME", &home.join(".local/share"))?.join("QuickSave");
        let config = xdg("XDG_CONFIG_HOME", &home.join(".config"))?.join("QuickSave");
        let cache = xdg("XDG_CACHE_HOME", &home.join(".cache"))?.join("QuickSave");
        let state = xdg("XDG_STATE_HOME", &home.join(".local/state"))?.join("QuickSave");
        let runtime = match std::env::var_os("XDG_RUNTIME_DIR") {
            Some(value) if !value.is_empty() => {
                let base = PathBuf::from(value);
                validate_base(&base)?;
                base.join("QuickSave")
            }
            _ => state.join("Runtime"),
        };
        return paths(
            "linux",
            "XDG-Base-Directory-with-native-account-home-fallback",
            &data,
            &config,
            &cache,
            &state,
            &state.join("Logs"),
            &runtime,
        );
    }
    #[cfg(windows)]
    {
        use windows_sys::Win32::UI::Shell::{FOLDERID_LocalAppData, FOLDERID_RoamingAppData};
        let data = known_folder(&FOLDERID_LocalAppData)?.join("QuickSave");
        let config = known_folder(&FOLDERID_RoamingAppData)?.join("QuickSave");
        return paths(
            "windows",
            "SHGetKnownFolderPath-without-creation",
            &data,
            &config,
            &data.join("Cache"),
            &data.join("State"),
            &data.join("Logs"),
            &data.join("Runtime"),
        );
    }
    #[cfg(not(any(target_os = "macos", target_os = "linux", windows)))]
    anyhow::bail!("native application-directory discovery is unsupported on this platform")
}

#[allow(clippy::too_many_arguments)]
fn paths(
    platform: &str,
    discovery: &str,
    data: &Path,
    config: &Path,
    cache: &Path,
    state: &Path,
    logs: &Path,
    runtime: &Path,
) -> Result<serde_json::Value> {
    let mut output = serde_json::json!({
        "application": "QuickSave",
        "platform": platform,
        "discovery": discovery,
        "created": false,
    });
    for (key, path) in [
        ("data", data),
        ("config", config),
        ("cache", cache),
        ("state", state),
        ("logs", logs),
        ("runtime", runtime),
    ] {
        validate_base(path)?;
        output[key] = serde_json::Value::String(
            path.to_str()
                .context("application path must be UTF-8")?
                .to_owned(),
        );
    }
    Ok(output)
}

fn validate_base(path: &Path) -> Result<()> {
    let text = path
        .to_str()
        .context("application directory must be UTF-8")?;
    ensure!(
        path.is_absolute() && text.len() <= crate::MAX_PATH_BYTES && !text.contains('\0'),
        "application directory must be an absolute bounded native path"
    );
    ensure!(
        !path
            .components()
            .any(|component| { matches!(component, Component::ParentDir | Component::CurDir) })
            && !text
                .split(['/', '\\'])
                .any(|component| component == "." || component == ".."),
        "application directory contains traversal components"
    );
    Ok(())
}

#[cfg(target_os = "linux")]
fn xdg(variable: &str, fallback: &Path) -> Result<PathBuf> {
    match std::env::var_os(variable) {
        Some(value) if !value.is_empty() => {
            let path = PathBuf::from(value);
            validate_base(&path).with_context(|| format!("invalid {variable}"))?;
            Ok(path)
        }
        _ => Ok(fallback.to_path_buf()),
    }
}

#[cfg(any(target_os = "macos", target_os = "linux"))]
fn native_home() -> Result<PathBuf> {
    use std::{ffi::CStr, mem::MaybeUninit};
    // Bound native NSS output rather than trusting a potentially huge sysconf.
    let mut bytes = 16 * 1024;
    loop {
        let mut buffer = vec![0u8; bytes];
        let mut entry = MaybeUninit::<libc::passwd>::uninit();
        let mut result = std::ptr::null_mut();
        // SAFETY: buffers remain live; getpwuid_r initializes entry on success.
        let status = unsafe {
            libc::getpwuid_r(
                libc::geteuid(),
                entry.as_mut_ptr(),
                buffer.as_mut_ptr().cast(),
                buffer.len(),
                &mut result,
            )
        };
        if status == libc::ERANGE && bytes < 1024 * 1024 {
            bytes *= 2;
            continue;
        }
        if status != 0 {
            return Err(std::io::Error::from_raw_os_error(status))
                .context("discover native account home");
        }
        ensure!(
            !result.is_null(),
            "native account has no home directory record"
        );
        let entry = unsafe { entry.assume_init() };
        ensure!(!entry.pw_dir.is_null(), "native account home is absent");
        let text = unsafe { CStr::from_ptr(entry.pw_dir) }
            .to_str()
            .context("native account home must be UTF-8")?;
        let home = PathBuf::from(text);
        validate_base(&home)?;
        return Ok(home);
    }
}

#[cfg(windows)]
fn known_folder(id: &windows_sys::core::GUID) -> Result<PathBuf> {
    use windows_sys::Win32::{System::Com::CoTaskMemFree, UI::Shell::SHGetKnownFolderPath};
    let mut raw = std::ptr::null_mut();
    // KF_FLAG_DONT_VERIFY avoids probing or creating application state. In
    // particular, KF_FLAG_CREATE is never set.
    let status = unsafe { SHGetKnownFolderPath(id, 0x4000, std::ptr::null_mut(), &mut raw) };
    if status < 0 {
        if !raw.is_null() {
            unsafe { CoTaskMemFree(raw.cast()) };
        }
        anyhow::bail!(
            "SHGetKnownFolderPath failed with HRESULT 0x{:08x}",
            status as u32
        );
    }
    ensure!(!raw.is_null(), "known-folder API returned an absent path");
    let result = (|| -> Result<PathBuf> {
        let mut length = 0;
        while length < crate::MAX_PATH_BYTES / 2 && unsafe { *raw.add(length) } != 0 {
            length += 1;
        }
        ensure!(
            length < crate::MAX_PATH_BYTES / 2,
            "known-folder path exceeds limit"
        );
        let text = String::from_utf16(unsafe { std::slice::from_raw_parts(raw, length) })
            .context("known-folder path must be valid Unicode")?;
        let path = PathBuf::from(text);
        validate_base(&path)?;
        Ok(path)
    })();
    unsafe { CoTaskMemFree(raw.cast()) };
    result
}
