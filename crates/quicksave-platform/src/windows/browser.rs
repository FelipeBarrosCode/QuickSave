// SPDX-License-Identifier: GPL-3.0-only
//! Native OAuth browser handoff at the platform unsafe-code audit boundary.
//! Original QuickSave implementation, moved from the service without weakening
//! its HTTPS origin boundary, bounded caller wait, or single-worker ownership.
//!
//! Parent wiring: Windows-only public export of `open_oauth_browser`, `url = "2"`,
//! `zeroize = "1"`, and windows-sys's `Win32_System_Registry` feature alongside
//! its existing Shell/COM/Foundation features. No helper executable, PATH,
//! environment override, account probe, or browser termination is involved.
//!
//! Shell/COM extensions cannot safely be killed. After the three-second caller
//! deadline the outcome is UNKNOWN, including possible late launch. One owned
//! worker retains admission until the native call and cleanup actually return.
//! An accepted OS handoff is not authentication or a provider connection.
//!
//! ABI references:
//! https://learn.microsoft.com/en-us/windows/win32/api/shellapi/nf-shellapi-shellexecuteexw
//! https://learn.microsoft.com/en-us/windows/win32/api/shellapi/ns-shellapi-shellexecuteinfow
//! https://learn.microsoft.com/en-us/windows/win32/api/combaseapi/nf-combaseapi-coinitializeex

use anyhow::{anyhow, ensure, Result};
use url::Url;

const MAX_AUTHORIZATION_URL_BYTES: usize = 16 * 1024;

/// Defense in depth, independent of any service feature flag or validation.
/// Keep the exact origin/canonicalization policy aligned with quicksave-oauth's
/// pure `validate_authorization_browser_url`; do not depend on that higher layer.
fn validate_browser_url(value: &str) -> Result<()> {
    ensure!(
        value.len() <= MAX_AUTHORIZATION_URL_BYTES
            && !value
                .chars()
                .any(|character| character.is_control() || character.is_whitespace()),
        "Invalid native OAuth authorization URL"
    );
    let url = Url::parse(value).map_err(|_| anyhow!("Invalid native OAuth authorization URL"))?;
    ensure!(
        url.scheme() == "https"
            && url.username().is_empty()
            && url.password().is_none()
            && url.fragment().is_none()
            && url.port_or_known_default() == Some(443)
            && matches!(
                url.host_str(),
                Some(
                    "accounts.google.com"
                        | "login.microsoftonline.com"
                        | "www.dropbox.com"
                        | "account.box.com"
                )
            ),
        "Native OAuth authorization origin is not allowed"
    );
    ensure!(
        url.as_str() == value && !value.contains('\\'),
        "Native OAuth authorization URL is not canonical"
    );
    Ok(())
}

#[cfg(any(windows, test))]
fn checked_shell_launch(success: bool, instance: usize, native_error: u32) -> Result<()> {
    ensure!(
        success && instance > 32,
        "The OS browser launch failed (native error {native_error}, shell status {instance})"
    );
    Ok(())
}

/// Safe, Windows-only native OAuth handoff. Only canonical HTTPS authorization
/// origins for Google, Microsoft, Dropbox and Box are allowed. Native consent
/// remains the caller's responsibility; this API never authenticates an account.
/// Errors contain no authorization URL, state, code, client ID, or secret.
#[cfg(windows)]
pub fn open_oauth_browser(url: &str) -> Result<()> {
    validate_browser_url(url)?;
    native::open(url)
}

#[cfg(windows)]
mod native {
    use super::*;
    use anyhow::bail;
    use std::{
        mem::size_of,
        ptr,
        sync::{
            atomic::{AtomicBool, Ordering},
            mpsc,
        },
        time::{Duration, Instant},
    };
    use windows_sys::Win32::{
        Foundation::{CloseHandle, GetLastError, HANDLE, INVALID_HANDLE_VALUE},
        System::Com::{
            CoInitializeEx, CoUninitialize, COINIT_APARTMENTTHREADED, COINIT_DISABLE_OLE1DDE,
        },
        UI::Shell::{
            ShellExecuteExW, SEE_MASK_FLAG_NO_UI, SEE_MASK_NOASYNC, SEE_MASK_NOCLOSEPROCESS,
            SEE_MASK_UNICODE, SHELLEXECUTEINFOW,
        },
    };
    use zeroize::Zeroizing;

    static OPENING: AtomicBool = AtomicBool::new(false);
    const DEADLINE: Duration = Duration::from_secs(3);
    const MASK: u32 =
        SEE_MASK_NOCLOSEPROCESS | SEE_MASK_NOASYNC | SEE_MASK_FLAG_NO_UI | SEE_MASK_UNICODE;
    const _: () =
        assert!(size_of::<SHELLEXECUTEINFOW>() == if size_of::<usize>() == 8 { 112 } else { 60 });

    struct Flight;
    impl Drop for Flight {
        fn drop(&mut self) {
            OPENING.store(false, Ordering::Release);
        }
    }

    struct Apartment;
    impl Drop for Apartment {
        fn drop(&mut self) {
            // SAFETY: constructed only after successful CoInitializeEx on this
            // worker; S_OK and S_FALSE both require exactly one CoUninitialize.
            unsafe { CoUninitialize() };
        }
    }

    struct Process(HANDLE);
    impl Process {
        fn close(mut self) -> Result<()> {
            if self.0.is_null() {
                return Ok(());
            }
            ensure!(
                self.0 != INVALID_HANDLE_VALUE,
                "The OS returned an invalid browser process handle"
            );
            // SAFETY: this is the owned hProcess returned by ShellExecuteExW,
            // never a caller-supplied, borrowed, or pseudo-process handle.
            let closed = unsafe { CloseHandle(self.0) };
            ensure!(
                closed != 0,
                "The native browser process handle could not be released"
            );
            self.0 = ptr::null_mut();
            Ok(())
        }
    }
    impl Drop for Process {
        fn drop(&mut self) {
            if !self.0.is_null() && self.0 != INVALID_HANDLE_VALUE {
                // SAFETY: same owned process handle; best-effort release only
                // on an earlier close/error/unwind path. It is never terminated.
                unsafe { CloseHandle(self.0) };
            }
        }
    }

    fn information(verb: &[u16], url: &[u16]) -> SHELLEXECUTEINFOW {
        SHELLEXECUTEINFOW {
            cbSize: size_of::<SHELLEXECUTEINFOW>() as u32,
            fMask: MASK,
            lpVerb: verb.as_ptr(),
            lpFile: url.as_ptr(),
            nShow: 1, // SW_SHOWNORMAL; no wait for input idle or browser exit.
            ..SHELLEXECUTEINFOW::default()
        }
    }

    fn launch(url: Zeroizing<Vec<u16>>) -> Result<()> {
        // SAFETY: a dedicated fresh worker initializes its own COM STA; there
        // is no shared apartment or caller-owned native pointer.
        let initialized = unsafe {
            CoInitializeEx(
                ptr::null(),
                (COINIT_APARTMENTTHREADED | COINIT_DISABLE_OLE1DDE) as u32,
            )
        };
        ensure!(initialized >= 0, "Native browser COM initialization failed");
        let _apartment = Apartment;
        let verb: Vec<u16> = "open".encode_utf16().chain(Some(0)).collect();
        let mut info = information(&verb, &url);
        // SAFETY: the generated native ABI/size is used; the verb and bounded,
        // validated URL are NUL-terminated and remain live for the whole call.
        // All optional class/ID-list/parameter/directory/window fields are null.
        let success = unsafe { ShellExecuteExW(&mut info) } != 0;
        let error = if success {
            0
        } else {
            // SAFETY: read immediately on the worker that made the failed call.
            unsafe { GetLastError() }
        };
        let process = Process(info.hProcess);
        // A null process is valid when the OS reuses an existing browser. Close
        // any returned handle, never kill or wait for the user's browser.
        let launched = checked_shell_launch(success, info.hInstApp as usize, error);
        let closed = process.close();
        launched.and(closed)
    }

    pub(super) fn open(url: &str) -> Result<()> {
        ensure!(
            OPENING
                .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
                .is_ok(),
            "A native OS browser handoff is still pending"
        );
        let flight = Flight;
        let url = Zeroizing::new(url.encode_utf16().chain(Some(0)).collect::<Vec<_>>());
        let deadline = Instant::now() + DEADLINE;
        let (send, receive) = mpsc::sync_channel(1);
        let worker = std::thread::Builder::new()
            .name("quicksave-browser-handoff".into())
            .spawn(move || {
                let _flight = flight;
                let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| launch(url)))
                    .unwrap_or_else(|_| Err(anyhow!("The native OS browser handoff failed")));
                let _ = send.send((Instant::now(), result));
            })
            .map_err(|_| anyhow!("The native OS browser handoff thread could not start"))?;
        // Extensible Shell/COM code cannot safely be killed. Bound the caller
        // wait and outstanding worker count, not the OS call's execution time.
        let reply = receive.recv_timeout(deadline.saturating_duration_since(Instant::now()));
        drop(worker); // Never join an unresponsive native extension here.
        match reply {
            Ok((completed, result)) if completed <= deadline => result,
            _ => bail!("The native browser handoff exceeded its launch deadline; the OS outcome is unknown. No OAuth connection completed."),
        }
    }

    #[cfg(test)]
    mod tests {
        use super::*;
        use std::{ffi::c_void, mem::offset_of};

        #[test]
        fn actual_win32_abi_and_launch_parameters_are_pure_and_never_call_the_os() {
            // Type checks reference the generated real Win32 prototypes, never
            // substitute a hand-written FFI struct or invoke these functions.
            let _safe_api: fn(&str) -> Result<()> = super::super::open_oauth_browser;
            let _shell: unsafe extern "system" fn(*mut SHELLEXECUTEINFOW) -> i32 = ShellExecuteExW;
            let _initialize: unsafe extern "system" fn(*const c_void, u32) -> i32 = CoInitializeEx;
            let _uninitialize: unsafe extern "system" fn() = CoUninitialize;
            let _close: unsafe extern "system" fn(HANDLE) -> i32 = CloseHandle;
            assert_eq!(
                size_of::<SHELLEXECUTEINFOW>(),
                if size_of::<usize>() == 8 { 112 } else { 60 }
            );
            assert_eq!(
                offset_of!(SHELLEXECUTEINFOW, hProcess),
                if size_of::<usize>() == 8 { 104 } else { 56 }
            );
            let url: Vec<u16> = "https://account.box.com/api/oauth2/authorize?client_id=synthetic"
                .encode_utf16()
                .chain(Some(0))
                .collect();
            let verb: Vec<u16> = "open".encode_utf16().chain(Some(0)).collect();
            let info = information(&verb, &url);
            // Copy fields to locals rather than reference packed x86 fields.
            let size = info.cbSize;
            let mask = info.fMask;
            let supplied_verb = info.lpVerb;
            let supplied_url = info.lpFile;
            assert_eq!(size as usize, size_of::<SHELLEXECUTEINFOW>());
            assert_eq!(mask, 0x40 | 0x100 | 0x400 | 0x4000);
            assert_eq!(mask & (0x200 | 0x0c | 0x0080_0000 | 0x0200_0000), 0);
            assert!(info.hwnd.is_null() && info.lpIDList.is_null());
            assert!(info.lpParameters.is_null() && info.lpDirectory.is_null());
            assert!(info.lpClass.is_null() && info.hkeyClass.is_null());
            assert!(info.hInstApp.is_null() && info.hProcess.is_null());
            assert_eq!(supplied_verb, verb.as_ptr());
            assert_eq!(supplied_url, url.as_ptr());
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn platform_revalidates_all_four_exact_provider_origins_without_os_calls() {
        for url in [
            "https://accounts.google.com/o/oauth2/v2/auth?client_id=synthetic",
            "https://login.microsoftonline.com/common/oauth2/v2.0/authorize?client_id=synthetic",
            "https://www.dropbox.com/oauth2/authorize?client_id=synthetic",
            "https://account.box.com/api/oauth2/authorize?client_id=synthetic",
        ] {
            assert!(validate_browser_url(url).is_ok());
        }
        for url in [
            "",
            "file:///synthetic/unsafe",
            "http://account.box.com/api/oauth2/authorize",
            "https://account.box.com.attacker.invalid/",
            "https://accounts.google.com.attacker.invalid/oauth",
            "https://login.microsoftonline.com.attacker.invalid/",
            "https://www.dropbox.com.attacker.invalid/",
            "https://account.box.com@attacker.invalid/",
            "https://attacker.invalid@account.box.com/",
            "https://account.box.com:444/",
            "https://account.box.com:443/",
            "https://account.box.com\\@attacker.invalid/",
            "https://account.box.com/#fragment",
            "https://%61ccount.box.com/",
            "https://ACCOUNT.BOX.COM/",
            "https://account.box.com/ bad",
            "https://account.box.com/\0synthetic",
            "https://account.box.com/\nsynthetic",
            "https://account.box.com/\u{2003}synthetic",
        ] {
            assert!(validate_browser_url(url).is_err());
        }
    }

    #[test]
    fn platform_url_byte_bound_and_rejections_do_not_disclose_authorization_parameters() {
        let prefix = "https://account.box.com/?state=";
        let mut bounded = prefix.to_owned();
        bounded.extend(std::iter::repeat_n(
            's',
            MAX_AUTHORIZATION_URL_BYTES - prefix.len(),
        ));
        assert!(validate_browser_url(&bounded).is_ok());
        bounded.push('s');
        assert!(validate_browser_url(&bounded).is_err());
        let error = validate_browser_url(
            "https://account.box.com.attacker.invalid/?state=PRIVATE-SYNTHETIC-STATE",
        )
        .unwrap_err()
        .to_string();
        assert!(!error.contains("PRIVATE-SYNTHETIC-STATE"));
        assert!(!error.contains("https://"));
    }

    #[test]
    fn shell_result_validation_is_pure_and_requires_real_os_success() {
        assert!(checked_shell_launch(true, 33, 0).is_ok());
        assert!(checked_shell_launch(true, 32, 0).is_err());
        assert!(checked_shell_launch(false, 33, 5).is_err());
        assert!(checked_shell_launch(false, 0, 1155).is_err());
    }
}
