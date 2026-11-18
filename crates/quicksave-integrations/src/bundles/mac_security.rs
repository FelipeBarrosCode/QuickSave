// SPDX-License-Identifier: GPL-3.0-only
//! Read-only Security/CoreFoundation calls. No signing identity, certificate
//! selection, keychain, account, subprocess or credential APIs are used.
//!
//! Constants/signatures follow Apple's SDK SecStaticCode.h / SecCode.h and
//! CoreFoundation headers. Only identifier and application-group entitlement
//! values are copied, under strict bounds. Callers revalidate native identities.

use super::backend::MacSigningEvidence;
use crate::parsers::macos;
use anyhow::{ensure, Result};
use std::ffi::{c_char, c_long, c_void};
use std::path::Path;
use std::ptr;

type CFTypeRef = *const c_void;
type CFStringRef = CFTypeRef;
type CFDictionaryRef = CFTypeRef;
type CFArrayRef = CFTypeRef;
type SecStaticCodeRef = CFTypeRef;

#[link(name = "Security", kind = "framework")]
unsafe extern "C" {
    fn SecStaticCodeCreateWithPath(path: CFTypeRef, flags: u32, code: *mut SecStaticCodeRef)
        -> i32;
    fn SecStaticCodeCheckValidity(
        code: SecStaticCodeRef,
        flags: u32,
        requirement: CFTypeRef,
    ) -> i32;
    fn SecCodeCopySigningInformation(
        code: SecStaticCodeRef,
        flags: u32,
        information: *mut CFDictionaryRef,
    ) -> i32;
    static kSecCodeInfoIdentifier: CFStringRef;
    static kSecCodeInfoEntitlementsDict: CFStringRef;
}

#[link(name = "CoreFoundation", kind = "framework")]
unsafe extern "C" {
    fn CFURLCreateFromFileSystemRepresentation(
        allocator: CFTypeRef,
        buffer: *const u8,
        length: c_long,
        is_directory: u8,
    ) -> CFTypeRef;
    fn CFRelease(value: CFTypeRef);
    fn CFGetTypeID(value: CFTypeRef) -> usize;
    fn CFDictionaryGetTypeID() -> usize;
    fn CFDictionaryGetCount(value: CFDictionaryRef) -> c_long;
    fn CFDictionaryGetValue(value: CFDictionaryRef, key: CFTypeRef) -> CFTypeRef;
    fn CFStringGetTypeID() -> usize;
    fn CFStringGetLength(value: CFStringRef) -> c_long;
    fn CFStringGetCString(
        value: CFStringRef,
        buffer: *mut c_char,
        size: c_long,
        encoding: u32,
    ) -> u8;
    fn CFStringCreateWithCString(
        allocator: CFTypeRef,
        bytes: *const c_char,
        encoding: u32,
    ) -> CFStringRef;
    fn CFArrayGetTypeID() -> usize;
    fn CFArrayGetCount(value: CFArrayRef) -> c_long;
    fn CFArrayGetValueAtIndex(value: CFArrayRef, index: c_long) -> CFTypeRef;
}

struct Owned(CFTypeRef);
impl Drop for Owned {
    fn drop(&mut self) {
        if !self.0.is_null() {
            // SAFETY: these are +1 Copy/Create results owned exactly once.
            unsafe { CFRelease(self.0) }
        }
    }
}

pub(super) fn signing_evidence(bundle: &Path) -> Result<MacSigningEvidence> {
    let path = bundle
        .to_str()
        .ok_or_else(|| anyhow::anyhow!("non-UTF8 bundle path"))?;
    ensure!(
        path.len() <= 4096 && !path.as_bytes().contains(&0),
        "invalid bundle path"
    );
    // SAFETY: input is bounded and valid for the duration of these read-only
    // calls. All copied CF references use RAII; borrowed references stay inside
    // their owning dictionary. No error/user dictionary values are logged.
    unsafe {
        let url = Owned(CFURLCreateFromFileSystemRepresentation(
            ptr::null(),
            path.as_ptr(),
            path.len() as c_long,
            1,
        ));
        ensure!(!url.0.is_null(), "unable to create bundle metadata URL");
        let mut code = ptr::null();
        if SecStaticCodeCreateWithPath(url.0, 0, &mut code) != 0 {
            return Ok(MacSigningEvidence::unavailable());
        }
        let code = Owned(code);
        ensure!(
            !code.0.is_null(),
            "Security returned a null static-code reference"
        );
        // kSecCSCheckAllArchitectures | kSecCSStrictValidate |
        // kSecCSDoNotValidateResources. Validate the executable's existing
        // signature/entitlements without recursively walking bundle resources
        // or framework links. kSecCSAllowNetworkAccess is deliberately absent.
        // This never signs, prompts or selects a signing identity.
        if SecStaticCodeCheckValidity(code.0, (1 << 0) | (1 << 4) | (1 << 2), ptr::null()) != 0 {
            return Ok(MacSigningEvidence::unavailable());
        }
        let mut dictionary = ptr::null();
        // kSecCSSigningInformation.
        if SecCodeCopySigningInformation(code.0, 1 << 1, &mut dictionary) != 0 {
            return Ok(MacSigningEvidence::unavailable());
        }
        let dictionary = Owned(dictionary);
        ensure_dictionary(dictionary.0)?;
        let identifier =
            bounded_string(CFDictionaryGetValue(dictionary.0, kSecCodeInfoIdentifier))?;
        macos::validate_identifier(&identifier)?;
        let entitlements = CFDictionaryGetValue(dictionary.0, kSecCodeInfoEntitlementsDict);
        let mut groups = Vec::new();
        if !entitlements.is_null() {
            ensure_dictionary(entitlements)?;
            // This key is read directly. No keychain access-group entitlement
            // or unrelated signed entitlement is fetched or copied.
            let key = Owned(CFStringCreateWithCString(
                ptr::null(),
                c"com.apple.security.application-groups".as_ptr(),
                0x08000100,
            ));
            ensure!(!key.0.is_null(), "unable to create entitlement lookup key");
            let array = CFDictionaryGetValue(entitlements, key.0);
            if !array.is_null() {
                ensure!(
                    CFGetTypeID(array) == CFArrayGetTypeID(),
                    "invalid signed application-group type"
                );
                let count = CFArrayGetCount(array);
                ensure!(
                    (0..=64).contains(&count),
                    "signed application-group bound exceeded"
                );
                for index in 0..count {
                    let group = bounded_string(CFArrayGetValueAtIndex(array, index))?;
                    macos::validate_identifier(&group)?;
                    ensure!(
                        !groups.contains(&group),
                        "duplicate signed application group"
                    );
                    groups.push(group);
                }
            }
        }
        groups.sort();
        Ok(MacSigningEvidence {
            signing_identifier: Some(identifier),
            application_groups: groups,
            signature_validated: true,
        })
    }
}

unsafe fn ensure_dictionary(value: CFTypeRef) -> Result<()> {
    ensure!(!value.is_null(), "missing signing dictionary");
    // SAFETY: nonnull borrowed/owned CF reference from Security.
    ensure!(
        unsafe { CFGetTypeID(value) == CFDictionaryGetTypeID() },
        "invalid signing dictionary type"
    );
    let count = unsafe { CFDictionaryGetCount(value) };
    ensure!(
        (0..=4096).contains(&count),
        "signing dictionary bound exceeded"
    );
    Ok(())
}

unsafe fn bounded_string(value: CFTypeRef) -> Result<String> {
    ensure!(!value.is_null(), "missing signed identifier");
    // SAFETY: type is checked before using CFString operations.
    ensure!(
        unsafe { CFGetTypeID(value) == CFStringGetTypeID() },
        "invalid signed identifier type"
    );
    let length = unsafe { CFStringGetLength(value) };
    ensure!(
        (1..=255).contains(&length),
        "signed identifier bound exceeded"
    );
    let mut buffer = [0u8; 1024];
    ensure!(
        unsafe {
            CFStringGetCString(
                value,
                buffer.as_mut_ptr().cast(),
                buffer.len() as c_long,
                0x08000100,
            )
        } != 0,
        "invalid signed identifier encoding"
    );
    let end = buffer
        .iter()
        .position(|b| *b == 0)
        .ok_or_else(|| anyhow::anyhow!("unterminated signed identifier"))?;
    Ok(std::str::from_utf8(&buffer[..end])?.to_owned())
}
