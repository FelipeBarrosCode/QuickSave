// SPDX-License-Identifier: GPL-3.0-only
//! Metadata-only Secret Service inventory. Backend semantics verified against
//! keyring 3.6.3 `src/secret_service.rs`: default-target items in any collection,
//! plus missing-target legacy items only in the default collection.
//!
//! Direct libdbus is intentional: dbus-secret-service 4.1.0 hides its connection,
//! preventing native receive limits from being installed. No secret session,
//! Unlock, prompt, GetSecret, write, delete, or activation call is made here.

use anyhow::{ensure, Result};
use libdbus_sys as ffi;
use std::{
    collections::{BTreeMap, BTreeSet},
    ffi::{c_char, c_void, CString},
    marker::PhantomData,
    ptr,
    sync::OnceLock,
    time::{Duration, Instant},
};

const MAX_ACCOUNTS: usize = 4096;
const MAX_ACCOUNT_BYTES: usize = 512;
const MAX_PATH_BYTES: usize = 1024;
const MAX_ATTRIBUTES: usize = 64;
const MAX_METADATA_BYTES: usize = 4096;
const MAX_MESSAGE_BYTES: i64 = 8 * 1024 * 1024;
const SERVICE_PATH: &str = "/org/freedesktop/secrets";
const SERVICE_INTERFACE: &str = "org.freedesktop.Secret.Service";
const PROPERTIES_INTERFACE: &str = "org.freedesktop.DBus.Properties";

pub(super) fn accounts(service: &str) -> Result<Vec<String>> {
    ensure!(
        service == super::QUICKSAVE_VAULT_SERVICE,
        "only QuickSave inventory is permitted"
    );
    let connection = Connection::open()?;
    let owner_reply = connection.call(
        "org.freedesktop.DBus",
        "/org/freedesktop/DBus",
        "org.freedesktop.DBus",
        "GetNameOwner",
        |i| i.append_string("org.freedesktop.secrets"),
    )?;
    let mut owner_cursor = owner_reply.cursor()?;
    let owner = owner_cursor.string(ffi::DBUS_TYPE_STRING, 256)?;
    owner_cursor.end()?;
    ensure!(owner.starts_with(':'), "invalid Secret Service owner");
    let initial = snapshot(&connection, &owner, service)?;
    // A second metadata pass rejects observable collection/item/attribute changes.
    // This is not an atomic OS snapshot; the migration must still verify reads.
    let verification = snapshot(&connection, &owner, service)?;
    ensure!(
        initial == verification,
        "QuickSave legacy inventory changed during enumeration"
    );
    let current_owner_reply = connection.call(
        "org.freedesktop.DBus",
        "/org/freedesktop/DBus",
        "org.freedesktop.DBus",
        "GetNameOwner",
        |i| i.append_string("org.freedesktop.secrets"),
    )?;
    let mut current_owner = current_owner_reply.cursor()?;
    ensure!(
        current_owner.string(ffi::DBUS_TYPE_STRING, 256)? == owner,
        "Secret Service owner changed during enumeration"
    );
    current_owner.end()?;
    Ok(initial
        .into_values()
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect())
}

fn snapshot(
    connection: &Connection,
    owner: &str,
    service: &str,
) -> Result<BTreeMap<String, String>> {
    let reply = connection.call(owner, SERVICE_PATH, SERVICE_INTERFACE, "ReadAlias", |i| {
        i.append_string("default")
    })?;
    let mut cursor = reply.cursor()?;
    let default_collection = cursor.string(ffi::DBUS_TYPE_OBJECT_PATH, MAX_PATH_BYTES)?;
    cursor.end()?;
    ensure!(
        default_collection != "/",
        "default Secret Service collection is unavailable; complete legacy inventory cannot be proven"
    );
    let all = search(
        connection,
        owner,
        SERVICE_PATH,
        SERVICE_INTERFACE,
        service,
        true,
    )?;
    let default = search(
        connection,
        owner,
        &default_collection,
        "org.freedesktop.Secret.Collection",
        service,
        false,
    )?;
    ensure!(
        default.is_subset(&all),
        "Secret Service collection inventory disagrees with service inventory"
    );
    let mut result = BTreeMap::new();
    let mut seen_accounts = BTreeSet::new();
    for path in &all {
        let reply = connection.call(owner, path, PROPERTIES_INTERFACE, "Get", |i| {
            i.append_string("org.freedesktop.Secret.Item")?;
            i.append_string("Attributes")
        })?;
        let mut cursor = reply.cursor()?;
        let mut variant = cursor.container(ffi::DBUS_TYPE_VARIANT)?;
        let attributes = variant.attributes()?;
        variant.end()?;
        cursor.end()?;
        let Some(account) = select_account(&attributes, service, default.contains(path))? else {
            continue;
        };
        ensure!(
            seen_accounts.insert(account.clone()),
            "duplicate QuickSave legacy account; migration cannot choose an item"
        );
        result.insert(path.clone(), account.clone());
    }
    Ok(result)
}

fn select_account<'a>(
    attributes: &'a BTreeMap<String, String>,
    service: &str,
    in_default_collection: bool,
) -> Result<Option<&'a String>> {
    ensure!(
        attributes.get("service").map(String::as_str) == Some(service),
        "Secret Service returned a foreign or changed item"
    );
    match attributes.get("target").map(String::as_str) {
        Some("default") => {}
        None if in_default_collection => {}
        _ => return Ok(None),
    }
    let account = attributes
        .get("username")
        .ok_or_else(|| anyhow::anyhow!("QuickSave legacy item has no account"))?;
    validate_account(account)?;
    Ok(Some(account))
}

fn validate_account(account: &str) -> Result<()> {
    ensure!(
        !account.is_empty()
            && account.len() <= MAX_ACCOUNT_BYTES
            && !account.chars().any(char::is_control),
        "invalid QuickSave legacy account"
    );
    Ok(())
}

fn search(
    connection: &Connection,
    owner: &str,
    path: &str,
    interface: &str,
    service: &str,
    service_wide: bool,
) -> Result<BTreeSet<String>> {
    let reply = connection.call(owner, path, interface, "SearchItems", |i| {
        i.append_service_filter(service)
    })?;
    let mut cursor = reply.cursor()?;
    let mut paths = BTreeSet::new();
    cursor.paths(&mut paths)?;
    if service_wide {
        // Both arrays are mandatory: locked entries must never be omitted.
        cursor.paths(&mut paths)?;
    }
    cursor.end()?;
    Ok(paths)
}

struct Error(ffi::DBusError);
impl Error {
    fn new() -> Self {
        // SAFETY: initialized by libdbus before any use.
        let mut value = unsafe { std::mem::zeroed() };
        unsafe { ffi::dbus_error_init(&mut value) };
        Self(value)
    }
}
impl Drop for Error {
    fn drop(&mut self) {
        unsafe { ffi::dbus_error_free(&mut self.0) };
    }
}

struct Connection {
    raw: *mut ffi::DBusConnection,
    deadline: Instant,
}
impl Connection {
    fn open() -> Result<Self> {
        static INITIALIZED: OnceLock<bool> = OnceLock::new();
        ensure!(
            *INITIALIZED.get_or_init(|| unsafe { ffi::dbus_threads_init_default() != 0 }),
            "native D-Bus initialization failed"
        );
        // Never use autolaunch or a helper, nor a remotely addressed bus.
        let address = std::env::var("DBUS_SESSION_BUS_ADDRESS")
            .map_err(|_| anyhow::anyhow!("local Secret Service session bus is unavailable"))?;
        ensure!(
            address.len() <= 4096
                && (address.starts_with("unix:path=") || address.starts_with("unix:abstract="))
                && !address.contains(';'),
            "unsupported Secret Service session bus address"
        );
        let address = CString::new(address)?;
        let mut error = Error::new();
        let raw = unsafe { ffi::dbus_connection_open_private(address.as_ptr(), &mut error.0) };
        ensure!(!raw.is_null(), "Secret Service bus connection failed");
        let connection = Self {
            raw,
            deadline: Instant::now() + Duration::from_secs(60),
        };
        // Install limits before registration or any message exchange. libdbus
        // closes the connection on oversized messages rather than truncating.
        unsafe {
            ffi::dbus_connection_set_exit_on_disconnect(raw, 0);
            ffi::dbus_connection_set_max_message_size(raw, MAX_MESSAGE_BYTES as _);
            ffi::dbus_connection_set_max_received_size(raw, (2 * MAX_MESSAGE_BYTES) as _);
            ffi::dbus_connection_set_max_message_unix_fds(raw, 0);
            ffi::dbus_connection_set_max_received_unix_fds(raw, 0);
        }
        // Register via the bounded, finite-time Hello call, not the library's
        // registration helper (which chooses its own timeout).
        let hello = connection.call(
            "org.freedesktop.DBus",
            "/org/freedesktop/DBus",
            "org.freedesktop.DBus",
            "Hello",
            |_| Ok(()),
        )?;
        let mut cursor = hello.cursor()?;
        let unique = cursor.string(ffi::DBUS_TYPE_STRING, 256)?;
        cursor.end()?;
        ensure!(unique.starts_with(':'), "invalid session bus identity");
        Ok(connection)
    }

    fn call(
        &self,
        destination: &str,
        path: &str,
        interface: &str,
        method: &str,
        append: impl FnOnce(&mut Cursor<'_>) -> Result<()>,
    ) -> Result<Message> {
        let remaining = self.deadline.saturating_duration_since(Instant::now());
        ensure!(!remaining.is_zero(), "Secret Service inventory timed out");
        let destination = CString::new(destination)?;
        let path = CString::new(path)?;
        let interface = CString::new(interface)?;
        let method = CString::new(method)?;
        let raw = unsafe {
            ffi::dbus_message_new_method_call(
                destination.as_ptr(),
                path.as_ptr(),
                interface.as_ptr(),
                method.as_ptr(),
            )
        };
        ensure!(!raw.is_null(), "native inventory message allocation failed");
        let request = Message(raw);
        unsafe { ffi::dbus_message_set_auto_start(request.0, 0) };
        let mut iter = unsafe { std::mem::zeroed() };
        unsafe { ffi::dbus_message_iter_init_append(request.0, &mut iter) };
        append(&mut Cursor {
            iter,
            _message: PhantomData,
        })?;
        let mut error = Error::new();
        let raw = unsafe {
            ffi::dbus_connection_send_with_reply_and_block(
                self.raw,
                request.0,
                remaining.as_millis().min(5000) as i32,
                &mut error.0,
            )
        };
        ensure!(
            !raw.is_null(),
            "complete Secret Service metadata inventory failed; source credentials are unchanged"
        );
        let reply = Message(raw);
        ensure!(
            unsafe { ffi::dbus_message_get_type(reply.0) }
                == ffi::DBusMessageType::MethodReturn as i32,
            "Secret Service metadata request failed"
        );
        Ok(reply)
    }
}
impl Drop for Connection {
    fn drop(&mut self) {
        unsafe {
            ffi::dbus_connection_close(self.raw);
            ffi::dbus_connection_unref(self.raw);
        }
    }
}

struct Message(*mut ffi::DBusMessage);
impl Message {
    fn cursor(&self) -> Result<Cursor<'_>> {
        let mut iter = unsafe { std::mem::zeroed() };
        ensure!(
            unsafe { ffi::dbus_message_iter_init(self.0, &mut iter) } != 0,
            "empty Secret Service metadata response"
        );
        Ok(Cursor {
            iter,
            _message: PhantomData,
        })
    }
}
impl Drop for Message {
    fn drop(&mut self) {
        unsafe { ffi::dbus_message_unref(self.0) };
    }
}

// Cursor lifetimes are bounded by the owning message. All raw pointers below
// come from a live libdbus message, whose wire types libdbus validated first.
struct Cursor<'a> {
    iter: ffi::DBusMessageIter,
    _message: PhantomData<&'a Message>,
}
impl<'a> Cursor<'a> {
    fn kind(&mut self) -> i32 {
        unsafe { ffi::dbus_message_iter_get_arg_type(&mut self.iter) }
    }
    fn next(&mut self) {
        unsafe { ffi::dbus_message_iter_next(&mut self.iter) };
    }
    fn end(&mut self) -> Result<()> {
        ensure!(
            self.kind() == ffi::DBUS_TYPE_INVALID,
            "unexpected inventory metadata fields"
        );
        Ok(())
    }
    fn string(&mut self, kind: i32, max: usize) -> Result<String> {
        ensure!(self.kind() == kind, "invalid inventory metadata field type");
        let mut value: *const c_char = ptr::null();
        unsafe {
            ffi::dbus_message_iter_get_basic(&mut self.iter, &mut value as *mut _ as *mut c_void)
        };
        ensure!(!value.is_null(), "null inventory metadata");
        // libdbus guarantees NUL termination. Scan only the caller's bound.
        let mut length = 0;
        while length <= max && unsafe { *value.add(length) } != 0 {
            length += 1;
        }
        ensure!(length <= max, "inventory metadata exceeds size limit");
        let bytes = unsafe { std::slice::from_raw_parts(value.cast::<u8>(), length) };
        let value = std::str::from_utf8(bytes)
            .map_err(|_| anyhow::anyhow!("invalid inventory metadata encoding"))?
            .to_owned();
        self.next();
        Ok(value)
    }
    fn container(&mut self, kind: i32) -> Result<Cursor<'a>> {
        ensure!(self.kind() == kind, "invalid inventory metadata container");
        let mut iter = unsafe { std::mem::zeroed() };
        unsafe { ffi::dbus_message_iter_recurse(&mut self.iter, &mut iter) };
        self.next();
        Ok(Cursor {
            iter,
            _message: PhantomData,
        })
    }
    fn paths(&mut self, result: &mut BTreeSet<String>) -> Result<()> {
        ensure!(
            self.kind() == ffi::DBUS_TYPE_ARRAY
                && unsafe { ffi::dbus_message_iter_get_element_type(&mut self.iter) }
                    == ffi::DBUS_TYPE_OBJECT_PATH,
            "invalid inventory path array type"
        );
        let mut array = self.container(ffi::DBUS_TYPE_ARRAY)?;
        while array.kind() != ffi::DBUS_TYPE_INVALID {
            ensure!(
                result.len() < MAX_ACCOUNTS,
                "legacy inventory exceeds 4096 items"
            );
            let path = array.string(ffi::DBUS_TYPE_OBJECT_PATH, MAX_PATH_BYTES)?;
            ensure!(result.insert(path), "duplicate legacy inventory item");
        }
        Ok(())
    }
    fn attributes(&mut self) -> Result<BTreeMap<String, String>> {
        ensure!(
            self.kind() == ffi::DBUS_TYPE_ARRAY
                && unsafe { ffi::dbus_message_iter_get_element_type(&mut self.iter) }
                    == ffi::DBUS_TYPE_DICT_ENTRY,
            "invalid inventory attribute array type"
        );
        let mut array = self.container(ffi::DBUS_TYPE_ARRAY)?;
        let mut result = BTreeMap::new();
        while array.kind() != ffi::DBUS_TYPE_INVALID {
            ensure!(
                result.len() < MAX_ATTRIBUTES,
                "too many legacy item attributes"
            );
            let mut entry = array.container(ffi::DBUS_TYPE_DICT_ENTRY)?;
            let key = entry.string(ffi::DBUS_TYPE_STRING, MAX_METADATA_BYTES)?;
            let value = entry.string(ffi::DBUS_TYPE_STRING, MAX_METADATA_BYTES)?;
            entry.end()?;
            ensure!(
                result.insert(key, value).is_none(),
                "duplicate legacy item attribute"
            );
        }
        Ok(result)
    }
    fn append_string(&mut self, value: &str) -> Result<()> {
        let value = CString::new(value)?;
        let raw = value.as_ptr();
        ensure!(
            unsafe {
                ffi::dbus_message_iter_append_basic(
                    &mut self.iter,
                    ffi::DBUS_TYPE_STRING,
                    &raw as *const _ as *const c_void,
                )
            } != 0,
            "inventory message allocation failed"
        );
        Ok(())
    }
    fn append_service_filter(&mut self, service: &str) -> Result<()> {
        let signature = CString::new("{ss}")?;
        let mut array = unsafe { std::mem::zeroed() };
        ensure!(
            unsafe {
                ffi::dbus_message_iter_open_container(
                    &mut self.iter,
                    ffi::DBUS_TYPE_ARRAY,
                    signature.as_ptr(),
                    &mut array,
                )
            } != 0,
            "inventory filter allocation failed"
        );
        let mut array = Cursor {
            iter: array,
            _message: PhantomData,
        };
        let mut entry = unsafe { std::mem::zeroed() };
        ensure!(
            unsafe {
                ffi::dbus_message_iter_open_container(
                    &mut array.iter,
                    ffi::DBUS_TYPE_DICT_ENTRY,
                    ptr::null(),
                    &mut entry,
                )
            } != 0,
            "inventory filter allocation failed"
        );
        let mut entry = Cursor {
            iter: entry,
            _message: PhantomData,
        };
        entry.append_string("service")?;
        entry.append_string(service)?;
        ensure!(
            unsafe { ffi::dbus_message_iter_close_container(&mut array.iter, &mut entry.iter) }
                != 0
                && unsafe {
                    ffi::dbus_message_iter_close_container(&mut self.iter, &mut array.iter)
                } != 0,
            "inventory filter allocation failed"
        );
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn account_validation_is_byte_bounded_and_rejects_controls() {
        for account in [
            "inactive.authority",
            "provider.old",
            "recovery.older",
            "üser",
        ] {
            validate_account(account).unwrap();
        }
        for account in ["", "account\n", "account\u{0085}", "account\0"] {
            assert!(validate_account(account).is_err());
        }
        assert!(validate_account(&"x".repeat(512)).is_ok());
        assert!(validate_account(&"x".repeat(513)).is_err());
        assert!(validate_account(&"ü".repeat(257)).is_err());
    }

    #[test]
    fn foreign_service_is_rejected_before_any_native_connection() {
        assert!(accounts("foreign.service").is_err());
    }

    #[test]
    fn synthetic_attributes_match_keyring_default_and_legacy_collection_rules() {
        let service = super::super::QUICKSAVE_VAULT_SERVICE;
        let mut attributes = BTreeMap::from([
            ("service".into(), service.into()),
            ("username".into(), "inactive.recovery".into()),
            ("target".into(), "default".into()),
        ]);
        assert!(select_account(&attributes, service, false)
            .unwrap()
            .is_some());
        attributes.insert("target".into(), "other".into());
        assert!(select_account(&attributes, service, true)
            .unwrap()
            .is_none());
        attributes.remove("target");
        assert!(select_account(&attributes, service, false)
            .unwrap()
            .is_none());
        assert!(select_account(&attributes, service, true)
            .unwrap()
            .is_some());
        attributes.insert("service".into(), "foreign".into());
        assert!(select_account(&attributes, service, true).is_err());
        attributes.insert("service".into(), service.into());
        attributes.remove("username");
        assert!(select_account(&attributes, service, true).is_err());
    }

    #[test]
    fn synthetic_message_round_trips_filter_without_bus_or_vault_access() {
        let raw = unsafe {
            ffi::dbus_message_new_method_call(
                c"org.example.Synthetic".as_ptr(),
                c"/synthetic".as_ptr(),
                c"org.example.Synthetic".as_ptr(),
                c"Synthetic".as_ptr(),
            )
        };
        assert!(!raw.is_null());
        let message = Message(raw);
        let mut iter = unsafe { std::mem::zeroed() };
        unsafe { ffi::dbus_message_iter_init_append(message.0, &mut iter) };
        let mut cursor = Cursor {
            iter,
            _message: PhantomData,
        };
        cursor.append_service_filter("synthetic.service").unwrap();
        let mut cursor = message.cursor().unwrap();
        assert_eq!(
            cursor.attributes().unwrap(),
            BTreeMap::from([("service".into(), "synthetic.service".into())])
        );
        cursor.end().unwrap();
    }
}
