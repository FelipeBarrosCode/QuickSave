// SPDX-License-Identifier: GPL-3.0-only
//! Bounded native operation policy; never global rclone flags or credential IO.
use crate::{EphemeralRcloneSession, ProviderCapabilities, ProviderKind, TransferTuning};
use noland_state_core::{Result, StateError};
use std::{
    collections::BTreeMap,
    sync::{Mutex, OnceLock},
};

#[derive(Clone)]
pub struct NativeTransferPolicy {
    pub tuning: Option<TransferTuning>,
    pub upload_ceiling: Option<usize>,
    pub download_ceiling: Option<usize>,
}
struct Entry {
    id: uuid::Uuid,
    session: blake3::Hash,
    policy: NativeTransferPolicy,
}
static POLICIES: OnceLock<Mutex<BTreeMap<String, Entry>>> = OnceLock::new();
fn registry() -> &'static Mutex<BTreeMap<String, Entry>> {
    POLICIES.get_or_init(Mutex::default)
}
fn failed() -> StateError {
    StateError::Conflict("native transfer policy is stale or outside provider limits".into())
}
pub(crate) fn invalidate_stopped_operation(operation: &str) -> Result<()> {
    registry().lock().map_err(|_| failed())?.remove(operation);
    Ok(())
}
fn fingerprint(session: &EphemeralRcloneSession) -> blake3::Hash {
    let mut hash = blake3::Hasher::new();
    for value in [
        &session.operation_id,
        &session.provider,
        &session.backend_type,
        &session.remote_name,
        &session.root,
        &session.config_ini,
    ] {
        hash.update(&(value.len() as u64).to_le_bytes());
        hash.update(value.as_bytes());
    }
    hash.finalize()
}

pub struct NativeTransferPolicyRegistration {
    operation: String,
    id: uuid::Uuid,
}
impl NativeTransferPolicyRegistration {
    pub fn invalidate(&self) -> Result<()> {
        let mut registry = registry().lock().map_err(|_| failed())?;
        if registry
            .get(&self.operation)
            .is_some_and(|entry| entry.id == self.id)
        {
            registry.remove(&self.operation);
        }
        Ok(())
    }
}
impl Drop for NativeTransferPolicyRegistration {
    fn drop(&mut self) {
        if let Ok(mut registry) = registry().lock() {
            if registry
                .get(&self.operation)
                .is_some_and(|entry| entry.id == self.id)
            {
                registry.remove(&self.operation);
            }
        }
    }
}
pub fn register_native_transfer_policy(
    session: &EphemeralRcloneSession,
    policy: NativeTransferPolicy,
) -> Result<NativeTransferPolicyRegistration> {
    let kind = ProviderKind::parse(&session.provider).ok_or_else(failed)?;
    let capabilities = ProviderCapabilities::for_provider(kind);
    if session.operation_id.is_empty()
        || session.operation_id.len() > 255
        || policy
            .upload_ceiling
            .is_some_and(|value| value == 0 || value > capabilities.max_upload_concurrency)
        || policy
            .download_ceiling
            .is_some_and(|value| value == 0 || value > capabilities.max_download_concurrency)
    {
        return Err(failed());
    }
    let mut registry = registry().lock().map_err(|_| failed())?;
    if registry.len() >= 256 || registry.contains_key(&session.operation_id) {
        return Err(failed());
    }
    let id = uuid::Uuid::new_v4();
    registry.insert(
        session.operation_id.clone(),
        Entry {
            id,
            session: fingerprint(session),
            policy,
        },
    );
    Ok(NativeTransferPolicyRegistration {
        operation: session.operation_id.clone(),
        id,
    })
}
pub(crate) fn for_session(
    session: &EphemeralRcloneSession,
) -> Result<Option<NativeTransferPolicy>> {
    let registry = registry().lock().map_err(|_| failed())?;
    match registry.get(&session.operation_id) {
        Some(entry) if entry.session == fingerprint(session) => Ok(Some(entry.policy.clone())),
        Some(_) => Err(failed()),
        None => Ok(None),
    }
}
