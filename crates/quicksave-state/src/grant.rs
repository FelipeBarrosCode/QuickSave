// SPDX-License-Identifier: GPL-3.0-only

use crate::{
    bounded_json,
    model::{ProviderRecord, StateSoftware},
};
use anyhow::{ensure, Result};
use hmac::{Hmac, Mac};
use serde_json::{json, Value};
use sha2::Sha256;

type HmacSha256 = Hmac<Sha256>;
const DOMAIN: &[u8] = b"QuickSave/native-authority/v1\0";

pub(crate) fn canonical(scope: &Value) -> Result<Vec<u8>> {
    bounded_json(scope, 2 * 1024 * 1024)?;
    fn sorted(value: &Value) -> Value {
        match value {
            Value::Object(object) => {
                let mut result: serde_json::Map<String, Value> = object
                    .iter()
                    .map(|(key, value)| (key.clone(), sorted(value)))
                    .collect();
                result.sort_keys();
                Value::Object(result)
            }
            Value::Array(values) => Value::Array(values.iter().map(sorted).collect()),
            value => value.clone(),
        }
    }
    Ok(serde_json::to_vec(&sorted(scope))?)
}

pub(crate) fn seal(key: &[u8; 32], scope: &Value) -> Result<Value> {
    let mut mac = HmacSha256::new_from_slice(key)?;
    mac.update(DOMAIN);
    mac.update(&canonical(scope)?);
    Ok(
        json!({"version":1, "algorithm":"hmac-sha256", "mac":hex::encode(mac.finalize().into_bytes())}),
    )
}

pub(crate) fn verify(key: &[u8; 32], scope: &Value, grant: &Value) -> Result<bool> {
    bounded_json(grant, 1024)?;
    if grant.get("version").and_then(Value::as_u64) != Some(1)
        || grant.get("algorithm").and_then(Value::as_str) != Some("hmac-sha256")
    {
        return Ok(false);
    }
    let Some(encoded) = grant.get("mac").and_then(Value::as_str) else {
        return Ok(false);
    };
    if encoded.len() != 64 {
        return Ok(false);
    }
    let Ok(bytes) = hex::decode(encoded) else {
        return Ok(false);
    };
    let mut mac = HmacSha256::new_from_slice(key)?;
    mac.update(DOMAIN);
    mac.update(&canonical(scope)?);
    // The MAC crate performs constant-time comparison.
    Ok(mac.verify_slice(&bytes).is_ok())
}

pub(crate) fn tracking_scope(software: &StateSoftware) -> Result<Value> {
    ensure!(
        !software.roots.is_empty(),
        "tracking authority needs explicitly approved native roots"
    );
    let mut scope = json!({
        "version":1,"softwareId":software.id,"appId":software.app_id,
        "roots":software.roots.iter().map(|root| {
            let mut result = json!({
                "id":root.id,"path":root.path,"role":root.role,
                "identity":root.identity,"allowedFiles":root.allowed_files,
            });
            if !root.directory { result["directory"] = json!(false); }
            result
        }).collect::<Vec<_>>(),
    });
    if let Some(enrollment) = &software.auto_enrollment {
        scope["autoEnrollment"] = enrollment.binding()?;
    }
    if let Some(identity) = &software.source_identity {
        scope["sourceIdentity"] = identity.clone();
    }
    Ok(scope)
}

pub(crate) fn autosave_scope(software: &StateSoftware, provider: &ProviderRecord) -> Result<Value> {
    ensure!(
        software.tracked
            && (software.auto_enrollment.is_none() || software.bundle_index_source.is_some()),
        "autosave requires a materialized tracked native scope"
    );
    ensure!(
        software.provider_id.as_deref() == Some(provider.id.as_str()),
        "autosave provider differs from software provider"
    );
    ensure!(
        !provider.read_only,
        "read-only imported provider requires a separate write grant"
    );
    Ok(json!({
        "version":1, "tracking":tracking_scope(software)?, "providerId":software.provider_id,
    }))
}

pub(crate) fn provider_authority(provider: &ProviderRecord) -> Value {
    json!({
            "id":provider.id, "kind":provider.kind, "bucket":provider.bucket,
            "prefix":provider.prefix, "credentialRef":provider.credential_ref,
            "repositoryKeyRef":provider.repository_key_ref,
            "readOnly":provider.read_only,"origin":provider.origin,
            "publicScope":provider.public_scope,
            "authorityRevision":provider.authority_revision,
    })
}
