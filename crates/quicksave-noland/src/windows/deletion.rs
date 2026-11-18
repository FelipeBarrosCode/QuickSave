// SPDX-License-Identifier: GPL-3.0-only
//! Native consent/projection wrapper only. Closure, inventory validation,
//! publication and deletion execution remain the actual No Land storage APIs.
use super::*;
use crate::catalog_control::{self, DeletionSelection, FrozenFullDeletionPlan};

#[cfg(test)]
#[path = "deletion_tests.rs"]
mod tests;

const MAX_REVIEW_TARGETS: usize = 256;

pub(super) fn storage_binding(access: &PrivateAccess) -> Result<String> {
    ensure!(
        access.authority_revision.is_some() && !access.read_only,
        "frozen deletion requires the original native provider authority revision and write policy"
    );
    let mut hash = blake3::Hasher::new_keyed(&access.master.0);
    hash.update(b"QuickSave/windows-frozen-deletion-provider/v1\0");
    hash.update(&serde_json::to_vec(&(
        &access.provider,
        access.session.storage_identity(),
        access.authority_revision,
        access.read_only,
    ))?);
    Ok(hash.finalize().to_hex().to_string())
}

pub(super) fn projection(
    plan: &FullDeletionPlan,
    requested: &[DeletionSelection],
) -> Result<FrozenFullDeletionPlan> {
    let frozen = catalog_control::deletion_projection(plan, Some(requested))?;
    let dependencies = frozen.dependencies.as_ref()
        .context("original deletion dependency identities are unavailable")?;
    ensure!(
        frozen.targets.len() <= MAX_REVIEW_TARGETS && dependencies.len() <= MAX_REVIEW_TARGETS,
        "deletion exceeds the 256-target exact native review bound; no deletion was authorized"
    );
    Ok(frozen)
}

fn dependency_items(frozen: &FrozenFullDeletionPlan) -> Result<Value> {
    let dependencies = frozen.dependencies.as_ref()
        .context("original deletion dependency identities are unavailable")?;
    Ok(json!(dependencies.iter().map(|target| json!({
        "id":target.bundle_id,"appId":target.app_id,"commitId":target.commit_id,
    })).collect::<Vec<_>>()))
}

pub(super) fn summary(
    provider: &str,
    plan: &FullDeletionPlan,
    frozen: &FrozenFullDeletionPlan,
) -> Result<Value> {
    frozen.validate()?;
    let dependencies = dependency_items(frozen)?;
    Ok(json!({
        "previewId":plan.plan_id,"providerId":provider,"dependentBundles":dependencies,
        "dependentBundleCount":frozen.dependencies.as_ref().map(Vec::len),
        "affectedBundles":frozen.targets,"planDigest":frozen.digest,
        "items":frozen.targets.len(),"logicalBytes":frozen.logical_bytes,
        "physicalBytes":frozen.physical_bytes,"packCount":frozen.pack_count,
        "objectCount":frozen.pack_count.saturating_add(frozen.metadata_object_count),
        "fullDeletion":true,"expiresInSeconds":600,
        "selectionHash":noland_storage::compact_json_hash(&plan.targets).map_err(source_error)?,
        "targetCount":frozen.targets.len(),"names":frozen.names,
    }))
}

pub(super) fn check_preview(
    preview: &Preview,
    access: &PrivateAccess,
    selection: &Value,
) -> Result<bool> {
    ensure!(
        preview.created.elapsed() < Duration::from_secs(600)
            && preview.provider == access.provider
            && preview.storage == storage_binding(access)?
            && selection["previewId"].as_str().and_then(|id| Uuid::parse_str(id).ok())
                == Some(preview.plan.plan_id),
        "deletion preview expired or provider/account/root/key/authority changed"
    );
    let requested = preview.frozen.requested.as_ref()
        .context("original native deletion selection is unavailable")?
        .iter().map(|target| DeletionSelection {
            app_id:target.app_id.clone(),bundle_id:target.bundle_id.clone(),
        }).collect::<Vec<_>>();
    // Pure projection of the SAME held Source plan, never a new inventory or
    // dependency-closure computation after native approval.
    ensure!(
        projection(&preview.plan,&requested)? == preview.frozen,
        "original frozen deletion identities/digest changed; preview again"
    );
    ensure!(
        selection.get("providerId").is_none_or(|value| value == &json!(preview.provider))
            && selection.get("planDigest").is_none_or(|value| value == &json!(preview.frozen.digest))
            && selection.get("affectedBundles").is_none_or(|value| value == &json!(preview.frozen.targets))
            && selection.get("dependentBundles").is_none_or(|value|
                dependency_items(&preview.frozen).is_ok_and(|expected| *value == expected)),
        "incoming deletion acknowledgement differs from the exact original native preview"
    );
    let ack = match selection.get("acknowledgeDependencies") {
        None => false,
        Some(value) => value.as_bool().context("dependency acknowledgement must be a boolean")?,
    };
    ensure!(
        preview.frozen.dependencies.as_ref().is_some_and(|dependencies| dependencies.is_empty()) || ack,
        "dependent backups require separate explicit acknowledgement of the original native plan"
    );
    // Consent itself is the caller's native PublishGuard/NativeTicket, NOT this
    // boolean or a caller-constructed JSON plan. Service binds the exact preview
    // summary (identities + digest) to that ticket before invoking this wrapper.
    Ok(ack)
}

/// Applies to initial spend AND retry/worker entry. Original native consent is
/// never replaced by global provider write permission.
pub(super) fn check_guard(plan: &FrozenPlan, guard: Option<&PublishGuard>) -> Result<()> {
    if matches!(&plan.work, Work::Delete { .. }) {
        guard.context("native deletion requires fresh exact-plan publication authority")?()?;
    }
    Ok(())
}
