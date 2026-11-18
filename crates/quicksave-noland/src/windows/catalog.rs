// SPDX-License-Identifier: GPL-3.0-only
//! Bounded read-only catalog composition. Semantics derive from No Land
//! e81238a7536aae201540956ce76981364fd36595 cloud_catalog.rs: only overlapping
//! refreshes coalesce; no cached latest/negative result becomes fresh authority.
//! Paging uses immutable revision-bound snapshots, never per-bundle remote reads.
use super::*;
use crate::catalog_control::{
    self, BundleEvidence, CatalogEvidence, CatalogFreshness, DeletionSelection,
    MAX_CATALOG_BUNDLES, MAX_CATALOG_BYTES,
};
use serde::Serialize;
#[cfg(test)]
#[path = "catalog_tests.rs"]
mod tests;

#[derive(Default)]
pub(super) struct CatalogState {
    gates: BTreeMap<String, Weak<tokio::sync::Mutex<()>>>,
    snapshots: BTreeMap<String, Snapshot>,
    details: BTreeMap<(String, Uuid), Detail>,
    requested: BTreeMap<(String, Uuid), Requested>,
}

struct Snapshot {
    value: Arc<Value>,
    // Native diagnostics only. Never part of Service's strict rich projection,
    // freshness, execution authority or the shared revision/hash input.
    _metrics: Value,
    bytes: usize,
    completed: Instant,
}
struct CatalogRead {
    projection: Value,
    metrics: Value,
}
struct Detail {
    value: BundleEvidence,
    bytes: usize,
    observed: Instant,
}
struct Requested {
    selections: Vec<DeletionSelection>,
    plan_digest: String,
    device_mac: [u8; 32],
    bytes: usize,
    observed: Instant,
}

fn scope_key(
    instance: Uuid,
    provider: &str,
    session: &EphemeralRcloneSession,
    master: &MasterKey,
    read_only: bool,
    revision: Option<u64>,
) -> Result<String> {
    ensure!(
        revision.is_some(),
        "native catalog requires its original provider authority revision"
    );
    let mut hash = blake3::Hasher::new_keyed(&master.0);
    hash.update(b"QuickSave/windows-catalog-native-scope/v1\0");
    hash.update(&serde_json::to_vec(&(
        instance,
        provider,
        session.storage_identity(),
        read_only,
        revision,
    ))?);
    Ok(hash.finalize().to_hex().to_string())
}

fn access_key(engine: &NativeEngine, access: &ProviderAccess) -> Result<String> {
    validate_id(&access.provider_id)?;
    ensure!(
        bytes(&access.session)? <= MAX_SESSION,
        "native catalog session exceeds its bound"
    );
    let session: EphemeralRcloneSession = serde_json::from_value(access.session.clone())
        .map_err(|_| anyhow::anyhow!("invalid native catalog provider session"))?;
    let revision = access.session["native_authority_revision"].as_u64();
    scope_key(
        engine.inner.instance,
        &access.provider_id,
        &session,
        &MasterKey::from_bytes(access.repository_key),
        access.read_only,
        revision,
    )
}

fn private_key(inner: &Inner, access: &PrivateAccess) -> Result<String> {
    scope_key(
        inner.instance,
        &access.provider,
        &access.session,
        &access.master,
        access.read_only,
        access.authority_revision,
    )
}

impl CatalogState {
    fn entries(&self) -> usize {
        self.snapshots
            .len()
            .saturating_add(self.details.len())
            .saturating_add(self.requested.len())
    }

    fn used(&self) -> usize {
        self.snapshots
            .values()
            .map(|entry| entry.bytes)
            .chain(self.details.values().map(|entry| entry.bytes))
            .chain(self.requested.values().map(|entry| entry.bytes))
            .fold(0usize, usize::saturating_add)
    }

    fn reserve(&mut self, bytes: usize) -> Result<()> {
        ensure!(
            bytes <= MAX_CATALOG_BYTES,
            "native catalog entry exceeds 32 MiB"
        );
        while self.used().saturating_add(bytes) > MAX_CATALOG_BYTES
            || self.entries() >= MAX_CATALOG_BUNDLES
        {
            if let Some(key) = self
                .snapshots
                .iter()
                .min_by_key(|(_, entry)| entry.completed)
                .map(|(key, _)| key.clone())
            {
                self.snapshots.remove(&key);
            } else if let Some(key) = self
                .details
                .iter()
                .min_by_key(|(_, entry)| entry.observed)
                .map(|(key, _)| key.clone())
            {
                self.details.remove(&key);
            } else if let Some(key) = self
                .requested
                .iter()
                .min_by_key(|(_, entry)| entry.observed)
                .map(|(key, _)| key.clone())
            {
                self.requested.remove(&key);
            } else {
                bail!("native catalog cache accounting is invalid")
            }
        }
        Ok(())
    }
}

fn bytes(value: &impl Serialize) -> Result<usize> {
    struct Count(usize);
    impl Write for Count {
        fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
            self.0 = self
                .0
                .checked_add(bytes.len())
                .filter(|total| *total <= MAX_CATALOG_BYTES)
                .ok_or_else(|| std::io::Error::other("native catalog exceeds 32 MiB"))?;
            Ok(bytes.len())
        }
        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }
    let mut count = Count(0);
    serde_json::to_writer(&mut count, value)?;
    Ok(count.0)
}

pub(super) fn remember_manifest(
    inner: &Inner,
    access: &PrivateAccess,
    manifest: &BundleManifest,
) -> Result<()> {
    let scope = private_key(inner, access)?;
    let detail = BundleEvidence::from_authenticated_manifest(manifest, false)?;
    let size = bytes(&detail)?.saturating_add(256);
    let mut state = inner.catalog.lock().map_err(poison)?;
    state.details.remove(&(scope.clone(), manifest.bundle_id));
    if state.details.len() >= MAX_CATALOG_BUNDLES {
        if let Some(key) = state
            .details
            .iter()
            .min_by_key(|(_, entry)| entry.observed)
            .map(|(key, _)| key.clone())
        {
            state.details.remove(&key);
        }
    }
    state.reserve(size)?;
    state.details.insert(
        (scope, manifest.bundle_id),
        Detail {
            value: detail,
            bytes: size,
            observed: Instant::now(),
        },
    );
    Ok(())
}

fn requested_message(scope: &str, plan: &str, selections: &[DeletionSelection]) -> Result<Vec<u8>> {
    let mut message = b"QuickSave/windows-original-deletion-catalog-selection/v1\0".to_vec();
    message.extend_from_slice(full_scope::metadata_digest(&(scope, plan, selections))?.as_bytes());
    Ok(message)
}

pub(super) fn remember_requested(
    inner: &Inner,
    access: &PrivateAccess,
    plan: &FullDeletionPlan,
    selections: Vec<DeletionSelection>,
) -> Result<()> {
    let scope = private_key(inner, access)?;
    let projected = catalog_control::deletion_projection(plan, Some(&selections))?;
    let authority = inner
        .operation_authority
        .lock()
        .map_err(poison)?
        .clone()
        .context("original deletion catalog scope requires existing device authority")?;
    let device_mac = authority(&requested_message(&scope, &projected.digest, &selections)?)?;
    let size = bytes(&selections)?.saturating_add(256);
    let mut state = inner.catalog.lock().map_err(poison)?;
    state.requested.remove(&(scope.clone(), plan.plan_id));
    state.reserve(size)?;
    state.requested.insert(
        (scope, plan.plan_id),
        Requested {
            selections,
            plan_digest: projected.digest,
            device_mac,
            bytes: size,
            observed: Instant::now(),
        },
    );
    Ok(())
}

fn requested(
    inner: &Inner,
    scope: &str,
    plan: &FullDeletionPlan,
) -> Result<Option<Vec<DeletionSelection>>> {
    let (selected, digest, mac) = {
        let state = inner.catalog.lock().map_err(poison)?;
        let Some(entry) = state.requested.get(&(scope.into(), plan.plan_id)) else {
            return Ok(None);
        };
        (
            entry.selections.clone(),
            entry.plan_digest.clone(),
            entry.device_mac,
        )
    };
    let actual = catalog_control::deletion_projection(plan, None)?;
    ensure!(
        actual.digest == digest,
        "authenticated pending deletion differs from original local scope"
    );
    let authority = inner
        .operation_authority
        .lock()
        .map_err(poison)?
        .clone()
        .context("original deletion catalog device authority is unavailable")?;
    let expected = authority(&requested_message(scope, &digest, &selected)?)?;
    ensure!(
        expected
            .iter()
            .zip(mac)
            .fold(0u8, |difference, (a, b)| difference | (*a ^ b))
            == 0,
        "original pending deletion selection device authentication failed"
    );
    Ok(Some(selected))
}

fn ms(started: Instant) -> u64 {
    started.elapsed().as_millis().min(u64::MAX as u128) as u64
}

/// The portable counterpart of the source's read-current catalog controller:
/// typed shared catalog + authenticated pending full plans + actual provider I/O.
async fn read_catalog_current(
    inner: &Inner,
    private: &PrivateAccess,
    provider: &dyn SharedStorageProvider,
    scope: &str,
) -> Result<CatalogRead> {
    let started = Instant::now();
    let started_at = chrono::Utc::now();
    let before = provider.operation_metrics();
    let metadata_before = provider.metadata_read_metrics();
    let catalog_start = Instant::now();
    let pending_start = Instant::now();
    // Drain both actual bounded branches even if one fails.
    let (catalog, pending) = tokio::join!(
        async {
            let result = load_catalog(provider, &private.master).await;
            (result, ms(catalog_start))
        },
        async {
            let result = noland_storage::pending_deletions(provider, &private.master).await;
            (result, ms(pending_start))
        },
    );
    let (document, catalog_ms) = (catalog.0.map_err(source_error)?, catalog.1);
    let (pending, pending_ms) = (pending.0.map_err(source_error)?, pending.1);
    ensure!(
        document
            .apps
            .iter()
            .try_fold(0usize, |count, app| count.checked_add(app.bundles.len()))
            .is_some_and(|count| count <= MAX_CATALOG_BUNDLES),
        "native catalog has more than 100000 real bundles"
    );
    // Count before cloning/projection, including authenticated full pending plans.
    bytes(&(&document, &pending))?;
    let mut evidence = CatalogEvidence {
        freshness: CatalogFreshness {
            source: "live_remote_validation".into(),
            refresh_started_at: Some(started_at.to_rfc3339()),
            observed_at: Some(chrono::Utc::now().to_rfc3339()),
            coalesced: false,
        },
        ..Default::default()
    };
    {
        let state = inner.catalog.lock().map_err(poison)?;
        for app in &document.apps {
            for bundle in &app.bundles {
                if let Some(detail) = state.details.get(&(scope.into(), bundle.bundle_id)) {
                    if detail.value.app_id == app.app_id.as_str()
                        && detail.value.commit_id == bundle.commit_id.to_string()
                    {
                        evidence
                            .bundles
                            .insert(bundle.bundle_id.to_string(), detail.value.clone());
                    }
                }
            }
        }
    }
    for plan in pending {
        let selected = requested(inner, scope, &plan)?;
        evidence
            .pending_deletions
            .push(catalog_control::deletion_projection(
                &plan,
                selected.as_deref(),
            )?);
    }
    let projection = catalog_control::catalog_projection(&private.provider, &document, &evidence)?;
    let metrics = json!({
        "loadCatalogDurationMs":catalog_ms,"pendingDeletionsDurationMs":pending_ms,
        "refreshDurationMs":ms(started),
        "storage":provider.operation_metrics().saturating_sub(before),
        "metadataProviderIo":provider.metadata_read_metrics().saturating_sub(metadata_before),
    });
    bytes(&(&projection, &metrics))?;
    Ok(CatalogRead {
        projection,
        metrics,
    })
}

impl NativeEngine {
    fn catalog_authority(&self, access: &ProviderAccess) -> Result<()> {
        ensure!(
            !self.inner.stopping.load(Ordering::Acquire)
                && !self.inner.finalization_failed.load(Ordering::Acquire),
            "native catalog owner is stopping or unverified"
        );
        self.inner._owner.check()?;
        let authority = self
            .inner
            .authority
            .lock()
            .map_err(poison)?
            .clone()
            .context("native catalog authority is unavailable")?;
        authority(&access.provider_id, false)?;
        if let Some(store) = &self.workspace {
            let document = store.document()?;
            let record = document
                .providers
                .iter()
                .find(|record| record.id == access.provider_id)
                .context("native catalog provider is unavailable")?;
            ensure!(
                access.session["native_authority_revision"].as_u64()
                    == Some(record.authority_revision)
                    && access.read_only == record.read_only,
                "native catalog provider/account/read-only authority changed"
            );
        }
        Ok(())
    }

    /// Full, lossless shared projection on explicit refresh. Only requests that
    /// actually overlap share a completed refresh; sequential requests revalidate
    /// current catalog/pending-deletion state, never a TTL-cached latest.
    pub async fn catalog_projection(&self, access: &ProviderAccess) -> Result<Value> {
        let (snapshot, coalesced) = self.catalog_snapshot(access).await?;
        let mut value = (*snapshot).clone();
        value["freshness"]["coalesced"] = json!(coalesced);
        Ok(value)
    }

    async fn catalog_snapshot(&self, access: &ProviderAccess) -> Result<(Arc<Value>, bool)> {
        let requested_at = Instant::now();
        self.catalog_authority(access)?;
        let scope = access_key(self, access)?;
        let _slot = self
            .inner
            .reads
            .try_acquire()
            .context("native catalog reader is at capacity")?;
        let gate = {
            let mut state = self.inner.catalog.lock().map_err(poison)?;
            state.gates.retain(|_, gate| gate.strong_count() > 0);
            if let Some(gate) = state.gates.get(&scope).and_then(Weak::upgrade) {
                gate
            } else {
                ensure!(
                    state.gates.len() < 16,
                    "native catalog refresh queue is full"
                );
                let gate = Arc::new(tokio::sync::Mutex::new(()));
                state.gates.insert(scope.clone(), Arc::downgrade(&gate));
                gate
            }
        };
        let _refresh = gate.lock().await;
        let shared = self
            .inner
            .catalog
            .lock()
            .map_err(poison)?
            .snapshots
            .get(&scope)
            .filter(|snapshot| snapshot.completed >= requested_at)
            .map(|snapshot| Arc::clone(&snapshot.value));
        if let Some(shared) = shared {
            self.catalog_authority(access)?;
            return Ok((shared, true));
        }
        self.preflight().await?;
        let private = self.private_access(access, None)?;
        ensure!(
            private_key(&self.inner, &private)? == scope,
            "native catalog scope changed during provider attachment"
        );
        let session = self.session(&private, None, Arc::new(AtomicBool::new(false)), false)?;
        let result = read_catalog_current(&self.inner, &private, &session.provider, &scope).await;
        let current = session.finish(result)?;
        self.catalog_authority(access)?;
        let size = bytes(&(&current.projection, &current.metrics))?.saturating_add(256);
        let value = Arc::new(current.projection);
        {
            let mut state = self.inner.catalog.lock().map_err(poison)?;
            state.snapshots.remove(&scope);
            state.reserve(size)?;
            state.snapshots.insert(
                scope,
                Snapshot {
                    value: Arc::clone(&value),
                    _metrics: current.metrics,
                    bytes: size,
                    completed: Instant::now(),
                },
            );
        }
        Ok((value, false))
    }

    pub async fn catalog(&self, access: &ProviderAccess) -> Result<Value> {
        self.catalog_page(access, &json!({})).await
    }

    /// Legacy paging signature, now fed by the rich producer without flattening
    /// away source heads/instances/pending identities or repeating bundle details.
    pub async fn catalog_page(&self, access: &ProviderAccess, params: &Value) -> Result<Value> {
        self.catalog_authority(access)?;
        let first_page = params.get("cursor").is_none_or(Value::is_null);
        let (snapshot, coalesced) = if !first_page {
            let scope = access_key(self, access)?;
            let snapshot = self
                .inner
                .catalog
                .lock()
                .map_err(poison)?
                .snapshots
                .get(&scope)
                .map(|snapshot| Arc::clone(&snapshot.value))
                .context("catalog page revision was evicted; explicitly refresh the catalog")?;
            (snapshot, false)
        } else {
            self.catalog_snapshot(access).await?
        };
        let mut page = catalog_page(snapshot.as_ref(), params, first_page)?;
        if first_page {
            page["freshness"]["coalesced"] = json!(coalesced);
        }
        Ok(page)
    }
}

fn catalog_page(snapshot: &Value, params: &Value, first_page: bool) -> Result<Value> {
    let bundles = snapshot["bundles"]
        .as_array()
        .context("native catalog bundle projection is missing")?;
    let revision = snapshot["revision"]
        .as_str()
        .context("native catalog revision is missing")?;
    let mut page = indexed_page(bundles, params, revision)?;
    let object = page
        .as_object_mut()
        .context("native catalog page is invalid")?;
    let rows = object
        .remove("files")
        .context("native catalog page rows are missing")?;
    object.insert("bundles".into(), rows);
    for field in [
        "projectionVersion",
        "providerId",
        "schemaVersion",
        "catalogCommitId",
        "createdAt",
        "revision",
        "freshness",
        "authoritativeForExecution",
    ] {
        if let Some(value) = snapshot.get(field) {
            object.insert(field.into(), value.clone());
        }
    }
    if first_page {
        for field in ["heads", "apps", "instances", "pendingDeletions"] {
            if let Some(value) = snapshot.get(field) {
                object.insert(field.into(), value.clone());
            }
        }
    } else {
        // It is an immutable old revision page, not another fresh remote
        // observation. Large app/pending identity lists appear only once.
        object.insert(
            "freshness".into(),
            json!({
                "source":"immutable_revision_page",
                "refreshStartedAt":snapshot["freshness"]["refreshStartedAt"],
                "observedAt":snapshot["freshness"]["observedAt"],
                "coalesced":false,
            }),
        );
    }
    object.insert("catalogRevision".into(), json!(revision));
    bytes(&page)?;
    Ok(page)
}

pub(super) fn clear(inner: &Inner) -> Result<()> {
    *inner.catalog.lock().map_err(poison)? = CatalogState::default();
    Ok(())
}
