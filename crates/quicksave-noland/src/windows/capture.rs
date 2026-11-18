// SPDX-License-Identifier: GPL-3.0-only
//! Windows portable facade for the parent's native capture controller. No Linux
//! StateAgent/collector is linked. The receipt constructor is engine-private.
use super::*;
use serde::{Deserialize, Serialize};

pub use super::full_scope::FullScopeBinding;
pub use super::full_scope::FullScopeBinding as NativeFullScopeBinding;
pub use super::plan::CaptureScope;
pub type CaptureStamp = FileStamp;
pub(super) const EXPECTED_AAD: &[u8] = b"quicksave-native-expected-manifest-v1";
const EXPECTED_ALGORITHM: &str = "source-xchacha20poly1305-metadata";

/// Rust-only owner of the original signed tracker full-scope/baseline grants.
/// JSON bindings never implement or substitute for this authority.
pub trait NativeFullScopeAuthority: Send + Sync + 'static {
    fn evidence(&self) -> Result<Value>;
    fn revalidate(&self) -> Result<()>;
}

pub fn full_scope_from_evidence(evidence: &Value) -> Result<FullScopeBinding> {
    FullScopeBinding::from_evidence(evidence)
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct FrozenCaptureNode {
    pub id: String,
    pub root_id: String,
    pub logical_root: String,
    pub path: String,
    pub kind: String,
    pub size: u64,
    pub stamp: CaptureStamp,
    #[serde(default)]
    pub link_target_hash: Option<String>,
}

pub trait NativeCaptureController: Send + Sync + 'static {
    fn node_page(
        &self,
        scope: &CaptureScope,
        offset: usize,
        limit: usize,
    ) -> Result<Vec<FrozenCaptureNode>>;
    fn reuse_epoch(&self, _scope: &CaptureScope) -> Result<Option<String>> {
        Ok(None)
    }
    fn full_scope_authority(
        &self,
        _scope: &CaptureScope,
    ) -> Result<Option<Arc<dyn NativeFullScopeAuthority>>> {
        Ok(None)
    }
    fn accept(&self, receipt: Arc<PreparedCaptureReceipt>) -> Result<()>;
    fn verify_publication(&self) -> Result<()>;
}

pub struct PreparedCaptureReceipt {
    evidence: Arc<Value>,
    revalidate: Arc<dyn Fn() -> Result<()> + Send + Sync>,
}
impl PreparedCaptureReceipt {
    pub fn evidence(&self) -> Result<Value> {
        Ok((*self.evidence).clone())
    }
    pub fn revalidate(&self) -> Result<()> {
        (self.revalidate)()
    }
    pub(super) fn new(
        evidence: Value,
        revalidate: Arc<dyn Fn() -> Result<()> + Send + Sync>,
    ) -> Self {
        Self {
            evidence: Arc::new(evidence),
            revalidate,
        }
    }
}

pub(super) fn freeze(
    binding: &SoftwareBinding,
    scope: &CaptureScope,
    controller: &dyn NativeCaptureController,
    provider: &str,
) -> Result<(
    Vec<ExpectedFile>,
    Vec<FrozenMetadata>,
    Option<full_scope::FullSnapshot>,
)> {
    scope.validate()?;
    let full = full_scope::FullSnapshot::prepare(binding, scope, controller, provider)?;
    let mut files = Vec::new();
    let mut metadata = Vec::new();
    let mut seen = BTreeSet::new();
    let mut frozen_nodes = BTreeMap::new();
    let mut path_bytes = 0usize;
    let mut offset = 0;
    while offset < scope.node_count {
        let limit = (scope.node_count - offset).min(500);
        let nodes = controller.node_page(scope, offset, limit)?;
        ensure!(
            nodes.len() == limit,
            "trusted native frozen-node page changed its exact count"
        );
        for node in nodes {
            ensure!(
                frozen_nodes.insert(node.id.clone(), node.clone()).is_none(),
                "duplicate frozen native capture node"
            );
            let root = binding
                .roots
                .iter()
                .find(|root| root.spec.id == node.root_id)
                .context("native frozen node is outside approved roots")?;
            ensure!(
                node.logical_root == root.spec.logical
                    && node.id == file_id(&root.spec.logical, &node.path)
                    && seen.insert(node.id.clone()),
                "native frozen node identity/root mapping changed or duplicated"
            );
            validate_relative(&node.path)?;
            ensure!(
                root.spec
                    .allowed_files
                    .as_ref()
                    .is_none_or(|leaves| leaves.contains(&node.path)),
                "native frozen node widens a manual file leaf scope"
            );
            ensure!(
                root.handle.identity()? == root.spec.identity,
                "native frozen root changed"
            );
            path_bytes = path_bytes
                .checked_add(node.path.len())
                .context("native capture path overflow")?;
            ensure!(
                path_bytes <= 32 * 1024 * 1024,
                "native capture path memory bound exceeded"
            );
            match node.kind.as_str() {
                "file" => {
                    let (_, stamp) = root.handle.read_file(&node.path)?;
                    ensure!(stamp == node.stamp && stamp.size == node.size,
                        "native file no longer matches its frozen complete stamp");
                    files.push(ExpectedFile { id: node.id, root: node.logical_root, relative: node.path,
                        stamp, size: node.size, hash: String::new() });
                }
                "directory" => {
                    ensure!(node.size == 0, "native directory logical size is invalid");
                    let path = root.spec.path.join(&node.path);
                    let file = noland_snapshot::SourcePath::new(&path)
                        .and_then(|source| source.open_directory()).map_err(source_error)?;
                    ensure!(stamp(&file)? == node.stamp, "native directory changed from frozen metadata");
                    metadata.push(FrozenMetadata { root: node.logical_root, relative: node.path,
                        directory: true, stamp: node.stamp, link: None });
                }
                "symlink" => {
                    ensure!(node.size == 0, "native link logical size is invalid");
                    let link = root.handle.read_link(&node.path)?;
                    ensure!(link.stamp == node.stamp && link.target_is_directory.is_some()
                        && node.link_target_hash.as_deref()
                            == Some(blake3::hash(link.target.as_bytes()).to_hex().as_str()),
                        "native link stamp/target/directory-kind proof changed or is missing");
                    metadata.push(FrozenMetadata { root: node.logical_root, relative: node.path,
                        directory: false, stamp: node.stamp, link: Some(link) });
                }
                _ => bail!("native capture refuses unknown node kinds; Windows link kinds are never guessed"),
            }
        }
        offset += limit;
    }
    if let Some(full) = &full {
        full.verify_nodes(
            &binding
                .roots
                .iter()
                .map(|root| root.spec.clone())
                .collect::<Vec<_>>(),
            &frozen_nodes,
        )?;
    }
    ensure!(
        controller.node_page(scope, scope.node_count, 1)?.is_empty(),
        "native capture controller added nodes beyond original frozen count"
    );
    files.sort_by(|a, b| a.id.cmp(&b.id));
    Ok((files, metadata, full))
}

pub(super) fn stamp(file: &File) -> Result<FileStamp> {
    let metadata = noland_snapshot::SourceMetadata::from_file(file).map_err(source_error)?;
    let id = metadata
        .native_identity()
        .context("native full file identity is unavailable")?;
    let modified = metadata
        .mtime_ns()
        .context("native mtime is outside exact No Land nanosecond range")?;
    let changed = metadata
        .ctime_ns()
        .context("native ctime is outside exact No Land nanosecond range")?;
    Ok(FileStamp {
        device: id.volume,
        file_id: id.file_id,
        size: metadata.len(),
        modified_seconds: modified.div_euclid(1_000_000_000),
        modified_nanoseconds: modified.rem_euclid(1_000_000_000) as u32,
        changed_seconds: changed.div_euclid(1_000_000_000),
        changed_nanoseconds: changed.rem_euclid(1_000_000_000) as u32,
    })
}

pub(super) fn accept(inner: &Arc<Inner>, job: &Job, manifest: &BundleManifest) -> Result<()> {
    let Some(controller) = &job.controller else {
        ensure!(
            !matches!(
                &job.plan.work,
                Work::Upload {
                    capture_scope: Some(_),
                    ..
                }
            ),
            "native metadata capture lost its Rust source receipt sink before publication"
        );
        return Ok(());
    };
    let Work::Upload {
        capture_scope: Some(scope),
        roots,
        files,
        metadata,
        full_snapshot,
        ..
    } = &job.plan.work
    else {
        bail!("native capture controller has no authenticated frozen scope");
    };
    let full_authority = full_snapshot
        .as_ref()
        .map(|full| {
            full.revalidate_roots(roots)?;
            full.revalidate_authority(scope, controller.as_ref())
        })
        .transpose()?;
    let manifest_hash = full_scope::metadata_digest(manifest)?;
    let accepted = inner
        .captures
        .lock()
        .map_err(poison)?
        .get(&job.plan.operation)
        .cloned();
    if let Some((original, receipt)) =
        accepted.and_then(|(hash, receipt)| receipt.upgrade().map(|receipt| (hash, receipt)))
    {
        ensure!(
            original == manifest_hash,
            "native retry changed its accepted source manifest"
        );
        receipt.revalidate()?;
        completion::accepted(
            inner,
            job,
            manifest,
            &receipt.evidence["sourceExpectedManifestAuth"],
        )?;
        return controller.verify_publication();
    }
    let nodes = captured_nodes(&job.plan, manifest)?;
    let body = expected_body(&job.plan, manifest, &nodes)?;
    let authentication = noland_storage::seal_metadata(
        &noland_crypto::derive_keys(&job.access.master).manifest,
        EXPECTED_AAD,
        &body,
    )
    .map_err(source_error)?
    .envelope;
    let source_auth = json!({"version":1,"algorithm":EXPECTED_ALGORITHM,
        "manifestHash":body["manifestHash"],"capturedFilesHash":body["capturedFilesHash"],
        "capturedProofHash":body["capturedProofHash"],"rootLayoutsHash":body["rootLayoutsHash"],
        "operationId":job.plan.operation,"aad":std::str::from_utf8(EXPECTED_AAD)?,
        "envelopeHex":authentication.iter().map(|byte|format!("{byte:02x}")).collect::<String>()});
    let layouts = manifest.environment["quicksave_native_root_layouts"].clone();
    let evidence = json!({
        "workId":scope.work_id,"metadataIdentity":scope.metadata_identity,
        "sourceSnapshotId":manifest.bundle_id.to_string(),
        "sourceExpectedManifestAuth":source_auth,
        "sourceRootLayouts":layouts,"nodes":nodes,
        "nativeFullScope":full_snapshot.as_ref().map(|full| json!({
            "evidenceHash":scope.full_scope.as_ref().map(|binding| &binding.evidence_hash),
            "expectedFullScope":full.evidence["expectedFullScope"],
            "rootCaptures":full.roots,"deletedNodes":full.deleted,
            "baselineReference":full.evidence["baseline"]["reference"],
            "baselineScope":full.evidence["baseline"]["scope"],
        })),
    });
    let signed = bounded_digest(&evidence)?;
    let authority = inner
        .operation_authority
        .lock()
        .map_err(poison)?
        .clone()
        .context("native source receipt requires device authority")?;
    let device_mac = authority(&signed)?;
    let roots = roots.clone();
    let original_plan = Arc::clone(&job.plan);
    let weak = Arc::downgrade(inner);
    let operation = job.plan.operation;
    let receipt = Arc::new(PreparedCaptureReceipt::new(
        evidence,
        Arc::new(move || {
            let inner = weak
                .upgrade()
                .context("native source owner is unavailable")?;
            ensure!(
                !inner.stopping.load(Ordering::Acquire),
                "native source owner is stopping"
            );
            inner._owner.check()?;
            ensure!(
                !inner
                    .active
                    .lock()
                    .map_err(poison)?
                    .get(&operation)
                    .is_some_and(|stop| stop.load(Ordering::Acquire)),
                "native source capture was cancelled"
            );
            let observed = authority(&signed)?;
            ensure!(
                observed
                    .iter()
                    .zip(device_mac)
                    .fold(0u8, |d, (a, b)| d | (*a ^ b))
                    == 0,
                "actual native source receipt device authentication failed"
            );
            // Never reenter Tracker from its own receipt callback.
            let _ = &full_authority;
            if let Work::Upload {
                full_snapshot: Some(full),
                ..
            } = &original_plan.work
            {
                full.revalidate_roots(&roots)?;
            }
            check_roots(&roots)
        }),
    ));
    receipt.revalidate()?;
    controller.accept(Arc::clone(&receipt))?;
    receipt.revalidate()?;
    completion::accepted(
        inner,
        job,
        manifest,
        &receipt.evidence["sourceExpectedManifestAuth"],
    )?;
    let mut accepted = inner.captures.lock().map_err(poison)?;
    if accepted.len() >= 128 {
        accepted.pop_first();
    }
    accepted.insert(
        job.plan.operation,
        (manifest_hash, Arc::downgrade(&receipt)),
    );
    drop(accepted);
    controller.verify_publication()
}

fn captured_nodes(plan: &FrozenPlan, manifest: &BundleManifest) -> Result<Vec<Value>> {
    let Work::Upload {
        capture_scope: Some(scope),
        roots,
        files,
        metadata,
        ..
    } = &plan.work
    else {
        bail!("original Windows capture node scope is missing")
    };
    let by_id = manifest
        .files
        .iter()
        .map(|file| (file_id(&file.logical_root, &file.relative_path), file))
        .collect::<BTreeMap<_, _>>();
    ensure!(
        by_id.len() == scope.node_count,
        "actual source capture added or omitted frozen nodes"
    );
    let root_ids = roots
        .iter()
        .map(|root| (root.logical.as_str(), root.id.as_str()))
        .collect::<BTreeMap<_, _>>();
    let mut nodes = Vec::with_capacity(scope.node_count);
    for expected in files {
        let file = by_id
            .get(&expected.id)
            .context("actual native capture omitted a file")?;
        nodes.push(
            json!({"id":expected.id,"rootId":root_ids[expected.root.as_str()],
            "path":expected.relative,"kind":"file","size":file.size,"stamp":expected.stamp,
            "fileHash":file.file_hash}),
        );
    }
    for expected in metadata {
        let id = file_id(&expected.root, &expected.relative);
        by_id
            .get(&id)
            .context("actual native capture omitted a metadata node")?;
        let mut node = json!({"id":id,"rootId":root_ids[expected.root.as_str()],
            "path":expected.relative,"kind":if expected.directory {"directory"} else {"symlink"},
            "size":0,"stamp":expected.stamp});
        if let Some(link) = &expected.link {
            node["linkTargetHash"] =
                json!(blake3::hash(link.target.as_bytes()).to_hex().to_string());
        }
        nodes.push(node);
    }
    nodes.sort_by(|a, b| a["id"].as_str().cmp(&b["id"].as_str()));
    Ok(nodes)
}

fn expected_body(plan: &FrozenPlan, manifest: &BundleManifest, nodes: &[Value]) -> Result<Value> {
    let Work::Upload {
        software,
        software_instance_id,
        roots,
        capture_scope: Some(scope),
        capture_origin: Some(origin),
        coverage,
        ..
    } = &plan.work
    else {
        bail!("original Windows capture generation/authorization is missing")
    };
    let manifest_hash = full_scope::metadata_digest(manifest)?;
    let files_hash = full_scope::metadata_digest(&manifest.files)?;
    let roots_fingerprint = native_roots_fingerprint(&manifest.app.app_id, roots)?;
    let layouts = manifest.environment["quicksave_native_root_layouts"].clone();
    ensure!(
        layouts.is_object(),
        "actual native capture lacks its authenticated source root layout"
    );
    let layouts_hash = full_scope::metadata_digest(&layouts)?;
    let proof_hash = full_scope::metadata_digest(&(
        &nodes,
        &manifest.tombstones,
        &layouts,
        &manifest.environment["quicksave_native"]["full_scope"],
    ))?;
    Ok(
        json!({"version":1,"operation":plan.operation,"app":manifest.app.app_id,
             "scope":scope,"manifestHash":manifest_hash,"capturedFilesHash":files_hash,
              "capturedProofHash":proof_hash,"rootLayoutsHash":layouts_hash,
            "rootsFingerprint":roots_fingerprint,"provider":plan.provider,"storage":plan.storage,
            "softwareId":software,"softwareInstanceId":software_instance_id,
            "sourceSnapshotId":manifest.bundle_id,"commitId":manifest.commit_id,
            "sourceInstanceId":manifest.source.instance_id,"mode":manifest.mode,"coverage":coverage,
            "selectionHash":full_scope::metadata_digest(&manifest.environment["quicksave_native"]["selection"])?,
            "generation":origin.generation,"automatic":origin.automatic,
            "captureOriginHash":full_scope::metadata_digest(origin)?}),
    )
}

/// Decoder for the actual Windows producer above, not Unix ManifestAuthentication.
pub(super) fn verify_source_auth(
    auth: &Value,
    master: &MasterKey,
    plan: &FrozenPlan,
    manifest: &BundleManifest,
) -> Result<()> {
    ensure!(
        auth["version"] == 1
            && auth["algorithm"] == EXPECTED_ALGORITHM
            && auth["operationId"] == plan.operation.to_string()
            && auth["aad"].as_str() == Some(std::str::from_utf8(EXPECTED_AAD)?),
        "original Windows expected-manifest envelope is unavailable"
    );
    let encoded = auth["envelopeHex"]
        .as_str()
        .context("original Windows envelope bytes are missing")?;
    ensure!(
        encoded.len() <= 128 * 1024
            && encoded.len() % 2 == 0
            && encoded
                .bytes()
                .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase()),
        "invalid original Windows expected-manifest envelope encoding"
    );
    let bytes = encoded
        .as_bytes()
        .chunks_exact(2)
        .map(|pair| u8::from_str_radix(std::str::from_utf8(pair)?, 16).map_err(anyhow::Error::from))
        .collect::<Result<Vec<_>>>()?;
    let body: Value = noland_storage::open_metadata_with_limit(
        &noland_crypto::derive_keys(master).manifest,
        EXPECTED_AAD,
        bytes,
        64 * 1024,
    )
    .map_err(source_error)?;
    let nodes = captured_nodes(plan, manifest)?;
    let expected = expected_body(plan, manifest, &nodes)?;
    ensure!(
        body == expected,
        "actual Windows source envelope differs from original frozen capture"
    );
    for field in [
        "manifestHash",
        "capturedFilesHash",
        "capturedProofHash",
        "rootLayoutsHash",
    ] {
        ensure!(
            auth[field] == body[field] && body[field].as_str().is_some_and(full_scope::raw_hash),
            "actual Windows source envelope hash fields changed"
        );
    }
    Ok(())
}

fn bounded_digest(value: &Value) -> Result<Vec<u8>> {
    struct Digest {
        hash: blake3::Hasher,
        count: usize,
    }
    impl Write for Digest {
        fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
            self.count = self
                .count
                .checked_add(bytes.len())
                .filter(|count| *count <= MAX_PLAN_BYTES)
                .ok_or_else(|| {
                    std::io::Error::other(
                        "native capture receipt exceeds its bounded document size",
                    )
                })?;
            self.hash.update(bytes);
            Ok(bytes.len())
        }
        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }
    let mut digest = Digest {
        hash: blake3::Hasher::new(),
        count: 0,
    };
    serde_json::to_writer(&mut digest, value)?;
    let mut signed = b"QuickSave actual Windows capture receipt v1\0".to_vec();
    signed.extend_from_slice(digest.hash.finalize().as_bytes());
    Ok(signed)
}
