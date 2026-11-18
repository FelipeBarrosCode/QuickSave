// SPDX-License-Identifier: GPL-3.0-only
//! Isolated native fixtures. The authority below is synthetic and native-only;
//! real service/Tracker grant tests and actual Windows execution remain required.
use super::*;
use crate::windows::tests::Fixture;

struct Owner {
    evidence: Value,
    digest: String,
    active: AtomicBool,
}
impl NativeFullScopeAuthority for Owner {
    fn evidence(&self) -> Result<Value> {
        self.revalidate()?;
        Ok(self.evidence.clone())
    }
    fn revalidate(&self) -> Result<()> {
        ensure!(
            self.active.load(Ordering::Acquire) && metadata_digest(&self.evidence)? == self.digest,
            "synthetic original full-scope owner was revoked or changed"
        );
        Ok(())
    }
}

struct Controller {
    nodes: Vec<FrozenCaptureNode>,
    owner: Option<Arc<Owner>>,
}
impl NativeCaptureController for Controller {
    fn node_page(
        &self,
        _: &CaptureScope,
        offset: usize,
        limit: usize,
    ) -> Result<Vec<FrozenCaptureNode>> {
        ensure!(
            offset <= self.nodes.len(),
            "synthetic node offset exceeds frozen scope"
        );
        Ok(self.nodes[offset..(offset + limit).min(self.nodes.len())].to_vec())
    }
    fn full_scope_authority(
        &self,
        _: &CaptureScope,
    ) -> Result<Option<Arc<dyn NativeFullScopeAuthority>>> {
        Ok(self
            .owner
            .as_ref()
            .map(|owner| Arc::clone(owner) as Arc<dyn NativeFullScopeAuthority>))
    }
    fn accept(&self, _: Arc<capture::PreparedCaptureReceipt>) -> Result<()> {
        bail!("metadata preparation cannot mint a completed CAS receipt")
    }
    fn verify_publication(&self) -> Result<()> {
        bail!("no actual CAS receipt has been accepted")
    }
}

fn binding(fixture: &Fixture, allowed_files: Option<BTreeSet<String>>) -> SoftwareBinding {
    let path = fixture.root.join("software");
    let handle = SafeRoot::open(&path).unwrap();
    let app = AppId::steam(480);
    let identity = AppIdentity::new(app.clone(), "Fixture");
    let root = RootSpec {
        id: "save".into(),
        logical: logical_token(app.as_str(), "save"),
        path,
        identity: handle.identity().unwrap(),
        allowed_files,
        role: NativeRootRole::Save,
    };
    let scope = if root.allowed_files.is_some() {
        ScopeIds::default()
    } else {
        ScopeIds::from_root(&handle).unwrap()
    };
    SoftwareBinding {
        id: "fixture".into(),
        app,
        instance: "steam:480@fixture".into(),
        name: "Fixture".into(),
        identity_fingerprint: noland_storage::compact_json_hash(&identity).unwrap(),
        identity,
        roots: vec![Arc::new(BoundRoot {
            spec: root,
            scope,
            handle,
        })],
        index: Vec::new(),
        index_revision: "fixture".into(),
        source_revision: None,
    }
}

fn evidence(binding: &SoftwareBinding, nodes: &[FrozenCaptureNode]) -> Value {
    let root = &binding.roots[0].spec;
    let capture = root_capture(root).unwrap();
    let tracking = json!({"softwareId":binding.id,"appId":binding.instance,"providerId":"fixture",
        "roots":[{"id":root.id,"path":root.path,"identity":root.identity,"role":"save","allowedFiles":root.allowed_files}]});
    let ids = nodes
        .iter()
        .map(|node| node.id.clone())
        .collect::<BTreeSet<_>>();
    let metadata_identity = metadata_digest(&nodes).unwrap();
    let scope = json!({
        "version":1,"workId":"work-fixture","softwareId":binding.id,"providerId":"fixture",
        "generation":1,"trackingScopeHash":metadata_digest(&tracking).unwrap(),
        "metadataIdentity":metadata_identity,"rootIds":["save"],
        "expectedNodeIdsHash":metadata_digest(&ids.iter().collect::<Vec<_>>()).unwrap(),
        "deletedNodeIdsHash":metadata_digest(&Vec::<String>::new()).unwrap(),
        "baselineKind":"none","baselineIdentity":null,"snapshotMode":"additive_full_scope","keepsHistory":true,
    });
    json!({
        "version":1,"workId":"work-fixture","softwareId":binding.id,"sourceIdentity":binding.identity,
        "providerId":"fixture","generation":1,"metadataIdentity":metadata_identity,
        "fullScope":true,"completeFileList":true,"keepsVersionHistory":true,
        "coverageScope":"approved_evidenced_roots_only",
        "expectedFullScope":{"scope":scope,"grant":{"syntheticNativeOwnerOnly":true}},
        "authorization":{"trackingScope":tracking,"trackingGrant":{"syntheticNativeOwnerOnly":true}},
        "roots":[{"id":root.id,"path":root.path,"identity":root.identity,
            "role":"save","allowedFiles":root.allowed_files}],
        "rootMetadata":if root.allowed_files.is_none() {json!({"save":capture.metadata})} else {json!({})},
        "rootStamps":if root.allowed_files.is_none() {json!({"save":capture.stamp})} else {json!({})},
        "deletedFileIds":[],"deletedNodes":[],
        "baseline":{"kind":"none","snapshotIdentity":null,"reference":null,"scope":null},
    })
}

fn controller(evidence: Value, nodes: Vec<FrozenCaptureNode>) -> Controller {
    Controller {
        nodes,
        owner: Some(Arc::new(Owner {
            digest: metadata_digest(&evidence).unwrap(),
            evidence,
            active: AtomicBool::new(true),
        })),
    }
}

fn frozen_scope(controller: &Controller) -> CaptureScope {
    let evidence = &controller.owner.as_ref().unwrap().evidence;
    CaptureScope {
        version: 1,
        work_id: "work-fixture".into(),
        metadata_identity: evidence["metadataIdentity"].as_str().unwrap().into(),
        node_count: controller.nodes.len(),
        full_scope: Some(FullScopeBinding::from_evidence(evidence).unwrap()),
    }
}

#[test]
fn raw_tracker_metadata_digest_schema_is_not_content_hash_schema() {
    let metadata = "a".repeat(64);
    let ids = metadata_digest(&Vec::<String>::new()).unwrap();
    let mut evidence = json!({
        "metadataIdentity":metadata,"roots":[{}],"deletedNodes":[],
        "expectedFullScope":{"scope":{"metadataIdentity":metadata,
            "trackingScopeHash":ids,"expectedNodeIdsHash":ids,"deletedNodeIdsHash":ids,
            "baselineIdentity":null}},
        "baseline":{"kind":"none","snapshotIdentity":null,"reference":null,"scope":null},
    });
    assert!(FullScopeBinding::from_evidence(&evidence).is_ok());
    for pointer in [
        "/metadataIdentity",
        "/expectedFullScope/scope/metadataIdentity",
        "/expectedFullScope/scope/trackingScopeHash",
        "/expectedFullScope/scope/expectedNodeIdsHash",
        "/expectedFullScope/scope/deletedNodeIdsHash",
    ] {
        let original = evidence.pointer(pointer).unwrap().clone();
        *evidence.pointer_mut(pointer).unwrap() =
            json!(format!("blake3:{}", original.as_str().unwrap()));
        assert!(
            FullScopeBinding::from_evidence(&evidence).is_err(),
            "{pointer}"
        );
        *evidence.pointer_mut(pointer).unwrap() = original;
    }
}

#[test]
fn additive_zero_nodes_require_live_native_owner_exact_roots_and_actual_empty_inventory() {
    let fixture = Fixture::new();
    let binding = binding(&fixture, None);
    let owner = controller(evidence(&binding, &[]), Vec::new());
    let scope = frozen_scope(&owner);
    let (files, metadata, proof) = capture::freeze(&binding, &scope, &owner, "fixture").unwrap();
    assert!(files.is_empty() && metadata.is_empty() && proof.is_some());
    let no_owner = Controller {
        nodes: Vec::new(),
        owner: None,
    };
    assert!(capture::freeze(&binding, &scope, &no_owner, "fixture").is_err());
    let mut marker_only = scope.clone();
    marker_only.full_scope = None;
    assert!(
        marker_only.validate().is_err(),
        "zero nodes without a real full-scope header are not permission"
    );
    binding.roots[0]
        .handle
        .write_new("new.dat", |file| {
            file.write_all(b"not frozen")?;
            Ok(())
        })
        .unwrap();
    assert!(
        capture::freeze(&binding, &scope, &owner, "fixture").is_err(),
        "an empty frozen list cannot suppress a real native entry added later"
    );
}

#[test]
fn full_scope_never_reads_manual_siblings_or_claims_their_parent_metadata() {
    let fixture = Fixture::new();
    let handle = SafeRoot::open(&fixture.root.join("software")).unwrap();
    handle
        .write_new("unselected.dat", |file| {
            file.write_all(b"unrelated")?;
            Ok(())
        })
        .unwrap();
    let binding = binding(
        &fixture,
        Some(BTreeSet::from(["missing-approved.dat".into()])),
    );
    let owner = controller(evidence(&binding, &[]), Vec::new());
    let scope = frozen_scope(&owner);
    let (_, _, proof) = capture::freeze(&binding, &scope, &owner, "fixture").unwrap();
    let proof = proof.unwrap();
    let root = &binding.roots[0].spec;
    let capture = serde_json::to_value(&proof.roots[0]).unwrap();
    assert!(capture["metadata"].is_null());
    assert_eq!(
        capture["metadataScope"],
        json!({
            "version":1,"kind":"manual_leaves_only","sourceRootId":root.id,
            "sourceRootIdentity":root.identity,
            "allowedFilesDigest":blake3::hash(&serde_json::to_vec(&root.allowed_files).unwrap())
                .to_hex().to_string(),
        })
    );
    for (pointer, value) in [
        ("/metadataScope", Value::Null),
        ("/metadataScope/version", json!(2)),
        ("/metadataScope/sourceRootId", json!("another-root")),
        (
            "/metadataScope/sourceRootIdentity/fileId/1",
            json!(root.identity.file_id[1] ^ (1 << 63)),
        ),
        ("/metadataScope/allowedFilesDigest", json!("0".repeat(64))),
        ("/allowedFiles", json!([])),
    ] {
        let mut changed = capture.clone();
        *changed.pointer_mut(pointer).unwrap() = value;
        let changed: RootCapture = serde_json::from_value(changed).unwrap();
        assert!(changed.validate_metadata_scope(root).is_err(), "{pointer}");
    }
    let whole = root_capture(&RootSpec {
        allowed_files: None,
        ..root.clone()
    })
    .unwrap();
    assert!(serde_json::to_value(&whole)
        .unwrap()
        .get("metadataScope")
        .is_none());
    let mut promoted = proof.clone();
    promoted.roots[0].metadata = whole.metadata;
    assert!(
        promoted
            .validate_scope(
                &binding.app,
                &binding.id,
                &binding.instance,
                "fixture",
                &scope,
                &[root.clone()]
            )
            .is_err(),
        "native stat data cannot promote original manual-leaf metadata authority"
    );
    let mut empty = BundleManifest::new(
        noland_state_core::ManifestApp::from(&binding.identity),
        noland_state_core::ManifestSource {
            instance_id: Uuid::new_v4(),
            image_id: "isolated-fixture".into(),
            captured_at: chrono::Utc::now(),
        },
        noland_state_core::BackupMode::CompleteApplication,
    );
    empty.environment = json!({"quicksave_native":{
        "coverage":"full_approved_scope","software_instance_id":binding.instance,
        "rootsFingerprint":native_roots_fingerprint(&binding.app,&[root.clone()]).unwrap(),
    }});
    assert!(proof.apply_manifest(&mut empty,None,&[root.clone()]).is_err(),
        "missing manual leaves without authenticated prior deleted IDs cannot create an empty parent");
    owner
        .owner
        .as_ref()
        .unwrap()
        .active
        .store(false, Ordering::Release);
    assert!(capture::freeze(&binding, &scope, &owner, "fixture").is_err());
}

#[test]
fn complete_inventory_is_independent_of_the_browse_index_and_cannot_predict_hashes() {
    let fixture = Fixture::new();
    let handle = SafeRoot::open(&fixture.root.join("software")).unwrap();
    handle
        .write_new("data", |file| {
            file.write_all(b"actual source bytes")?;
            Ok(())
        })
        .unwrap();
    let binding = binding(&fixture, None);
    let root = &binding.roots[0].spec;
    let (_, stamp) = binding.roots[0].handle.read_file("data").unwrap();
    let nodes = vec![FrozenCaptureNode {
        id: file_id(&root.logical, "data"),
        root_id: root.id.clone(),
        logical_root: root.logical.clone(),
        path: "data".into(),
        kind: "file".into(),
        size: stamp.size,
        stamp,
        link_target_hash: None,
    }];
    let owner = controller(evidence(&binding, &nodes), nodes);
    let scope = frozen_scope(&owner);
    let (files, _, proof) = capture::freeze(&binding, &scope, &owner, "fixture").unwrap();
    assert!(
        binding.index.is_empty(),
        "no metadata browser index can invent capture authority"
    );
    assert_eq!(files.len(), 1);
    assert!(
        files[0].hash.is_empty(),
        "only the actual CAS pass can fill file hashes"
    );
    assert!(proof.is_some());
    let omitted = controller(evidence(&binding, &[]), Vec::new());
    assert!(capture::freeze(&binding, &frozen_scope(&omitted), &omitted, "fixture").is_err());
}

#[test]
fn full_native_root_proof_rejects_high_id_changes_and_posix_metadata_substitution() {
    let fixture = Fixture::new();
    let binding = binding(&fixture, None);
    let mut value = evidence(&binding, &[]);
    let high = value["roots"][0]["identity"]["fileId"][1].as_u64().unwrap();
    value["roots"][0]["identity"]["fileId"][1] = json!(high ^ (1 << 63));
    let owner = controller(value, Vec::new());
    assert!(capture::freeze(&binding, &frozen_scope(&owner), &owner, "fixture").is_err());
    let mut value = evidence(&binding, &[]);
    value["rootMetadata"]["save"] = json!({"mode":0o40700,"owner":0,"group":0,"linkCount":1});
    let owner = controller(value, Vec::new());
    assert!(capture::freeze(&binding, &frozen_scope(&owner), &owner, "fixture").is_err());
}

#[test]
fn native_v3_root_fingerprint_binds_role_leaf_kind_and_both_identity_words() {
    let fixture = Fixture::new();
    let binding = binding(&fixture, None);
    let mut roots = vec![binding.roots[0].spec.clone()];
    let original = native_roots_fingerprint(&binding.app, &roots).unwrap();
    roots[0].identity.file_id[1] ^= 1 << 63;
    assert_ne!(
        native_roots_fingerprint(&binding.app, &roots).unwrap(),
        original
    );
    roots[0] = binding.roots[0].spec.clone();
    roots[0].role = NativeRootRole::Config;
    assert_ne!(
        native_roots_fingerprint(&binding.app, &roots).unwrap(),
        original
    );
    let value = native_root_layouts_value(
        &binding.app,
        &binding.instance,
        &[binding.roots[0].spec.clone()],
        None,
    )
    .unwrap();
    assert_eq!(value["app_id"], "steam:480");
    assert_eq!(value["software_instance_id"], "steam:480@fixture");
    assert_eq!(value["roots"][0]["source_kind"], "directory");
    assert_eq!(value["roots"][0]["leaf_name"], "software");
    assert_eq!(value["roots"][0]["role"], "save");
}

#[test]
fn canonical_tombstones_keep_verified_prior_data_in_authenticated_history_not_wire_fields() {
    tombstones_keep_original_history(false);
    tombstones_keep_original_history(true);
}

fn tombstones_keep_original_history(manual_leaves: bool) {
    use noland_state_core::{
        BackupMode, ManifestApp, ManifestSource, PersistenceClass, SemanticRole,
    };
    let fixture = Fixture::new();
    let handle = SafeRoot::open(&fixture.root.join("software")).unwrap();
    let bytes = b"isolated prior native bytes";
    handle
        .write_new("removed.dat", |file| {
            file.write_all(bytes)?;
            Ok(())
        })
        .unwrap();
    let (file, stamp) = handle.read_file("removed.dat").unwrap();
    let metadata = NativeMetadata::from_native(&WindowsMetadata::from_file(&file).unwrap());
    drop(file);
    std::fs::remove_file(fixture.root.join("software/removed.dat")).unwrap();
    let binding = binding(
        &fixture,
        manual_leaves.then(|| BTreeSet::from(["removed.dat".into()])),
    );
    let roots = vec![binding.roots[0].spec.clone()];
    let root = &roots[0];
    let source = ManifestSource {
        instance_id: Uuid::new_v4(),
        image_id: "quicksave-native-windows".into(),
        captured_at: chrono::Utc::now(),
    };
    let roots_hash = native_roots_fingerprint(&binding.app, &roots).unwrap();
    let mut parent = BundleManifest::new(
        ManifestApp::from(&binding.identity),
        source.clone(),
        BackupMode::CompleteApplication,
    );
    parent.environment = json!({"quicksave_native":{
        "software_instance_id":binding.instance,"selection":{"roots_fingerprint":roots_hash},
    }});
    parent.files.push(ManifestFile {
        logical_root: root.logical.clone(),
        relative_path: "removed.dat".into(),
        source_path_hint: None,
        file_type: "file".into(),
        size: stamp.size,
        file_hash: noland_cas::blake3_hex(bytes),
        chunks: vec![noland_state_core::ChunkRef {
            hash: noland_cas::blake3_hex(bytes),
            size: stamp.size,
        }],
        mode: None,
        mtime_ns: Some(mtime_ns_from_stamp(&stamp).unwrap()),
        uid: None,
        gid: None,
        symlink_target: None,
        persistence_class: PersistenceClass::PersistentState,
        semantic_role: SemanticRole::UserState,
        association_confidence: 1.0,
        shared_app_ids: Vec::new(),
    });
    let id = file_id(&root.logical, "removed.dat");
    let mut original = evidence(&binding, &[]);
    original["deletedFileIds"] = json!([id]);
    original["deletedNodes"] = json!([{
        "id":id,"rootId":root.id,"path":"removed.dat","kind":"file","size":stamp.size,
        "stamp":stamp,"metadata":metadata,
        "fileHash":blake3::hash(bytes).to_hex().to_string(),"linkTargetHash":null,
    }]);
    let baseline_kind = if manual_leaves { "partial" } else { "full" };
    original["baseline"] = json!({"kind":baseline_kind,"snapshotIdentity":"f".repeat(64),
        "reference":{"hash":"e".repeat(64),"name":"fixture-baseline"},
        "scope":{"hash":"e".repeat(64),"name":"fixture-baseline"}});
    original["expectedFullScope"]["scope"]["baselineKind"] = json!(baseline_kind);
    original["expectedFullScope"]["scope"]["baselineIdentity"] = json!("f".repeat(64));
    original["expectedFullScope"]["scope"]["deletedNodeIdsHash"] =
        json!(metadata_digest(&vec![&id]).unwrap());
    let owner = controller(original, Vec::new());
    let (_, _, full) = capture::freeze(&binding, &frozen_scope(&owner), &owner, "fixture").unwrap();
    let full = full.unwrap();
    let mut current = BundleManifest::new(
        ManifestApp::from(&binding.identity),
        source,
        BackupMode::CompleteApplication,
    );
    current.parent_bundle_id = Some(parent.bundle_id);
    current.environment = json!({"platform":"windows",
        "quicksave_native_root_layouts":frozen_root_layouts_value(&binding.app,&binding.instance,&roots,None).unwrap(),
        "quicksave_native":{
        "coverage":"full_approved_scope","software_instance_id":binding.instance,"rootsFingerprint":roots_hash,
    }});
    full.apply_manifest(&mut current, Some(&parent), &roots)
        .unwrap();
    let tombstone = serde_json::to_value(&current.tombstones[0]).unwrap();
    assert_eq!(tombstone.as_object().unwrap().len(), 3);
    for key in ["logical_root", "relative_path", "reason"] {
        assert!(tombstone.get(key).is_some());
    }
    let history = &current.environment["quicksave_native"]["full_scope"];
    assert_eq!(history["sourceParent"], parent.bundle_id.to_string());
    assert_eq!(
        history["sourceParentManifestHash"],
        noland_storage::compact_json_hash(&parent).unwrap()
    );
    assert_eq!(
        history["sourceParentMode"],
        serde_json::to_value(parent.mode).unwrap()
    );
    assert_eq!(
        history["sourcePriorEntries"][0]["fileHash"],
        parent.files[0].file_hash
    );
    assert_eq!(history["sourcePriorEntries"][0]["size"], stamp.size);
    assert_eq!(
        history["sourcePriorEntries"][0]["semanticRole"],
        "USER_STATE"
    );
    assert_eq!(history["originalTrackerEvidence"]["softwareId"], binding.id);
    assert_eq!(
        history["originalTrackerEvidence"]["authorization"]["trackingScope"]["appId"],
        binding.instance
    );
    if manual_leaves {
        assert!(current.files.is_empty());
        assert_eq!(history["deletedNodes"][0]["id"], id);
        assert!(history["rootCaptures"][0]["metadata"].is_null());
        assert_eq!(
            history["rootCaptures"][0]["metadataScope"]["sourceRootIdentity"],
            json!(root.identity)
        );
        assert_eq!(
            history["rootCaptures"][0]["metadataScope"]["kind"],
            "manual_leaves_only"
        );
        // Exercise the actual source manifest AEAD framing, not a parallel JSON
        // projection. The versioned scope is inside the authenticated payload.
        let master = MasterKey::from_bytes([29; 32]);
        let key = noland_crypto::derive_keys(&master).manifest;
        let sealed = noland_storage::seal_metadata(&key, b"manifest", &current).unwrap();
        let decoded: BundleManifest =
            noland_storage::open_metadata(&key, b"manifest", sealed.envelope).unwrap();
        assert_eq!(
            decoded.environment["quicksave_native"]["full_scope"]["rootCaptures"],
            history["rootCaptures"]
        );
        assert_eq!(decoded.tombstones.len(), 1);
        let mut restore_payload = decoded;
        super::super::restore::select_payload(&mut restore_payload, None).unwrap();
        assert_eq!(
            restore_payload.tombstones.len(),
            1,
            "whole-revision handoff must not erase authenticated manual omission proof"
        );
        assert!(restore_payload.files.is_empty());
        let mut empty_parent = parent.clone();
        empty_parent.files.clear();
        assert!(full.apply_manifest(&mut current.clone(), Some(&empty_parent), &roots).is_err(),
            "manual last-leaf deletion needs its real prior authenticated file, not an invented empty parent");
    } else {
        assert!(history["rootCaptures"][0].get("metadataScope").is_none());
    }
    let mut bad = parent.clone();
    bad.files[0].file_hash = noland_cas::blake3_hex(b"different prior bytes");
    assert!(
        full.apply_manifest(&mut current, Some(&bad), &roots)
            .is_err(),
        "canonical wire fields must not drop the original captured-hash comparison"
    );
    let mut bad = parent.clone();
    bad.source.instance_id = Uuid::new_v4();
    assert!(full
        .apply_manifest(&mut current, Some(&bad), &roots)
        .is_err());
    let mut bad = parent.clone();
    bad.environment["quicksave_native"]["selection"]["roots_fingerprint"] = json!("c".repeat(64));
    assert!(full
        .apply_manifest(&mut current, Some(&bad), &roots)
        .is_err());
    let mut bad = parent.clone();
    bad.files[0].semantic_role = SemanticRole::AppContent;
    assert!(full
        .apply_manifest(&mut current, Some(&bad), &roots)
        .is_err());
    let mut wrong_mode = current.clone();
    wrong_mode.mode = BackupMode::Custom;
    assert!(full
        .apply_manifest(&mut wrong_mode, Some(&parent), &roots)
        .is_err());
}
