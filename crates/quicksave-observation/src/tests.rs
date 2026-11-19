// SPDX-License-Identifier: GPL-3.0-only
//! All process/kernel observations are injected. Filesystem fixtures are created
//! in isolated temporary directories; no real process, account, vault or app
//! state is queried by these tests.
use super::*;
use anyhow::Result;
use quicksave_integrations::profiles::{
    Architecture, InstallIdentity, InstallKind, Platform, ProductIdentity,
};
use quicksave_platform::{FileStamp, SafeRoot};
use std::{
    collections::{BTreeSet, VecDeque},
    fs,
    path::{Path, PathBuf},
    sync::{
        atomic::{AtomicBool, AtomicUsize, Ordering},
        mpsc::{channel, sync_channel},
        Arc, Mutex,
    },
    time::Duration,
};

struct Fixture {
    _temp: tempfile::TempDir,
    executable_dir: PathBuf,
    data_dir: PathBuf,
    executable: PathBuf,
    file: PathBuf,
}

impl Fixture {
    fn new() -> Self {
        let base = fs::canonicalize(std::env::temp_dir()).unwrap();
        let temp = tempfile::tempdir_in(base).unwrap();
        let executable_dir = temp.path().join("Synthetic.app/Contents/MacOS");
        let data_dir = temp.path().join("ApprovedData");
        fs::create_dir_all(&executable_dir).unwrap();
        fs::create_dir(&data_dir).unwrap();
        let executable = executable_dir.join("same-name");
        let file = data_dir.join("slot.dat");
        fs::write(&executable, b"synthetic image, never executed").unwrap();
        fs::write(&file, b"synthetic payload, never read by observation").unwrap();
        Self {
            _temp: temp,
            executable_dir,
            data_dir,
            executable,
            file,
        }
    }

    fn request(&self) -> ScopeRequest {
        let identity = quicksave_integrations::AppIdentity {
            product: ProductIdentity::DesktopEntryId("org.fixture.game.desktop".into()),
            install: InstallIdentity {
                kind: InstallKind::DesktopLauncher,
                location: None,
                metadata_path: self.executable_dir.join("org.fixture.game.desktop"),
            },
            platform: Platform::Linux,
            architecture: Architecture::Unknown,
        };
        ScopeRequest {
            id: "fixture-scope".into(),
            uid: 501,
            roots: vec![
                RootSpec {
                    id: "image".into(),
                    path: self.executable_dir.clone(),
                    identity: SafeRoot::open(&self.executable_dir)
                        .unwrap()
                        .identity()
                        .unwrap(),
                    kind: ObservationRootKind::Executable,
                    allowed_files: None,
                },
                RootSpec {
                    id: "data".into(),
                    path: self.data_dir.clone(),
                    identity: SafeRoot::open(&self.data_dir).unwrap().identity().unwrap(),
                    kind: ObservationRootKind::Data,
                    allowed_files: None,
                },
            ],
            applications: vec![ApplicationSpec {
                identity,
                executable: self.executable.clone(),
                executable_stamp: stamp(&self.executable),
            }],
            native_applications: vec![],
            excluded_paths: vec![],
            excluded_native_files: vec![],
        }
    }

    fn scope(&self) -> ObservationScope {
        approve(self.request())
    }

    fn process(&self) -> ProcessDescriptor {
        ProcessDescriptor {
            generation: ProcessGeneration {
                pid: 41,
                uid: 501,
                start: [1000, 9],
                namespace: [80, 2],
            },
            executable: self.executable.clone(),
            executable_identity: NativeFileIdentity::from(&stamp(&self.executable)),
            image_binding: ImageIdentityBinding::MappedImageNativeFile,
            bundle_identifier: None,
        }
    }

    fn descriptor(&self) -> DescriptorSample {
        DescriptorSample {
            path: self.file.clone(),
            identity: NativeFileIdentity::from(&stamp(&self.file)),
        }
    }
}

fn approve(request: ScopeRequest) -> ObservationScope {
    ObservationScope::approve(request, Arc::new(|_: &ScopeRequest| Ok(true))).unwrap()
}

fn stamp(path: &Path) -> FileStamp {
    let root = SafeRoot::open(path.parent().unwrap()).unwrap();
    root.read_file(path.file_name().unwrap().to_str().unwrap())
        .unwrap()
        .1
}

fn fixture_capabilities() -> SourceCapabilities {
    SourceCapabilities {
        source: SourceKind::InjectedFixture,
        state: CapabilityState::Available,
        process_generations: true,
        executable_stamps: true,
        running_image_native_identity: true,
        native_open_file_identity: true,
        bundle_identifier_verification: true,
        complete_lifecycle_stream: false,
        complete_file_stream: false,
        reason: "Injected isolated fixture; no native process calls.",
    }
}

struct FixtureProbe {
    process: ProcessDescriptor,
    descriptor: DescriptorSample,
    process_sequence: VecDeque<Option<ProcessDescriptor>>,
    descriptor_sequence: VecDeque<Option<DescriptorSample>>,
    process_calls: usize,
    calls: Arc<AtomicUsize>,
    on_process: Option<Box<dyn FnMut(usize) + Send>>,
    listing_complete: bool,
    descriptor_listing_complete: bool,
    empty: bool,
    error: bool,
    fd_count: usize,
}

impl FixtureProbe {
    fn new(fixture: &Fixture) -> Self {
        Self {
            process: fixture.process(),
            descriptor: fixture.descriptor(),
            process_sequence: VecDeque::new(),
            descriptor_sequence: VecDeque::new(),
            process_calls: 0,
            calls: Arc::new(AtomicUsize::new(0)),
            on_process: None,
            listing_complete: true,
            descriptor_listing_complete: true,
            empty: false,
            error: false,
            fd_count: 1,
        }
    }
}

impl ProcessProbe for FixtureProbe {
    fn capabilities(&self) -> SourceCapabilities {
        fixture_capabilities()
    }
    fn processes(&mut self, _: &ObservationScope, max: usize) -> Result<ProbeListing<u32>> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        if self.error {
            return Err(std::io::Error::new(
                std::io::ErrorKind::PermissionDenied,
                "injected native permission denial",
            )
            .into());
        }
        Ok(ProbeListing {
            items: if self.empty { vec![] } else { vec![41] }
                .into_iter()
                .take(max)
                .collect(),
            complete: self.listing_complete,
        })
    }
    fn process(&mut self, _: &ObservationScope, _: u32) -> Result<Option<ProcessDescriptor>> {
        self.process_calls += 1;
        if let Some(hook) = &mut self.on_process {
            hook(self.process_calls);
        }
        Ok(self
            .process_sequence
            .pop_front()
            .unwrap_or_else(|| Some(self.process.clone())))
    }
    fn descriptors(&mut self, _: u32, max: usize) -> Result<ProbeListing<u64>> {
        Ok(ProbeListing {
            items: (7..7 + self.fd_count.min(max) as u64).collect(),
            complete: self.descriptor_listing_complete && self.fd_count <= max,
        })
    }
    fn descriptor(
        &mut self,
        _: &ObservationScope,
        _: u32,
        _: u64,
    ) -> Result<Option<DescriptorSample>> {
        Ok(self
            .descriptor_sequence
            .pop_front()
            .unwrap_or_else(|| Some(self.descriptor.clone())))
    }
}

fn engine(fixture: &Fixture, probe: FixtureProbe) -> ObservationEngine {
    ObservationEngine::new(
        fixture.scope(),
        Box::new(PollingSource::new(probe)),
        ObservationLimits::default(),
    )
    .unwrap()
}

fn fixture_digest(value: &serde_json::Value) -> String {
    blake3::hash(&serde_json::to_vec(value).unwrap())
        .to_hex()
        .to_string()
}
fn fixture_grant(kind: &str, value: &serde_json::Value) -> serde_json::Value {
    serde_json::json!({"kind":kind, "fixtureHash":fixture_digest(value)})
}
fn fixture_verify(
    kind: &str,
    scope: &serde_json::Value,
    grant: &serde_json::Value,
) -> Result<bool> {
    // Deliberately injected fixture authenticator, never production authority.
    Ok(grant == &fixture_grant(kind, scope))
}
fn materialized_records(fixture: &Fixture) -> (serde_json::Value, serde_json::Value) {
    use serde_json::{json, Value};
    let request = fixture.request();
    let roots: Vec<Value> = request.roots.iter().map(|root| json!({
        "id":root.id, "path":root.path, "role":if root.id == "image" {"runtime"} else {"save"},
        "identity":root.identity, "allowedFiles":if root.id == "image" {
            vec!["same-name"]
        } else {vec!["slot.dat"]}
    })).collect();
    let source = json!({"app_id":"desktop:org.fixture.game.desktop",
        "desktop_entry_id":"org.fixture.game.desktop", "steam_app_id":null,
        "canonical_executable":fixture.executable});
    let policy = json!({"version":1, "enabled":true, "source":"verified_native_discovery", "excludedPaths":[]});
    let discovery = json!({"version":1, "source":"verified_native_discovery", "policyHash":fixture_digest(&policy)});
    let app_id = "desktop:org.fixture.game.desktop@native-install-fixture";
    let scope = json!({"version":1,"softwareId":"software-fixture","appId":app_id,"sourceIdentity":source,
        "roots":roots,"autoEnrollment":{"policyHash":fixture_digest(&policy),"discoveryHash":fixture_digest(&discovery)}});
    let mut index = json!({"version":1, "revisionId":"fixture-revision","snapshotIdentity":"fixture-snapshot",
        "trackingScopeHash":fixture_digest(&scope)});
    for kind in ["index", "manifest"] {
        let name = format!("{kind}-fixture.json");
        let hash = "a".repeat(64);
        let signed = json!({"version":1,"tracking":scope,"revisionId":"fixture-revision",
            "snapshotIdentity":"fixture-snapshot","kind":kind,"name":name,"hash":hash});
        index[kind] = json!({"name":name,"hash":hash,"grant":fixture_grant(&format!("bundle_{kind}"), &signed)});
    }
    let grant = fixture_grant("tracking", &scope);
    let record = json!({"id":"software-fixture","appId":app_id,"sourceIdentity":source,"tracked":true,
        "roots":roots,"trackingGrant":grant,"bundleIndexSource":index,
        "autoEnrollment":{"policyScope":policy,"policyGrant":fixture_grant("app_tracking_policy", &policy),
            "discoveryScope":discovery,"discoveryGrant":fixture_grant("bundle_discovery", &discovery)}});
    let authority = json!({"id":"software-fixture","softwareId":"software-fixture","appId":app_id,
        "sourceIdentity":source,"scope":scope,"grant":grant,"roots":roots});
    (record, authority)
}

#[test]
fn source_identity_ids_match_current_integrations_without_xdg_normalization() {
    let fixture = Fixture::new();
    let mut identity = fixture.request().applications.remove(0).identity;
    identity.product = ProductIdentity::SteamAppId(480);
    assert_eq!(stable_app_id(&identity).unwrap(), "steam:480");
    identity.product = ProductIdentity::MacBundleIdentifier("org.fixture.Signed".into());
    assert_eq!(
        stable_app_id(&identity).unwrap(),
        "mac-bundle:org.fixture.Signed"
    );
    identity.product = ProductIdentity::DesktopEntryId("Org.Fixture.Mixed-CASE.desktop".into());
    assert_eq!(
        stable_app_id(&identity).unwrap(),
        "desktop:Org.Fixture.Mixed-CASE.desktop"
    );
}

#[test]
fn materialized_adapter_preserves_actual_app_id_and_exact_file_scopes() {
    let fixture = Fixture::new();
    let (record, authority) = materialized_records(&fixture);
    let binding = integration::TrackerBundleBinding::from_native_records(
        &record,
        &authority,
        &fixture.executable,
        &fixture_verify,
    )
    .unwrap();
    assert_eq!(binding.source_app_id(), "desktop:org.fixture.game.desktop");
    assert_eq!(binding.app_id(), record["appId"].as_str().unwrap());
    let mut request = ScopeRequest::new("materialized-observation", 501, vec![], vec![]);
    binding.append_to_scope(&mut request).unwrap();
    assert_eq!(
        request
            .roots
            .iter()
            .find(|root| root.id == "data")
            .unwrap()
            .allowed_files,
        Some(BTreeSet::from(["slot.dat".into()]))
    );
    let scope = approve(request);
    let context = scope.context();
    let mut observer = ObservationEngine::new(
        scope,
        Box::new(PollingSource::new(FixtureProbe::new(&fixture))),
        ObservationLimits::default(),
    )
    .unwrap();
    let first = observer.reconcile(10).unwrap();
    assert_eq!(first.files[0].process().app_id(), binding.app_id());
    let hint = binding.hint(&first, &context).unwrap().unwrap();
    assert_eq!(hint.scope()["appId"], record["appId"]);
    let event = hint.into_event(serde_json::json!({"injected":"fixture-only"}));
    assert_eq!(event["kind"], "app_open");
    assert_eq!(event["nativeObservation"]["clean"], false);
    binding
        .validate_current(&record, &authority, &fixture_verify)
        .unwrap();
    // Remove the one-time restart recovery; subsequent silence is still
    // unknown, but no event is signed and no content reconciliation is queued.
    observer.reconcile(11).unwrap();
    let quiet = observer.reconcile(12).unwrap();
    assert_eq!(quiet.applications[0].completeness, "unknown");
    assert!(!quiet.activity_observed);
    assert!(binding.hint(&quiet, &context).unwrap().is_none());
}

#[test]
fn materialized_adapter_rejects_placeholder_unsigned_policy_and_unselected_executable() {
    let fixture = Fixture::new();
    let (record, authority) = materialized_records(&fixture);
    let mut placeholder = record.clone();
    placeholder["bundleIndexSource"] = serde_json::Value::Null;
    assert!(integration::TrackerBundleBinding::from_native_records(
        &placeholder,
        &authority,
        &fixture.executable,
        &fixture_verify
    )
    .is_err());
    let mut revoked = record.clone();
    revoked["autoEnrollment"]["policyGrant"] = serde_json::Value::Null;
    assert!(integration::TrackerBundleBinding::from_native_records(
        &revoked,
        &authority,
        &fixture.executable,
        &fixture_verify
    )
    .is_err());
    assert!(integration::TrackerBundleBinding::from_native_records(
        &record,
        &authority,
        &fixture.executable_dir.join("unapproved-sibling"),
        &fixture_verify
    )
    .is_err());
    let mut widened = authority.clone();
    widened["roots"][1]["allowedFiles"] = serde_json::Value::Null;
    assert!(integration::TrackerBundleBinding::from_native_records(
        &record,
        &widened,
        &fixture.executable,
        &fixture_verify
    )
    .is_err());
}

#[test]
fn adding_exact_roots_never_unions_leaves_or_promotes_a_parent() {
    let fixture = Fixture::new();
    let mut root = fixture.request().roots.remove(1);
    root.allowed_files = Some(BTreeSet::from(["slot.dat".into()]));
    let mut request = ScopeRequest::new("exact-roots", 501, vec![], vec![]);
    request.add_exact_root(root.clone()).unwrap();
    let mut wider = root.clone();
    wider.allowed_files = None;
    assert!(request.add_exact_root(wider).is_err());
    let mut sibling = root;
    sibling.allowed_files = Some(BTreeSet::from(["sibling".into()]));
    assert!(request.add_exact_root(sibling).is_err());
    assert_eq!(
        request.roots[0].allowed_files,
        Some(BTreeSet::from(["slot.dat".into()]))
    );
}

#[test]
fn materialized_append_rolls_back_roots_and_applications_on_failure() {
    let fixture = Fixture::new();
    let (record, authority) = materialized_records(&fixture);
    let binding = integration::TrackerBundleBinding::from_native_records(
        &record,
        &authority,
        &fixture.executable,
        &fixture_verify,
    )
    .unwrap();
    let mut conflict = binding.roots()[1].clone();
    conflict.allowed_files = None;
    let mut request = ScopeRequest::new("rollback-fixture", 501, vec![conflict], vec![]);
    let original = request.fingerprint().unwrap();
    assert!(binding.append_to_scope(&mut request).is_err());
    assert_eq!(request.fingerprint().unwrap(), original);
    assert!(request.native_applications.is_empty());

    let mut request = ScopeRequest::new("duplicate-fixture", 501, vec![], vec![]);
    binding.append_to_scope(&mut request).unwrap();
    let original = request.fingerprint().unwrap();
    assert!(binding.append_to_scope(&mut request).is_err());
    assert_eq!(request.fingerprint().unwrap(), original);
}

#[test]
fn larger_explicit_scopes_share_native_handles_without_unioning_root_selections() {
    let fixture = Fixture::new();
    let mut request = fixture.request();
    let data = request.roots[1].clone();
    for index in 0..68 {
        let mut root = data.clone();
        root.id = format!("separate-logical-root-{index}");
        root.allowed_files = Some(BTreeSet::from(["slot.dat".into()]));
        request.add_exact_root(root).unwrap();
    }
    assert!(
        ObservationScope::approve(request.clone(), Arc::new(|_: &ScopeRequest| Ok(true)),).is_err()
    ); // default 64 remains explicit, not a truncation
    let limits = ObservationLimits {
        max_roots: 4096,
        ..ObservationLimits::default()
    };
    let scope = ObservationScope::approve_with_limits(
        request,
        Arc::new(|_: &ScopeRequest| Ok(true)),
        &limits,
    )
    .unwrap();
    assert_eq!(scope.roots().count(), 70);
    assert!(Arc::ptr_eq(
        &scope.roots["data"].handle,
        &scope.roots["separate-logical-root-0"].handle,
    ));
    assert_eq!(
        scope.roots["separate-logical-root-0"].spec.allowed_files,
        Some(BTreeSet::from(["slot.dat".into()]))
    );
}

#[test]
fn periodic_polling_gaps_do_not_dirty_or_rehash_an_unchanged_materialized_app() {
    let fixture = Fixture::new();
    let mut observer = engine(&fixture, FixtureProbe::new(&fixture));
    observer.reconcile(10).unwrap();
    let second = observer.reconcile(11).unwrap();
    let third = observer.reconcile(12).unwrap();
    assert_eq!(
        third.applications[0].dirty_generation,
        second.applications[0].dirty_generation
    );
    assert!(!third.activity_observed);
    assert!(has_gap(
        &third,
        GapReason::PollingCannotObserveShortLivedOpens
    ));
    assert_eq!(third.applications[0].completeness, "unknown");
}

fn has_gap(snapshot: &ObservationSnapshot, gap: GapReason) -> bool {
    snapshot.gaps.iter().any(|item| item.reason == gap)
}

#[test]
fn native_use_evidence_is_not_ownership_or_backup_authority() {
    let fixture = Fixture::new();
    let mut observer = engine(&fixture, FixtureProbe::new(&fixture));
    let snapshot = observer.reconcile(100).unwrap();
    assert_eq!(
        snapshot.applications[0].app_id,
        "desktop:org.fixture.game.desktop"
    );
    assert_eq!(
        snapshot.applications[0].execution_state,
        ExecutionState::Running
    );
    assert_eq!(
        snapshot.applications[0].open_file_state,
        OpenFileState::OpenFilesObserved
    );
    assert_eq!(snapshot.files.len(), 1);
    assert_eq!(snapshot.files[0].root_id(), "data");
    assert_eq!(snapshot.files[0].relative_path(), "slot.dat");
    assert!(snapshot.applications[0].root_candidates[0].requires_native_policy_validation);
    assert!(!snapshot.applications[0].root_candidates[0].grants_tracking_authority);
    assert_eq!(snapshot.backup_authority, "not_granted");
    assert!(!snapshot.application_atomic);
    assert_eq!(snapshot.applications[0].completeness, "unknown");
    assert!(has_gap(
        &snapshot,
        GapReason::PollingCannotObserveShortLivedOpens
    ));
    let json = serde_json::to_string(snapshot.as_ref()).unwrap();
    assert!(!json.contains("synthetic payload"));
    assert!(!json.contains("SourcePath"));
    let page = snapshot.evidence_page(snapshot.epoch, 0, 1).unwrap();
    assert_eq!(page.files.len(), 1);
    let page_json = serde_json::to_string(&page).unwrap();
    assert!(!page_json.contains("executable_stamp"));
    assert!(!page_json.contains("scope_fingerprint"));
    assert!(snapshot.evidence_page(snapshot.epoch + 1, 0, 1).is_err());
    assert!(snapshot.evidence_page(snapshot.epoch, 0, 257).is_err());
}

#[test]
fn pid_reuse_during_poll_invalidates_all_file_evidence() {
    let fixture = Fixture::new();
    let mut probe = FixtureProbe::new(&fixture);
    let before = fixture.process();
    let mut reused = before.clone();
    reused.generation.start[0] += 1;
    probe.process_sequence = VecDeque::from([Some(before), Some(reused)]);
    let snapshot = engine(&fixture, probe).reconcile(100).unwrap();
    assert!(snapshot.files.is_empty());
    assert_eq!(
        snapshot.applications[0].execution_state,
        ExecutionState::Unknown
    );
    assert!(has_gap(
        &snapshot,
        GapReason::ProcessChangedDuringObservation
    ));
}

#[test]
fn descriptor_swap_or_deleted_replacement_cannot_borrow_a_name() {
    let fixture = Fixture::new();
    for change_native_id in [true, false] {
        let mut probe = FixtureProbe::new(&fixture);
        let first = fixture.descriptor();
        let second = if change_native_id {
            let mut replacement = first.clone();
            replacement.identity.file_id[0] += 1;
            Some(replacement)
        } else {
            None
        };
        probe.descriptor_sequence = VecDeque::from([Some(first), second]);
        let snapshot = engine(&fixture, probe).reconcile(100).unwrap();
        assert!(snapshot.files.is_empty());
        assert!(has_gap(
            &snapshot,
            GapReason::DescriptorChangedDuringObservation
        ));
        assert_eq!(
            snapshot.applications[0].open_file_state,
            OpenFileState::Unknown
        );
    }
}

#[test]
fn exec_during_poll_cannot_keep_the_old_app_binding() {
    let fixture = Fixture::new();
    let mut probe = FixtureProbe::new(&fixture);
    let first = fixture.process();
    let mut second = first.clone();
    second.executable = fixture.executable_dir.join("other-image");
    probe.process_sequence = VecDeque::from([Some(first), Some(second)]);
    let snapshot = engine(&fixture, probe).reconcile(100).unwrap();
    assert!(snapshot.files.is_empty());
    assert!(has_gap(
        &snapshot,
        GapReason::ProcessChangedDuringObservation
    ));
}

#[test]
fn namespace_change_invalidates_generation_even_when_pid_and_path_match() {
    let fixture = Fixture::new();
    let mut probe = FixtureProbe::new(&fixture);
    let first = fixture.process();
    let mut second = first.clone();
    second.generation.namespace[0] += 1;
    probe.process_sequence = VecDeque::from([Some(first), Some(second)]);
    let snapshot = engine(&fixture, probe).reconcile(100).unwrap();
    assert!(snapshot.files.is_empty());
    assert!(has_gap(
        &snapshot,
        GapReason::ProcessChangedDuringObservation
    ));
}

#[test]
fn root_remount_or_namespace_replacement_is_not_reapproved() {
    let fixture = Fixture::new();
    let mut probe = FixtureProbe::new(&fixture);
    let data = fixture.data_dir.clone();
    let original = fs::read(&fixture.file).unwrap();
    let blocked = Arc::new(AtomicBool::new(false));
    let attempted = blocked.clone();
    probe.on_process = Some(Box::new(move |call| {
        if call == 2 {
            if cfg!(windows) {
                // Native Windows directory handles deliberately deny delete
                // sharing: this attack must be prevented before replacement,
                // not made possible merely to exercise the Unix detector.
                let error =
                    fs::rename(&data, data.with_file_name("old-approved-data")).unwrap_err();
                assert_eq!(error.raw_os_error(), Some(32), "{error}");
                attempted.store(true, Ordering::Release);
                return;
            }
            fs::rename(&data, data.with_file_name("old-approved-data")).unwrap();
            fs::create_dir(&data).unwrap();
            fs::write(data.join("slot.dat"), b"unapproved replacement").unwrap();
        }
    }));
    let snapshot = engine(&fixture, probe).reconcile(100).unwrap();
    if cfg!(windows) {
        assert!(blocked.load(Ordering::Acquire));
        assert_eq!(fs::read(&fixture.file).unwrap(), original);
        assert!(!fixture
            .data_dir
            .with_file_name("old-approved-data")
            .exists());
        assert!(!has_gap(&snapshot, GapReason::RootIdentityChanged));
        assert_eq!(snapshot.files.len(), 1);
        assert_eq!(snapshot.files[0].root_id(), "data");
        assert_eq!(snapshot.files[0].relative_path(), "slot.dat");
        return;
    }
    assert!(snapshot.files.is_empty());
    assert!(has_gap(&snapshot, GapReason::RootIdentityChanged));
    assert_eq!(
        snapshot.applications[0].execution_state,
        ExecutionState::Unknown
    );
}

#[test]
fn changed_executable_stamp_never_rebinds_an_existing_app_id() {
    let fixture = Fixture::new();
    let mut probe = FixtureProbe::new(&fixture);
    let executable = fixture.executable.clone();
    probe.on_process = Some(Box::new(move |call| {
        if call == 2 {
            fs::write(
                &executable,
                b"a different synthetic executable, never executed",
            )
            .unwrap();
        }
    }));
    let snapshot = engine(&fixture, probe).reconcile(100).unwrap();
    assert!(snapshot.files.is_empty());
    assert!(has_gap(
        &snapshot,
        GapReason::ProcessChangedDuringObservation
    ));
}

#[test]
fn bundle_id_is_native_verified_not_inferred_from_application_basename() {
    let fixture = Fixture::new();
    let mut request = fixture.request();
    request.applications[0].identity.product =
        ProductIdentity::MacBundleIdentifier("org.fixture.signed".into());
    let probe = FixtureProbe::new(&fixture); // no native signing ID
    let mut observer = ObservationEngine::new(
        approve(request.clone()),
        Box::new(PollingSource::new(probe)),
        ObservationLimits::default(),
    )
    .unwrap();
    let snapshot = observer.reconcile(100).unwrap();
    assert!(snapshot.files.is_empty());
    assert!(has_gap(&snapshot, GapReason::BundleIdentityUnverified));
    let mut probe = FixtureProbe::new(&fixture);
    probe.process.bundle_identifier = Some("org.fixture.signed".into());
    let mut observer = ObservationEngine::new(
        approve(request),
        Box::new(PollingSource::new(probe)),
        ObservationLimits::default(),
    )
    .unwrap();
    let snapshot = observer.reconcile(100).unwrap();
    assert_eq!(
        snapshot.files[0].process().app_id(),
        "mac-bundle:org.fixture.signed"
    );
}

#[test]
fn unknown_native_executable_has_a_separate_manual_review_identity() {
    let fixture = Fixture::new();
    let mut request = fixture.request();
    request.applications.clear();
    let mut observer = ObservationEngine::new(
        approve(request),
        Box::new(PollingSource::new(FixtureProbe::new(&fixture))),
        ObservationLimits::default(),
    )
    .unwrap();
    let snapshot = observer.reconcile(100).unwrap();
    assert!(snapshot.applications[0]
        .app_id
        .starts_with("quicksave.observed:"));
    assert!(!snapshot.applications[0].registered_identity);
    assert!(snapshot.applications[0].root_candidates[0].requires_manual_review);
}

#[test]
fn exclusions_exact_leaves_and_root_markers_are_filtered_without_metadata_reads() {
    let fixture = Fixture::new();
    for relative in [
        "RootNativeMarker",
        ".quicksave-root",
        "master.key",
        ".ssh/id_ed25519",
        "private/slot",
    ] {
        // These paths need not exist: filtering must not attempt any stat/open.
        let mut probe = FixtureProbe::new(&fixture);
        probe.descriptor.path = fixture.data_dir.join(relative);
        let mut request = fixture.request();
        request
            .excluded_paths
            .push(fixture.data_dir.join("private"));
        let mut observer = ObservationEngine::new(
            approve(request),
            Box::new(PollingSource::new(probe)),
            ObservationLimits::default(),
        )
        .unwrap();
        let snapshot = observer.reconcile(100).unwrap();
        assert!(snapshot.files.is_empty());
        assert!(!has_gap(
            &snapshot,
            GapReason::DescriptorChangedDuringObservation
        ));
    }
    let mut request = fixture.request();
    request.roots[1].allowed_files = Some(BTreeSet::from(["other-leaf".into()]));
    let mut observer = ObservationEngine::new(
        approve(request),
        Box::new(PollingSource::new(FixtureProbe::new(&fixture))),
        ObservationLimits::default(),
    )
    .unwrap();
    assert!(observer.reconcile(100).unwrap().files.is_empty());
}

#[test]
fn excluded_native_marker_or_key_identity_cannot_be_observed_through_a_hardlink_alias() {
    let fixture = Fixture::new();
    let alias = fixture.data_dir.join("ordinary-name");
    fs::hard_link(&fixture.file, &alias).unwrap();
    let mut request = fixture.request();
    request
        .excluded_native_files
        .push(NativeFileIdentity::from(&stamp(&fixture.file)));
    let mut probe = FixtureProbe::new(&fixture);
    probe.descriptor.path = alias;
    let mut observer = ObservationEngine::new(
        approve(request),
        Box::new(PollingSource::new(probe)),
        ObservationLimits::default(),
    )
    .unwrap();
    let snapshot = observer.reconcile(10).unwrap();
    assert!(snapshot.files.is_empty());
    assert!(has_gap(
        &snapshot,
        GapReason::DescriptorChangedDuringObservation
    ));
}

#[cfg(unix)]
#[test]
fn symlinked_scoped_leaf_is_rejected_even_with_matching_native_target_id() {
    let fixture = Fixture::new();
    let target = fixture._temp.path().join("outside");
    fs::write(&target, b"outside payload not read").unwrap();
    let alias = fixture.data_dir.join("alias");
    std::os::unix::fs::symlink(&target, &alias).unwrap();
    let mut probe = FixtureProbe::new(&fixture);
    probe.descriptor = DescriptorSample {
        path: alias,
        identity: NativeFileIdentity::from(&stamp(&target)),
    };
    let snapshot = engine(&fixture, probe).reconcile(100).unwrap();
    assert!(snapshot.files.is_empty());
    assert!(has_gap(
        &snapshot,
        GapReason::DescriptorChangedDuringObservation
    ));
}

#[test]
fn revoked_consent_prevents_even_the_injected_process_probe_from_running() {
    let fixture = Fixture::new();
    let valid = Arc::new(AtomicBool::new(true));
    let guard = valid.clone();
    let scope = ObservationScope::approve(
        fixture.request(),
        Arc::new(move |_: &ScopeRequest| Ok(guard.load(Ordering::SeqCst))),
    )
    .unwrap();
    let probe = FixtureProbe::new(&fixture);
    let calls = probe.calls.clone();
    let mut observer = ObservationEngine::new(
        scope,
        Box::new(PollingSource::new(probe)),
        ObservationLimits::default(),
    )
    .unwrap();
    valid.store(false, Ordering::SeqCst);
    let snapshot = observer.reconcile(100).unwrap();
    assert_eq!(calls.load(Ordering::SeqCst), 0);
    assert!(has_gap(&snapshot, GapReason::ConsentRevoked));
    assert_eq!(
        snapshot.applications[0].execution_state,
        ExecutionState::Unknown
    );
}

#[test]
fn invalid_native_consent_is_not_a_json_boolean_grant_or_a_root_probe() {
    let fixture = Fixture::new();
    let mut request = fixture.request();
    request.roots[0].path = fixture._temp.path().join("nonexistent-root");
    let result = ObservationScope::approve(request, Arc::new(|_: &ScopeRequest| Ok(false)));
    assert!(result.err().unwrap().to_string().contains("consent"));
}

#[test]
fn root_hints_cannot_assign_an_owner_or_expand_the_scope() {
    let fixture = Fixture::new();
    let mut probe = FixtureProbe::new(&fixture);
    probe.empty = true;
    let mut observer = engine(&fixture, probe);
    assert!(observer
        .root_hint(RootHint {
            root_id: "not-approved".into()
        })
        .is_err());
    observer
        .root_hint(RootHint {
            root_id: "data".into(),
        })
        .unwrap();
    let snapshot = observer.reconcile(100).unwrap();
    assert!(snapshot.files.is_empty());
    assert!(snapshot.applications[0].root_candidates.is_empty());
    assert!(snapshot.unattributed_root_hints.contains("data"));
    assert!(!snapshot.applications[0]
        .capture_triggers
        .contains(&CaptureTrigger::ApprovedRootHint));
}

#[test]
fn poll_bounds_overflow_restart_and_missed_poll_never_mean_clean() {
    let fixture = Fixture::new();
    let mut probe = FixtureProbe::new(&fixture);
    probe.fd_count = 999;
    let limits = ObservationLimits {
        max_descriptors_per_process: 2,
        max_descriptors_total: 2,
        max_evidence: 2,
        max_poll_interval_ms: 5000,
        ..ObservationLimits::default()
    };
    let mut observer =
        ObservationEngine::new(fixture.scope(), Box::new(PollingSource::new(probe)), limits)
            .unwrap();
    let initial = observer.reconcile(0).unwrap();
    assert!(initial.files.len() <= 2);
    assert!(has_gap(
        &initial,
        GapReason::DescriptorEnumerationIncomplete
    ));
    assert!(has_gap(&initial, GapReason::Restart));
    observer.signal_gap(GapReason::WatcherOverflow);
    let next = observer.reconcile(6000).unwrap();
    assert!(has_gap(&next, GapReason::WatcherOverflow));
    assert!(has_gap(&next, GapReason::MissedPoll));
    assert!(next.uncertainty_epoch > initial.uncertainty_epoch);
    assert_eq!(next.applications[0].completeness, "unknown");
    let healthy = observer.reconcile(6001).unwrap();
    assert!(has_gap(
        &healthy,
        GapReason::PollingCannotObserveShortLivedOpens
    ));
    assert_eq!(healthy.applications[0].completeness, "unknown");
}

#[test]
fn path_only_windows_style_image_cannot_emit_open_file_attribution() {
    let fixture = Fixture::new();
    let mut probe = FixtureProbe::new(&fixture);
    probe.process.image_binding = ImageIdentityBinding::ProcessImagePathAndPinnedStampOnly;
    let snapshot = engine(&fixture, probe).reconcile(100).unwrap();
    assert_eq!(
        snapshot.applications[0].execution_state,
        ExecutionState::Unknown
    );
    let unconfirmed = snapshot
        .applications
        .iter()
        .find(|app| !app.registered_identity)
        .unwrap();
    assert_eq!(unconfirmed.execution_state, ExecutionState::Running);
    assert!(unconfirmed.app_id.starts_with("quicksave.observed:"));
    assert!(snapshot.files.is_empty());
    assert!(has_gap(&snapshot, GapReason::NativeFileSourceUnavailable));
}

struct ScriptedSource {
    batches: VecDeque<EvidenceBatch>,
}
impl EvidenceSource for ScriptedSource {
    fn capabilities(&self) -> SourceCapabilities {
        fixture_capabilities()
    }
    fn poll(
        &mut self,
        _: &ObservationScope,
        now_ms: u64,
        _: &ObservationLimits,
    ) -> Result<EvidenceBatch> {
        let mut batch = self.batches.pop_front().expect("test scripted batch");
        batch.observed_at_ms = now_ms;
        Ok(batch)
    }
}

#[test]
fn run_close_retains_candidates_and_requests_separate_stable_file_capture() {
    let fixture = Fixture::new();
    let scope = fixture.scope();
    let mut source = PollingSource::new(FixtureProbe::new(&fixture));
    let running = source
        .poll(&scope, 10, &ObservationLimits::default())
        .unwrap();
    let closed = EvidenceBatch {
        processes: vec![],
        files: vec![],
        gaps: vec![ObservationGap::global(
            GapReason::PollingCannotObserveShortLivedOpens,
        )],
        process_listing_complete: true,
        observed_at_ms: 11,
    };
    let mut observer = ObservationEngine::new(
        scope,
        Box::new(ScriptedSource {
            batches: VecDeque::from([running, closed]),
        }),
        ObservationLimits::default(),
    )
    .unwrap();
    let first = observer.reconcile(10).unwrap();
    let next = observer.reconcile(11).unwrap();
    let app = &next.applications[0];
    assert_eq!(app.execution_state, ExecutionState::NotObservedRunning);
    assert_eq!(app.ended_sessions.len(), 1);
    assert!(app
        .capture_triggers
        .contains(&CaptureTrigger::ObservedRunClose));
    assert_eq!(app.root_candidates.len(), 1);
    assert!(!app.root_candidates[0].currently_open);
    assert!(app.dirty_generation > first.applications[0].dirty_generation);
    assert_eq!(app.completeness, "unknown");
}

#[test]
fn source_gap_does_not_fabricate_run_close_and_stale_proofs_are_fenced() {
    let fixture = Fixture::new();
    let scope = fixture.scope();
    let mut source = PollingSource::new(FixtureProbe::new(&fixture));
    let running = source
        .poll(&scope, 10, &ObservationLimits::default())
        .unwrap();
    let gap = EvidenceBatch {
        processes: vec![],
        files: vec![],
        gaps: vec![ObservationGap::global(GapReason::SourceUnavailable)],
        process_listing_complete: false,
        observed_at_ms: 11,
    };
    let stale = running.clone();
    let mut observer = ObservationEngine::new(
        scope,
        Box::new(ScriptedSource {
            batches: VecDeque::from([running, gap, stale]),
        }),
        ObservationLimits::default(),
    )
    .unwrap();
    observer.reconcile(10).unwrap();
    let unknown = observer.reconcile(11).unwrap();
    assert_eq!(
        unknown.applications[0].execution_state,
        ExecutionState::Unknown
    );
    assert_eq!(unknown.applications[0].active_sessions.len(), 1);
    assert!(!unknown.applications[0].active_sessions[0].currently_observed);
    assert!(unknown.applications[0].ended_sessions.is_empty());
    assert!(observer.reconcile(12).is_err()); // immutable proof still has t=10
    assert!(has_gap(&observer.snapshot(), GapReason::InvalidEvidence));
}

#[test]
fn unavailable_os_source_is_unknown_not_an_empty_successful_poll() {
    let fixture = Fixture::new();
    let mut observer = ObservationEngine::new(
        fixture.scope(),
        Box::new(native::UnavailableSource::new(
            SourceKind::MacEndpointSecurity,
            CapabilityState::NeedsNativeEntitlement,
            "Synthetic missing entitlement",
        )),
        ObservationLimits::default(),
    )
    .unwrap();
    let snapshot = observer.reconcile(10).unwrap();
    assert!(has_gap(&snapshot, GapReason::SourceUnavailable));
    assert_eq!(
        snapshot.applications[0].execution_state,
        ExecutionState::Unknown
    );
    assert_eq!(
        snapshot.applications[0].open_file_state,
        OpenFileState::Unknown
    );
    assert!(!native::privileged_stream_status(SourceKind::LinuxEbpf).complete_file_stream);
}

#[test]
fn native_permission_errors_update_runtime_capability_not_just_an_empty_index() {
    let fixture = Fixture::new();
    let mut probe = FixtureProbe::new(&fixture);
    probe.error = true;
    let snapshot = engine(&fixture, probe).reconcile(10).unwrap();
    assert_eq!(
        snapshot.source.state,
        CapabilityState::NeedsNativePermission
    );
    assert!(has_gap(&snapshot, GapReason::SourcePermissionDenied));
    assert_eq!(
        snapshot.applications[0].execution_state,
        ExecutionState::Unknown
    );
}

struct BlockingFixtureSource {
    entered: Option<std::sync::mpsc::Sender<()>>,
    release: Arc<Mutex<std::sync::mpsc::Receiver<()>>>,
}
impl EvidenceSource for BlockingFixtureSource {
    fn capabilities(&self) -> SourceCapabilities {
        fixture_capabilities()
    }
    fn poll(
        &mut self,
        _: &ObservationScope,
        now_ms: u64,
        _: &ObservationLimits,
    ) -> Result<EvidenceBatch> {
        if let Some(entered) = self.entered.take() {
            entered.send(()).unwrap();
            self.release.lock().unwrap().recv().unwrap();
        }
        Ok(EvidenceBatch {
            processes: vec![],
            files: vec![],
            gaps: vec![ObservationGap::global(
                GapReason::PollingCannotObserveShortLivedOpens,
            )],
            process_listing_complete: true,
            observed_at_ms: now_ms,
        })
    }
}

#[test]
fn bounded_worker_queue_reports_overflow_and_shutdown_joins_without_native_probes() {
    let fixture = Fixture::new();
    let (entered_tx, entered_rx) = channel();
    let (release_tx, release_rx) = channel();
    let (snap_tx, snap_rx) = sync_channel(4);
    let observer = ObservationEngine::new(
        fixture.scope(),
        Box::new(BlockingFixtureSource {
            entered: Some(entered_tx),
            release: Arc::new(Mutex::new(release_rx)),
        }),
        ObservationLimits::default(),
    )
    .unwrap();
    let worker = ObservationWorker::start(
        observer,
        WorkerConfig {
            queue_capacity: 1,
            poll_interval: Duration::from_millis(10),
            idle_poll_interval: Duration::from_secs(60),
            watch_roots: false,
        },
        Arc::new(move |snapshot| {
            let _ = snap_tx.try_send(snapshot);
            Ok(())
        }),
    )
    .unwrap();
    entered_rx.recv_timeout(Duration::from_secs(5)).unwrap();
    worker.root_hint("data").unwrap();
    assert!(worker.request_reconcile().is_err());
    assert!(worker.watermark().pending_loss);
    release_tx.send(()).unwrap();
    let first = snap_rx.recv_timeout(Duration::from_secs(5)).unwrap();
    assert!(has_gap(&first, GapReason::EventsDuringReconciliation));
    let next = snap_rx.recv_timeout(Duration::from_secs(5)).unwrap();
    assert!(has_gap(&next, GapReason::QueueOverflow));
    worker.shutdown().unwrap();
    assert!(has_gap(
        &worker.snapshot().unwrap(),
        GapReason::WorkerStopped
    ));
    assert!(worker.request_reconcile().is_err());
    assert!(worker.watermark().stopped);
}
