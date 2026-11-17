// SPDX-License-Identifier: GPL-3.0-only
//! Native approvals authorize one exact request, not general filesystem access.

use std::{
    collections::BTreeMap,
    fs::File,
    path::{Path, PathBuf},
    time::{Duration, Instant},
};

use anyhow::{ensure, Context};
use quicksave_platform::{FileStamp, SafeRoot};
use uuid::Uuid;

use crate::message;

pub const MAX_INPUT_BYTES: usize = 4096;
pub const MAX_APPROVALS: usize = 32;
pub const APPROVAL_TTL: Duration = Duration::from_secs(10 * 60);

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Kind {
    Initialize,
    Backup,
    List,
    Restore,
}

impl Kind {
    pub fn parse(value: &str) -> Result<Self, String> {
        validate_text(value, "Operation kind")?;
        match value {
            "initialize" => Ok(Self::Initialize),
            "backup" => Ok(Self::Backup),
            "list" => Ok(Self::List),
            "restore" => Ok(Self::Restore),
            _ => Err("Unknown operation kind; use initialize, backup, list, or restore".into()),
        }
    }

    pub fn name(self) -> &'static str {
        match self {
            Self::Initialize => "initialize",
            Self::Backup => "backup",
            Self::List => "list",
            Self::Restore => "restore",
        }
    }

    fn description(self) -> &'static str {
        match self {
            Self::Initialize => "Create a new encrypted repository and a NEW recovery-key file",
            Self::Backup => "Read the source folder and append an encrypted backup",
            Self::List => "Use the recovery key to decrypt and list snapshot metadata",
            Self::Restore => "Decrypt the selected snapshot into an existing EMPTY destination",
        }
    }
}

/// Construction is lexical only: no metadata, canonicalize, directory opening,
/// key reading, history loading, or engine calls before native confirmation.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Scope {
    pub kind: Kind,
    pub repository: PathBuf,
    pub key_file: PathBuf,
    pub source: Option<PathBuf>,
    pub destination: Option<PathBuf>,
    pub snapshot_id: Option<String>,
}

impl Scope {
    pub fn new(
        kind: Kind,
        repository: &str,
        key_file: &str,
        source: Option<&str>,
        destination: Option<&str>,
        snapshot_id: Option<&str>,
    ) -> Result<Self, String> {
        let valid_fields = match kind {
            Kind::Initialize | Kind::List => {
                source.is_none() && destination.is_none() && snapshot_id.is_none()
            }
            Kind::Backup => source.is_some() && destination.is_none() && snapshot_id.is_none(),
            Kind::Restore => source.is_none() && destination.is_some() && snapshot_id.is_some(),
        };
        if !valid_fields {
            return Err("Operation fields do not match its exact authorization scope".into());
        }
        let snapshot_id = snapshot_id
            .map(|value| {
                validate_uuid(value, "Snapshot ID")?;
                Ok::<_, String>(value.to_owned())
            })
            .transpose()?;
        let key_file = literal_absolute(key_file, "Recovery-key path")?;
        if key_file.file_name().is_none() {
            return Err("Recovery key must name a file, not a filesystem root".into());
        }
        Ok(Self {
            kind,
            repository: literal_absolute(repository, "Repository path")?,
            key_file,
            source: source
                .map(|value| literal_absolute(value, "Source path"))
                .transpose()?,
            destination: destination
                .map(|value| literal_absolute(value, "Destination path"))
                .transpose()?,
            snapshot_id,
        })
    }

    pub fn confirmation_message(&self) -> String {
        let mut text = format!(
            "Approve exactly ONE QuickSave operation:\n\nAction: {}\nRepository: {:?}\nRecovery-key file ({}): {:?}\n",
            self.kind.description(),
            self.repository,
            if self.kind == Kind::Initialize { "NEW" } else { "existing, private" },
            self.key_file,
        );
        if let Some(source) = &self.source {
            text.push_str(&format!("Source folder: {source:?}\n"));
        }
        if let Some(destination) = &self.destination {
            text.push_str(&format!("EMPTY destination folder: {destination:?}\n"));
        }
        if let Some(snapshot) = &self.snapshot_id {
            text.push_str(&format!("Snapshot ID: {snapshot}\n"));
        }
        text.push_str(
            "\nReview every listed path. Cancel if anything is unexpected or not fully visible.\n\n\
             OK permits only this request, once, within 10 minutes. Folder selection alone does not authorize it. \
             Existing files will not be overwritten. Key bytes remain native; they are not shown to the webview.",
        );
        text
    }

    fn execute(&self) -> anyhow::Result<serde_json::Value> {
        match self.kind {
            Kind::Initialize => {
                quicksave_client::initialize_repository(&self.repository, &self.key_file)
            }
            Kind::Backup => quicksave_client::backup_folder(
                &self.repository,
                self.source
                    .as_deref()
                    .context("Missing authorized source")?,
                &self.key_file,
            ),
            Kind::List => quicksave_client::list_snapshots(&self.repository, &self.key_file),
            Kind::Restore => quicksave_client::restore_snapshot(
                &self.repository,
                self.snapshot_id
                    .as_deref()
                    .context("Missing authorized snapshot")?,
                self.destination
                    .as_deref()
                    .context("Missing authorized destination")?,
                &self.key_file,
            ),
        }
    }
}

fn validate_text(value: &str, label: &str) -> Result<(), String> {
    if value.is_empty() || value.len() > MAX_INPUT_BYTES {
        return Err(format!(
            "{label} must be nonempty and at most 4096 UTF-8 bytes"
        ));
    }
    // Prevent line/bidi control characters from disguising a different scope in
    // a native confirmation. Ordinary Unicode names remain supported.
    if value.chars().any(|character| {
        character.is_control()
            || matches!(
                character,
                '\u{061c}' | '\u{200e}' | '\u{200f}' | '\u{2028}'..='\u{202e}'
                    | '\u{2066}'..='\u{2069}'
            )
    }) {
        return Err(format!(
            "{label} contains unsupported display/control characters"
        ));
    }
    Ok(())
}

fn literal_absolute(value: &str, label: &str) -> Result<PathBuf, String> {
    validate_text(value, label)?;
    let path = Path::new(value);
    // In particular, never call current_dir() to resolve an unapproved relative
    // request. Native file pickers already return absolute paths.
    if !path.is_absolute() {
        return Err(format!("{label} must be an absolute native path"));
    }
    let path = quicksave_client::literal_path(path).map_err(message)?;
    if path.as_os_str().len() > MAX_INPUT_BYTES {
        return Err(format!(
            "{label} exceeds the 4096-byte normalized-path limit"
        ));
    }
    Ok(path)
}

pub fn validate_uuid(value: &str, label: &str) -> Result<Uuid, String> {
    validate_text(value, label)?;
    let id = Uuid::parse_str(value).map_err(|_| format!("{label} must be a UUID"))?;
    if id.is_nil() || id.hyphenated().to_string() != value {
        return Err(format!(
            "{label} must be a nonzero, lowercase hyphenated UUID"
        ));
    }
    Ok(id)
}

struct RootProof {
    path: PathBuf,
    root: SafeRoot,
}

impl RootProof {
    fn pin(path: &Path) -> anyhow::Result<Self> {
        Ok(Self {
            path: path.to_owned(),
            root: SafeRoot::open(path)?,
        })
    }

    fn verify(&self) -> anyhow::Result<()> {
        let current = SafeRoot::open(&self.path)?;
        ensure!(
            self.root.same_root(&current)?,
            "Approved directory changed; request a new native approval"
        );
        Ok(())
    }
}

struct KeyProof {
    parent: RootProof,
    name: String,
    // Keep the old file alive as well as its stamp, preventing inode reuse.
    existing: Option<(File, FileStamp)>,
}

impl KeyProof {
    fn pin(scope: &Scope) -> anyhow::Result<Self> {
        let parent = RootProof::pin(
            scope
                .key_file
                .parent()
                .context("Recovery key needs an existing parent directory")?,
        )?;
        let name = scope
            .key_file
            .file_name()
            .and_then(|name| name.to_str())
            .context("Recovery key needs a Unicode file name")?
            .to_owned();
        let existing = if scope.kind == Kind::Initialize {
            // Absence cannot be pinned. The client's native write_new remains
            // responsible for exclusive publication and never overwrites.
            None
        } else {
            let (file, stamp) = parent.root.read_file(&name)?;
            ensure!(stamp.size == 32, "Recovery key must be exactly 32 bytes");
            quicksave_platform::verify_private_file(&file)?;
            parent.root.verify_file(&name, &stamp)?;
            Some((file, stamp))
        };
        Ok(Self {
            parent,
            name,
            existing,
        })
    }

    fn verify(&self) -> anyhow::Result<()> {
        self.parent.verify()?;
        if let Some((original, before)) = &self.existing {
            quicksave_platform::verify_private_file(original)?;
            let (current, after) = self.parent.root.read_file(&self.name)?;
            ensure!(
                &after == before,
                "Approved recovery key changed; request a new native approval"
            );
            quicksave_platform::verify_private_file(&current)?;
            self.parent.root.verify_file(&self.name, before)?;
        }
        Ok(())
    }
}

/// Never serialized or supplied by the webview. All handles remain alive until
/// the authorized engine call returns. This is not a same-UID namespace lock.
pub struct PathProofs {
    repository: RootProof,
    source: Option<RootProof>,
    destination: Option<RootProof>,
    key: KeyProof,
}

impl PathProofs {
    /// Must only be called after a successful native confirmation.
    pub fn pin(scope: &Scope) -> anyhow::Result<Self> {
        Ok(Self {
            repository: RootProof::pin(&scope.repository)?,
            source: scope.source.as_deref().map(RootProof::pin).transpose()?,
            destination: scope
                .destination
                .as_deref()
                .map(RootProof::pin)
                .transpose()?,
            key: KeyProof::pin(scope)?,
        })
    }

    fn verify(&self) -> anyhow::Result<()> {
        self.repository.verify()?;
        if let Some(source) = &self.source {
            source.verify()?;
        }
        if let Some(destination) = &self.destination {
            destination.verify()?;
        }
        self.key.verify()
    }
}

pub struct Approval<T> {
    scope: Scope,
    issued_at: Instant,
    proof: T,
}

impl Approval<PathProofs> {
    pub fn verify(&self) -> anyhow::Result<()> {
        ensure!(
            !self.expired(Instant::now()),
            "Native approval expired; request a new approval"
        );
        self.proof.verify()
    }

    pub fn execute(&self) -> anyhow::Result<serde_json::Value> {
        // Recheck immediately before the native client call, not just before
        // potentially slow history initialization/admission.
        self.verify()?;
        self.scope.execute()
    }
}

impl<T> Approval<T> {
    fn expired(&self, now: Instant) -> bool {
        now.saturating_duration_since(self.issued_at) >= APPROVAL_TTL
    }
}

/// The generic payload permits pure policy tests without fabricating native
/// filesystem success. Production always stores real PathProofs.
pub struct ApprovalStore<T> {
    grants: BTreeMap<Uuid, Approval<T>>,
}

impl<T> Default for ApprovalStore<T> {
    fn default() -> Self {
        Self {
            grants: BTreeMap::new(),
        }
    }
}

impl<T> ApprovalStore<T> {
    fn prune(&mut self, now: Instant) {
        self.grants.retain(|_, grant| !grant.expired(now));
    }

    pub fn check_capacity(&mut self, now: Instant) -> Result<(), String> {
        self.prune(now);
        if self.grants.len() >= MAX_APPROVALS {
            return Err(
                "Too many unused approvals; use one or wait for its 10-minute expiry".into(),
            );
        }
        Ok(())
    }

    pub fn insert(&mut self, scope: Scope, proof: T, issued_at: Instant) -> Result<String, String> {
        let now = Instant::now();
        self.check_capacity(now)?;
        let grant = Approval {
            scope,
            issued_at,
            proof,
        };
        if grant.expired(now) {
            return Err("Native approval expired before path validation finished".into());
        }
        let id = loop {
            let id = Uuid::new_v4();
            if !self.grants.contains_key(&id) {
                break id;
            }
        };
        self.grants.insert(id, grant);
        Ok(id.to_string())
    }

    pub fn consume(
        &mut self,
        id: Uuid,
        scope: &Scope,
        now: Instant,
    ) -> Result<Approval<T>, String> {
        self.prune(now);
        // A mismatched attempt also spends the token. Never let a caller probe
        // or reuse a grant for another kind/path/snapshot.
        let grant = self
            .grants
            .remove(&id)
            .ok_or_else(|| "Unknown, expired, or already used native approval".to_owned())?;
        if &grant.scope != scope {
            return Err(
                "Native approval does not match this exact operation; request a new one".into(),
            );
        }
        Ok(grant)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn path(name: &str) -> String {
        #[cfg(windows)]
        {
            format!(r"C:\quicksave-approval-fixture\{name}")
        }
        #[cfg(not(windows))]
        {
            format!("/quicksave-approval-fixture/{name}")
        }
    }

    fn scope(kind: Kind) -> Scope {
        Scope::new(
            kind,
            &path("repository"),
            &path("key"),
            (kind == Kind::Backup).then(|| path("source")).as_deref(),
            (kind == Kind::Restore)
                .then(|| path("destination"))
                .as_deref(),
            (kind == Kind::Restore).then_some("61f64021-18e7-4137-8233-b2accab6573f"),
        )
        .unwrap()
    }

    #[test]
    fn rejects_relative_traversal_overlong_and_deceptive_inputs_without_io() {
        for bad in [
            String::new(),
            "relative/source".into(),
            format!("{}/../escape", path("source")),
            path("line\nbreak"),
            path("hidden\u{202e}name"),
            path(&"x".repeat(MAX_INPUT_BYTES)),
        ] {
            assert!(Scope::new(Kind::List, &bad, &path("key"), None, None, None).is_err());
        }
        assert!(Kind::parse("backup_folder").is_err());
        assert!(validate_uuid("not-an-id", "ID").is_err());
        assert!(validate_uuid("61F64021-18E7-4137-8233-B2ACCAB6573F", "ID").is_err());
        assert!(validate_uuid("61f6402118e741378233b2accab6573f", "ID").is_err());
        assert!(validate_uuid("00000000-0000-0000-0000-000000000000", "ID").is_err());
    }

    #[test]
    fn operation_fields_are_not_interchangeable() {
        assert!(Scope::new(
            Kind::Initialize,
            &path("repository"),
            &path("key"),
            Some(&path("source")),
            None,
            None,
        )
        .is_err());
        assert!(Scope::new(
            Kind::Backup,
            &path("repository"),
            &path("key"),
            None,
            None,
            None,
        )
        .is_err());
        assert!(Scope::new(
            Kind::Restore,
            &path("repository"),
            &path("key"),
            Some(&path("source")),
            Some(&path("destination")),
            Some("61f64021-18e7-4137-8233-b2accab6573f"),
        )
        .is_err());
        for kind in [Kind::Initialize, Kind::Backup, Kind::List, Kind::Restore] {
            assert_eq!(scope(kind).kind, kind);
        }
    }

    #[test]
    fn confirmation_names_the_exact_action_and_every_path_and_snapshot() {
        for kind in [Kind::Initialize, Kind::Backup, Kind::List, Kind::Restore] {
            let scope = scope(kind);
            let text = scope.confirmation_message();
            assert!(text.contains(kind.description()));
            for path in [&scope.repository, &scope.key_file]
                .into_iter()
                .chain(scope.source.iter())
                .chain(scope.destination.iter())
            {
                assert!(text.contains(&format!("{path:?}")));
            }
            if let Some(id) = scope.snapshot_id {
                assert!(text.contains(&id));
            }
        }
    }

    #[test]
    fn approvals_are_opaque_one_use_and_expire_at_ten_minutes() {
        let scope = scope(Kind::List);
        let now = Instant::now();
        let mut store = ApprovalStore::default();
        let id = store.insert(scope.clone(), (), now).unwrap();
        let id = validate_uuid(&id, "Approval ID").unwrap();
        assert!(store.consume(id, &scope, now).is_ok());
        assert!(store.consume(id, &scope, now).is_err());
        let id = store.insert(scope.clone(), (), now).unwrap();
        let id = validate_uuid(&id, "Approval ID").unwrap();
        assert!(store.consume(id, &scope, now + APPROVAL_TTL).is_err());
    }

    #[test]
    fn mismatching_any_scope_field_spends_the_token() {
        let original = scope(Kind::Restore);
        let mut alternatives = Vec::new();
        let mut changed = original.clone();
        changed.kind = Kind::List;
        alternatives.push(changed);
        let mut changed = original.clone();
        changed.repository = PathBuf::from(path("other-repository"));
        alternatives.push(changed);
        let mut changed = original.clone();
        changed.key_file = PathBuf::from(path("other-key"));
        alternatives.push(changed);
        let mut changed = original.clone();
        changed.destination = Some(PathBuf::from(path("other-destination")));
        alternatives.push(changed);
        let mut changed = original.clone();
        changed.source = Some(PathBuf::from(path("source")));
        alternatives.push(changed);
        let mut changed = original.clone();
        changed.snapshot_id = Some("72f64021-18e7-4137-8233-b2accab6573f".into());
        alternatives.push(changed);
        for changed in alternatives {
            let now = Instant::now();
            let mut store = ApprovalStore::default();
            let id = store.insert(original.clone(), (), now).unwrap();
            let id = validate_uuid(&id, "Approval ID").unwrap();
            assert!(store.consume(id, &changed, now).is_err());
            assert!(store.consume(id, &original, now).is_err());
        }
    }

    #[test]
    fn capacity_is_bounded_and_expired_proofs_are_retired_without_replay() {
        let scope = scope(Kind::List);
        let now = Instant::now();
        let mut store = ApprovalStore::default();
        for _ in 0..MAX_APPROVALS {
            store.insert(scope.clone(), (), now).unwrap();
        }
        assert!(store.insert(scope, (), now).is_err());
        assert_eq!(store.grants.len(), MAX_APPROVALS);
        store.check_capacity(now + APPROVAL_TTL).unwrap();
        assert!(store.grants.is_empty());
    }

    #[cfg(unix)]
    fn native_fixture() -> (tempfile::TempDir, Scope) {
        use std::{fs, os::unix::fs::PermissionsExt};
        let parent = std::env::temp_dir().canonicalize().unwrap();
        let temporary = tempfile::Builder::new()
            .prefix("quicksave-proof-")
            .tempdir_in(parent)
            .unwrap();
        let repository = temporary.path().join("repository");
        let source = temporary.path().join("source");
        let key = temporary.path().join("recovery.key");
        fs::create_dir(&repository).unwrap();
        fs::create_dir(&source).unwrap();
        fs::write(&key, [0x44; 32]).unwrap();
        fs::set_permissions(&key, fs::Permissions::from_mode(0o600)).unwrap();
        let scope = Scope::new(
            Kind::Backup,
            repository.to_str().unwrap(),
            key.to_str().unwrap(),
            Some(source.to_str().unwrap()),
            None,
            None,
        )
        .unwrap();
        (temporary, scope)
    }

    #[cfg(unix)]
    #[test]
    fn native_proofs_reject_replaced_repository_and_source_directories() {
        for repository in [true, false] {
            let (temporary, scope) = native_fixture();
            // This tests proof binding directly, not an automated native OK.
            let proof = PathProofs::pin(&scope).unwrap();
            assert!(proof.verify().is_ok());
            let original = if repository {
                &scope.repository
            } else {
                scope.source.as_ref().unwrap()
            };
            std::fs::rename(original, temporary.path().join("kept-original")).unwrap();
            std::fs::create_dir(original).unwrap();
            assert!(proof.verify().is_err());
        }
    }

    #[cfg(unix)]
    #[test]
    fn native_key_proof_rejects_same_length_key_replacement() {
        use std::os::unix::fs::PermissionsExt;
        let (temporary, scope) = native_fixture();
        let proof = PathProofs::pin(&scope).unwrap();
        std::fs::rename(&scope.key_file, temporary.path().join("kept-original.key")).unwrap();
        std::fs::write(&scope.key_file, [0x44; 32]).unwrap();
        std::fs::set_permissions(&scope.key_file, std::fs::Permissions::from_mode(0o600)).unwrap();
        assert!(proof.verify().is_err());
    }

    #[cfg(unix)]
    #[test]
    fn native_key_proof_rejects_privacy_changes_before_execution() {
        use std::os::unix::fs::PermissionsExt;
        let (_temporary, scope) = native_fixture();
        let proof = PathProofs::pin(&scope).unwrap();
        std::fs::set_permissions(&scope.key_file, std::fs::Permissions::from_mode(0o644)).unwrap();
        assert!(proof.verify().is_err());
    }
}
