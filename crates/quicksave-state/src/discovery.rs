// SPDX-License-Identifier: GPL-3.0-only
//! Bounded metadata-only discovery. Never load/migrate No Land state on discovery.

use crate::{validate_id, FileStamp, WorkspaceStore};
use anyhow::{ensure, Context, Result};
use quicksave_platform::{RootIdentity, SafeRoot};
use serde_json::{json, Value};
use std::{
    collections::BTreeSet,
    fs::File,
    path::{Component, Path, PathBuf},
    sync::Arc,
    time::{Duration, Instant},
};

pub const NOLAND_APP_IDENTIFIER: &str = "com.noland.connect";
const MAX_BASES: usize = 4;
const MAX_CANDIDATES: usize = 32;
const VALID_FOR: Duration = Duration::from_secs(10 * 60);

/// Native-only injection, not a deserializable IPC input. Each path is an
/// OS-selected application-data BASE, not an arbitrary state file or search root.
pub struct KnownDataDirs {
    pub bases: Vec<PathBuf>,
}

impl KnownDataDirs {
    /// Resolves paths only. Tests must inject temporary bases instead.
    pub fn native() -> Result<Self> {
        #[cfg(test)]
        anyhow::bail!("tests must inject KnownDataDirs; native user data is forbidden");
        #[cfg(not(test))]
        {
            let paths = quicksave_platform::app_directories()?;
            let mut bases = Vec::new();
            // Tauri app_data_dir uses data_dir. Include Windows' local and
            // roaming KnownFolders, but not config/cache/history trees elsewhere.
            let keys: &[&str] = if cfg!(windows) {
                &["data", "config"]
            } else {
                &["data"]
            };
            for key in keys {
                let path = PathBuf::from(
                    paths[*key]
                        .as_str()
                        .context("native data directory unavailable")?,
                );
                ensure!(
                    path.file_name().is_some_and(|name| name == "QuickSave"),
                    "native data-directory layout is unrecognized"
                );
                let base = path
                    .parent()
                    .context("native data directory has no base")?
                    .to_path_buf();
                if !bases.contains(&base) {
                    bases.push(base);
                }
            }
            Ok(Self { bases })
        }
    }
}

/// Held exclusively in Rust. No Debug/Serialize or caller-provided path proof.
pub struct NativeNolandSourceProof {
    pub(crate) path: PathBuf,
    root: SafeRoot,
    file: File,
    stamp: FileStamp,
    parent_identity: RootIdentity,
    created: Instant,
}

impl NativeNolandSourceProof {
    pub fn state_file(&self) -> &Path {
        &self.path
    }

    /// Native gateway ticket payload ONLY. Do not include in a webview DTO.
    pub fn approved_path_handoff(&self) -> Result<Value> {
        self.verify()?;
        Ok(json!({
            "path":self.path,"kind":"file",
            "identity":{"device":self.stamp.device,"fileId":self.stamp.file_id},
            "stamp":self.stamp,"parentIdentity":self.parent_identity,
        }))
    }

    fn verify(&self) -> Result<()> {
        ensure!(
            self.created.elapsed() < VALID_FOR,
            "No Land source discovery expired; discover again"
        );
        ensure!(
            self.root.identity()? == self.parent_identity,
            "No Land source parent changed"
        );
        verify_source_owner(&self.file)?;
        let (_, current) = self.root.read_file("state.json")?;
        ensure!(
            current == self.stamp,
            "No Land source identity or contents changed; discover again"
        );
        Ok(())
    }
}

fn verify_source_owner(file: &File) -> Result<()> {
    let metadata = file.metadata()?;
    ensure!(
        metadata.is_file() && metadata.len() > 0 && metadata.len() <= 8 * 1024 * 1024,
        "No Land source is not a bounded regular state file"
    );
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        // No Land's original File::create writer does not require 0600. Do not
        // chmod source data. Reject foreign ownership, writable-by-others files
        // and hard links; the source is not a recovery/master-key file.
        ensure!(
            metadata.uid() == unsafe { libc::geteuid() }
                && metadata.mode() & 0o022 == 0
                && metadata.nlink() == 1,
            "No Land source ownership or write permissions are unsafe"
        );
    }
    #[cfg(windows)]
    quicksave_platform::verify_private_file(file)?;
    Ok(())
}

fn validate_base(path: &Path) -> Result<()> {
    let text = path
        .to_str()
        .context("native application-data base is not UTF-8")?;
    ensure!(
        path.is_absolute()
            && text.len() <= quicksave_platform::MAX_PATH_BYTES
            && !text.chars().any(char::is_control)
            && !path
                .components()
                .any(|part| matches!(part, Component::CurDir | Component::ParentDir)),
        "native application-data base is invalid"
    );
    Ok(())
}

impl WorkspaceStore {
    /// Call only after the gateway's initial native consent to locate No Land.
    /// No JSON contents, source credentials, provider account or vault is read.
    pub fn discover_noland_sources(&self) -> Result<Value> {
        ensure!(self.inner.allow_native_discovery,
            "Injected-vault workspaces must supply explicit KnownDataDirs; native user-data discovery is disabled");
        self.discover_noland_sources_in(&KnownDataDirs::native()?)
    }

    pub fn discover_noland_sources_in(&self, dirs: &KnownDataDirs) -> Result<Value> {
        ensure!(
            !dirs.bases.is_empty() && dirs.bases.len() <= MAX_BASES,
            "known application-data directory set is outside its bound"
        );
        let mut found = Vec::new();
        let mut rejected = 0usize;
        let mut identities = BTreeSet::new();
        for base in &dirs.bases {
            validate_base(base)?;
            let parent = base.join(NOLAND_APP_IDENTIFIER);
            let path = parent.join("state.json");
            // This single exact-name metadata query never walks the home/disk,
            // opens a different application state file, or follows final links.
            match std::fs::symlink_metadata(&path) {
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => continue,
                Err(_) => {
                    rejected += 1;
                    continue;
                }
                Ok(metadata) if !metadata.is_file() || metadata.file_type().is_symlink() => {
                    rejected += 1;
                    continue;
                }
                Ok(_) => {}
            }
            let pinned = (|| -> Result<NativeNolandSourceProof> {
                let root = SafeRoot::open(&parent)?;
                let parent_identity = root.identity()?;
                let (file, stamp) = root.read_file("state.json")?;
                verify_source_owner(&file)?;
                root.verify_file("state.json", &stamp)?;
                Ok(NativeNolandSourceProof {
                    path,
                    root,
                    file,
                    stamp,
                    parent_identity,
                    created: Instant::now(),
                })
            })();
            match pinned {
                Ok(proof) if identities.insert((proof.stamp.device, proof.stamp.file_id)) => {
                    found.push(Arc::new(proof));
                }
                Ok(_) => {}
                Err(_) => rejected += 1,
            }
        }
        let mut registry = self
            .inner
            .noland_sources
            .lock()
            .map_err(|_| anyhow::anyhow!("native source registry is unavailable"))?;
        registry.retain(|_, proof| proof.created.elapsed() < VALID_FOR);
        ensure!(registry.len() + found.len() <= MAX_CANDIDATES,
            "native source discovery is at capacity; finish or wait for earlier selections to expire");
        let mut candidates = Vec::new();
        for (index, proof) in found.into_iter().enumerate() {
            let id = uuid::Uuid::new_v4().to_string();
            let location = proof
                .path
                .parent()
                .and_then(Path::parent)
                .and_then(Path::file_name)
                .and_then(|name| name.to_str())
                .unwrap_or("application-data");
            candidates.push(json!({
                "sourceId":id,"name":"No Land",
                "pathSafeSummary":format!("…/{location}/{NOLAND_APP_IDENTIFIER}/state.json"),
                "locationIndex":index + 1,
                "credentialReads":false,"contentsRead":false,
            }));
            registry.insert(id, proof);
        }
        let selected = (candidates.len() == 1).then(|| candidates[0]["sourceId"].clone());
        Ok(json!({
            "candidates":candidates,"selectedSourceId":selected,
            "requiresChoice":candidates.len() > 1,"hasData":!candidates.is_empty(),
            "rejectedCandidates":rejected,"credentialReads":false,
            "manualFallback":"advanced_only",
            "error":if candidates.is_empty() {
                Some("No eligible No Land state.json was found in the known application-data locations.")
            } else { None },
        }))
    }

    /// Resolve an opaque ID into pinned proof for an exact native confirmation.
    /// A webview-supplied path is never a substitute for this registration.
    pub fn noland_source_proof(&self, source_id: &str) -> Result<Arc<NativeNolandSourceProof>> {
        validate_id(source_id)?;
        let proof = self
            .inner
            .noland_sources
            .lock()
            .map_err(|_| anyhow::anyhow!("native source registry is unavailable"))?
            .get(source_id)
            .cloned()
            .context("No Land source is not registered; discover again")?;
        proof.verify()?;
        Ok(proof)
    }

    /// ServiceStore trait-forwarding convenience, NATIVE ONLY. The gateway must
    /// hold this exact proof in its one-use confirmation ticket, never return
    /// this object as the discovery UI DTO or accept it from JavaScript.
    pub fn noland_import_source_scope(&self, source_id: &str) -> Result<Value> {
        let proof = self.noland_source_proof(source_id)?;
        Ok(json!({
            "sourceId":source_id, "sourceName":"No Land",
            "stateFile":proof.state_file(),
            "_approvedPaths":[proof.approved_path_handoff()?],
            "readOnlySource":true,"quickSaveVaultOnly":true,
        }))
    }
}
