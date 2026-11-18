// SPDX-License-Identifier: GPL-3.0-only
//! Packaged Windows executable pin. Never searches PATH, downloads tools, starts
//! a shell or accepts an environment-provided executable/hash.
use anyhow::{ensure, Context, Result};
use quicksave_platform::{FileStamp, SafeRoot};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::{
    fs::File,
    io::Read,
    os::windows::fs::OpenOptionsExt,
    path::{Path, PathBuf},
    process::Stdio,
    time::Duration,
};
use tokio::{io::AsyncReadExt, process::Command};
use windows_sys::Win32::Storage::FileSystem::{FILE_FLAG_OPEN_REPARSE_POINT, FILE_SHARE_READ};
const MAX_RCLONE_BYTES: u64 = 128 * 1024 * 1024;

/// Native-private executable handle/hash; deliberately no Debug or serde.
pub struct SourceRuntime {
    executable: PathBuf,
    held: File,
    root: SafeRoot,
    stamp: FileStamp,
    version: String,
    digest: [u8; 32],
}

impl SourceRuntime {
    pub async fn discover() -> Result<Self> {
        let app =
            std::env::current_exe().context("cannot locate native application resource root")?;
        let resource = app
            .parent()
            .context("native application resource parent missing")?
            .join("resources")
            .join("rclone.exe");
        let digest = option_env!("QUICKSAVE_WINDOWS_RCLONE_SHA256")
            .context("Windows rclone package lacks its compiled SHA-256 pin; package resources/rclone.exe and compile its audited digest")?;
        ensure!(
            digest.len() == 64 && digest.bytes().all(|b| b.is_ascii_hexdigit()),
            "compiled Windows rclone SHA-256 pin is malformed"
        );
        let mut expected = [0; 32];
        for (index, byte) in expected.iter_mut().enumerate() {
            *byte = u8::from_str_radix(&digest[index * 2..index * 2 + 2], 16)?;
        }
        Self::from_resource(&resource, expected).await
    }

    /// Trusted native/package configuration only, never an IPC or environment
    /// override. The trusted digest must be supplied by the signed package.
    pub async fn from_resource(executable: &Path, expected_sha256: [u8; 32]) -> Result<Self> {
        ensure!(
            executable.is_absolute(),
            "native rclone resource must be absolute"
        );
        let parent = executable
            .parent()
            .context("rclone resource parent missing")?;
        let leaf = executable
            .file_name()
            .and_then(|s| s.to_str())
            .context("rclone resource must have a Unicode filename")?;
        let root = SafeRoot::open(parent)?;
        let (_, stamp) = root.read_file(leaf)?;
        ensure!(
            stamp.size > 0 && stamp.size <= MAX_RCLONE_BYTES,
            "rclone resource size is invalid"
        );
        // Unlike source reads, executable admission also denies concurrent write
        // access. Existing conflicting writers cause Windows sharing admission to
        // fail; the held descriptor remains until all operations have joined.
        let held = File::options()
            .read(true)
            .share_mode(FILE_SHARE_READ)
            .custom_flags(FILE_FLAG_OPEN_REPARSE_POINT)
            .open(executable)?;
        let (digest, blake3) = hash(&held)?;
        ensure!(
            digest == expected_sha256,
            "packaged rclone SHA-256 verification failed"
        );
        root.verify_file(leaf, &stamp)?;
        // BLAKE3 is derived only from bytes authenticated by the trusted package
        // SHA-256 above. The source pin independently validates this exact file's
        // full native identity and compatible PE architecture before execution.
        noland_storage::pin_native_rclone_resource(executable, blake3)
            .map_err(super::source_error)?;
        let version = parse_version(&output(executable, &["version"], 64 * 1024).await?)?;
        let flags = output(executable, &["help", "flags"], 2 * 1024 * 1024).await?;
        for flag in [
            "--immutable",
            "--checksum",
            "--checksum-choice",
            "--files-from-raw",
            "--no-traverse",
            "--error-on-no-transfer",
            "--use-json-log",
            "--multi-thread-streams",
            "--low-level-retries",
            "--ask-password",
        ] {
            ensure!(
                flags.contains(flag),
                "packaged rclone lacks required native flag {flag}"
            );
        }
        let listing = output(executable, &["lsjson", "--help"], 512 * 1024).await?;
        ensure!(
            ["--stat", "--recursive", "--no-mimetype", "--no-modtime"]
                .iter()
                .all(|flag| listing.contains(flag)),
            "packaged rclone lacks required bounded listing/stat flags"
        );
        root.verify_file(leaf, &stamp)?;
        ensure!(
            hash(&held)?.0 == digest,
            "packaged rclone changed during preflight"
        );
        noland_storage::install_native_rclone(executable).map_err(super::source_error)?;
        Ok(Self {
            executable: executable.to_owned(),
            held,
            root,
            stamp,
            version,
            digest,
        })
    }

    pub(super) fn check(&self) -> Result<()> {
        let leaf = self
            .executable
            .file_name()
            .and_then(|name| name.to_str())
            .context("rclone resource name changed")?;
        self.root.verify_file(leaf, &self.stamp)?;
        ensure!(
            self.held.metadata()?.len() == self.stamp.size,
            "rclone resource changed"
        );
        let _ = self.digest; // Original SHA-256 pin plus denied write sharing remain held.
        Ok(())
    }

    pub fn sanitized(&self) -> Value {
        json!({
            "available":true,"version":self.version,"minimumVersion":"1.76.0",
            "engineApiVersion":22,"format":"No Land shared storage",
            "captureConsistency":"validated_stable_files","automaticRetirement":false,
            "nativeRestoreAutoRollback":false,
            "frozenRestoreControls":"implemented_pending_native_validation",
            "nativeFullScopeCapture":"implemented_pending_native_service_fixture",
            "materializedSourceGraph":"not_integrated_on_windows",
            "nativeAcceptance":{"windows":false,"linux":false,"packaging":false},
            "filesystemRequirement":"local NTFS/ReFS; protected current-user DACL; actual native flush privileges",
        })
    }
}

fn hash(file: &File) -> Result<([u8; 32], [u8; 32])> {
    use std::io::{Seek, SeekFrom};
    let mut file = file.try_clone()?;
    file.seek(SeekFrom::Start(0))?;
    let mut digest = Sha256::new();
    let mut blake3 = blake3::Hasher::new();
    let mut buffer = [0; 64 * 1024];
    let mut total = 0u64;
    loop {
        let count = file.read(&mut buffer)?;
        if count == 0 {
            break;
        }
        total += count as u64;
        ensure!(
            total <= MAX_RCLONE_BYTES,
            "rclone resource exceeds its bound"
        );
        digest.update(&buffer[..count]);
        blake3.update(&buffer[..count]);
    }
    Ok((digest.finalize().into(), *blake3.finalize().as_bytes()))
}

fn parse_version(text: &str) -> Result<String> {
    let raw = text
        .lines()
        .next()
        .and_then(|line| line.strip_prefix("rclone v"))
        .context("packaged rclone returned an unrecognized version")?;
    let parts = raw
        .split(['.', '-', '+'])
        .take(3)
        .map(str::parse::<u64>)
        .collect::<std::result::Result<Vec<_>, _>>()?;
    ensure!(
        parts.len() == 3 && (parts[0], parts[1], parts[2]) >= (1, 76, 0),
        "packaged rclone >=1.76.0 is required"
    );
    Ok(raw.chars().take(64).collect())
}

async fn output(executable: &Path, args: &[&str], limit: usize) -> Result<String> {
    use std::os::windows::process::CommandExt;
    let mut command = Command::new(executable);
    command
        .args(args)
        .current_dir(
            executable
                .parent()
                .context("native helper resource parent is missing")?,
        )
        .env_clear()
        .stdin(Stdio::null())
        .stderr(Stdio::null())
        .stdout(Stdio::piped())
        .kill_on_drop(true);
    command.as_std_mut().creation_flags(0x0800_0000); // CREATE_NO_WINDOW
    let mut child = command
        .spawn()
        .context("could not execute packaged rclone")?;
    let stdout = child
        .stdout
        .take()
        .context("rclone preflight stdout missing")?;
    let mut bytes = Vec::new();
    let result = tokio::time::timeout(Duration::from_secs(15), async {
        stdout
            .take((limit + 1) as u64)
            .read_to_end(&mut bytes)
            .await?;
        ensure!(
            bytes.len() <= limit,
            "rclone preflight output exceeds its bound"
        );
        ensure!(
            child.wait().await?.success(),
            "rclone preflight failed; private output withheld"
        );
        Ok::<_, anyhow::Error>(())
    })
    .await;
    if !matches!(result, Ok(Ok(()))) {
        let _ = child.kill().await;
        let _ = child.wait().await;
    }
    result.context("rclone preflight timed out")??;
    String::from_utf8(bytes).context("rclone preflight returned invalid text")
}
