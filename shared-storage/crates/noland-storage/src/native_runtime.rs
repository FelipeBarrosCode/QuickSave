// SPDX-License-Identifier: GPL-3.0-only
//! Process-local installed-tool binding for native hosts. The ordinary upstream
//! Unix legacy selection is unchanged until a native caller installs this pin.
//! Windows always requires a trusted digest-pinned native resource.
use std::fs::File;
use std::io::{Read, Seek, SeekFrom};
use std::path::{Path, PathBuf};
use std::sync::{Mutex, OnceLock};

use noland_state_core::{Result, StateError};
use tokio::process::Command;

struct Executable {
    path: PathBuf,
    file: File,
    identity: crate::native_fs::FileState,
    _source: noland_snapshot::SourcePath,
    local_test_sandbox: Option<PathBuf>,
    #[cfg(windows)]
    system_root: PathBuf,
}

static NATIVE: OnceLock<Executable> = OnceLock::new();
static RESOURCES: OnceLock<Mutex<Vec<Resource>>> = OnceLock::new();

struct Resource {
    path: PathBuf,
    digest: [u8; 32],
    _file: File,
    identity: crate::native_fs::FileState,
    _source: noland_snapshot::SourcePath,
}

/// Native build/package/KnownFolder candidate only. The expected digest MUST
/// come from trusted build metadata, not JS/env or an adjacent writable file.
/// Pins the verified file across the parent's version/flag preflight and install.
/// Windows has no PATH, guessed executable, or unverified-install fallback.
pub fn pin_native_rclone_resource(path: &Path, expected_blake3: [u8; 32]) -> Result<()> {
    if !path.is_absolute() {
        return Err(StateError::UnsafePath(
            "native helper resource must be absolute".into(),
        ));
    }
    let source = noland_snapshot::SourcePath::new(path)?;
    let mut file = source.open_regular()?;
    verify_executable(&mut file)?;
    let identity = crate::native_fs::FileState::read(&file)?;
    if identity.len() > 128 * 1024 * 1024 {
        return Err(StateError::Invalid(
            "native helper resource exceeds 128 MiB".into(),
        ));
    }
    file.seek(SeekFrom::Start(0))?;
    let mut hash = blake3::Hasher::new();
    let mut bytes = [0u8; 64 * 1024];
    let mut total = 0usize;
    loop {
        let count = file.read(&mut bytes)?;
        if count == 0 {
            break;
        }
        total += count;
        if total > 128 * 1024 * 1024 {
            return Err(StateError::Invalid(
                "native helper resource exceeds 128 MiB".into(),
            ));
        }
        hash.update(&bytes[..count]);
    }
    if *hash.finalize().as_bytes() != expected_blake3
        || !identity.same_file(&file)?
        || !identity.same_file(&source.open_regular()?)?
    {
        return Err(StateError::Conflict(
            "native helper resource failed trusted digest/identity verification".into(),
        ));
    }
    let mut resources = RESOURCES.get_or_init(Mutex::default).lock().map_err(|_| {
        StateError::Conflict("native helper resource registry is unavailable".into())
    })?;
    if let Some(prior) = resources.iter().find(|resource| resource.path == path) {
        if prior.digest != expected_blake3 || !prior.identity.same_file(&file)? {
            return Err(StateError::Conflict(
                "native helper resource changed during preflight".into(),
            ));
        }
        return Ok(());
    }
    if resources.len() >= 8 {
        return Err(StateError::Conflict(
            "native helper resource registry exceeds eight pins".into(),
        ));
    }
    resources.push(Resource {
        path: path.to_path_buf(),
        digest: expected_blake3,
        _file: file,
        identity,
        _source: source,
    });
    Ok(())
}

fn verify_executable(file: &mut File) -> Result<()> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        let metadata = file.metadata()?;
        if metadata.mode() & 0o022 != 0
            || metadata.mode() & 0o111 == 0
            || !(metadata.uid() == 0 || metadata.uid() == unsafe { libc::geteuid() })
        {
            return Err(StateError::UnsafePath(
                "installed rclone is not a trusted executable".into(),
            ));
        }
    }
    #[cfg(windows)]
    {
        let native = noland_snapshot::WindowsMetadata::from_file(file)?;
        if native.kind != noland_snapshot::NativeEntryKind::File || native.number_of_links != 1 {
            return Err(StateError::UnsafePath(
                "native helper must be an unlinked regular PE executable".into(),
            ));
        }
        let mut dos = [0u8; 64];
        file.seek(SeekFrom::Start(0))?;
        file.read_exact(&mut dos)?;
        let pe = u32::from_le_bytes(dos[60..64].try_into().unwrap()) as u64;
        if &dos[..2] != b"MZ" || !(64..=1024 * 1024).contains(&pe) {
            return Err(StateError::Invalid(
                "native helper has no bounded PE header".into(),
            ));
        }
        file.seek(SeekFrom::Start(pe))?;
        let mut coff = [0u8; 24];
        file.read_exact(&mut coff)?;
        let machine = u16::from_le_bytes(coff[4..6].try_into().unwrap());
        let characteristics = u16::from_le_bytes(coff[22..24].try_into().unwrap());
        let compatible = cfg!(target_arch = "x86_64") && machine == 0x8664
            || cfg!(target_arch = "aarch64") && machine == 0xaa64
            || cfg!(target_arch = "x86") && machine == 0x14c;
        if &coff[..4] != b"PE\0\0"
            || !compatible
            || characteristics & 2 == 0
            || characteristics & 0x2000 != 0
        {
            return Err(StateError::Invalid(
                "native helper PE architecture/type is incompatible".into(),
            ));
        }
    }
    Ok(())
}

/// The caller must first preflight version/flags with this exact executable.
/// No caller can replace an executable already bound to this process.
pub fn install_native_rclone(path: &Path) -> Result<()> {
    install(path, None)
}

/// Tests only: parent verifies/downloads an official helper in an isolated
/// temporary directory. Never enabled by production discovery, argv or env.
#[cfg(all(any(unix, windows), any(test, feature = "native-test-runtime")))]
pub fn install_native_rclone_for_local_tests(path: &Path, sandbox: &Path) -> Result<()> {
    if !sandbox.is_absolute() {
        return Err(StateError::UnsafePath(
            "local test sandbox must be absolute".into(),
        ));
    }
    let root = noland_snapshot::SourcePath::new(sandbox)?.open_directory()?;
    noland_snapshot::native_metadata::verify_private_directory(&root)?;
    install(path, Some(sandbox.to_path_buf()))
}

fn install(path: &Path, local_test_sandbox: Option<PathBuf>) -> Result<()> {
    if !path.is_absolute() {
        return Err(StateError::UnsafePath(
            "native rclone requires an absolute installed path".into(),
        ));
    }
    let source = noland_snapshot::SourcePath::new(path)?;
    let mut file = source.open_regular()?;
    verify_executable(&mut file)?;
    #[cfg(windows)]
    {
        let resources = RESOURCES.get_or_init(Mutex::default).lock().map_err(|_| {
            StateError::Conflict("native helper resource registry is unavailable".into())
        })?;
        let resource = resources.iter().find(|resource| resource.path == path)
            .ok_or_else(|| StateError::Conflict(
                "Windows helper requires pin_native_rclone_resource with a trusted build digest before preflight/install".into()))?;
        if !resource.identity.same_file(&file)? || !resource.identity.same_file(&resource._file)? {
            return Err(StateError::Conflict(
                "native helper pin changed after preflight".into(),
            ));
        }
    }
    if let Some(prior) = NATIVE.get() {
        if prior.path != path
            || prior.local_test_sandbox != local_test_sandbox
            || !prior.identity.same_file(&file)?
        {
            return Err(StateError::Conflict(
                "installed rclone changed; restart and preflight again".into(),
            ));
        }
        return Ok(());
    }
    let identity = crate::native_fs::FileState::read(&file)?;
    NATIVE
        .set(Executable {
            path: path.to_path_buf(),
            file,
            identity,
            _source: source,
            local_test_sandbox,
            #[cfg(windows)]
            system_root: crate::native_windows::system_root()?,
        })
        .map_err(|_| {
            StateError::Conflict("native rclone was concurrently installed; retry preflight".into())
        })
}

pub(crate) fn validate_session(session: &crate::EphemeralRcloneSession) -> Result<()> {
    let Some(sandbox) = NATIVE
        .get()
        .and_then(|runtime| runtime.local_test_sandbox.as_ref())
    else {
        return Ok(());
    };
    if session.provider != "local"
        || session.backend_type != "local"
        || !Path::new(&session.root).is_absolute()
        || !Path::new(&session.root).starts_with(sandbox)
    {
        return Err(StateError::UnsafePath(
            "test-only helper refuses non-local or out-of-sandbox providers".into(),
        ));
    }
    // The parent creates its synthetic cloud directory in advance. Symlink
    // ancestors cannot redirect the real local transport outside that sandbox.
    #[cfg(any(unix, windows))]
    let _ = noland_snapshot::SourcePath::new(Path::new(&session.root))?.open_directory()?;
    #[cfg(not(any(unix, windows)))]
    return Err(StateError::Storage(
        "local test runtime requires supported native directory handles".into(),
    ));
    Ok(())
}

pub(crate) fn local_test_only() -> bool {
    NATIVE
        .get()
        .is_some_and(|runtime| runtime.local_test_sandbox.is_some())
}

pub(crate) fn enabled() -> bool {
    NATIVE.get().is_some()
}

pub(crate) fn command() -> std::io::Result<Command> {
    let Some(executable) = NATIVE.get() else {
        #[cfg(windows)]
        return Err(std::io::Error::new(std::io::ErrorKind::NotFound,
            "native Windows rclone requires a digest-pinned resource and explicit version/flag preflight"));
        #[cfg(not(windows))]
        return Ok(Command::new("rclone"));
    };
    let current = noland_snapshot::open_regular_nofollow(&executable.path)
        .map_err(|_| std::io::Error::other("installed rclone identity cannot be verified"))?;
    if !executable
        .identity
        .same_file(&executable.file)
        .map_err(|_| std::io::Error::other("native executable observation failed"))?
        || !executable
            .identity
            .same_file(&current)
            .map_err(|_| std::io::Error::other("native executable observation failed"))?
    {
        return Err(std::io::Error::other(
            "installed rclone changed; restart and preflight again",
        ));
    }
    let mut command = Command::new(&executable.path);
    // Inherited RCLONE_* credentials, filters or executable search paths cannot
    // change the approved session or widen/narrow the immutable object request.
    command.env_clear().env("LANG", "C").env("LC_ALL", "C");
    #[cfg(windows)]
    {
        use std::os::windows::process::CommandExt;
        command
            .env("SystemRoot", &executable.system_root)
            .env("WINDIR", &executable.system_root)
            .current_dir(&executable.system_root);
        command.as_std_mut().creation_flags(0x0800_0000); // CREATE_NO_WINDOW
    }
    command.arg("--ask-password=false");
    Ok(command)
}

#[cfg(all(test, windows))]
mod windows_tests {
    use super::*;
    // Header/identity validation only: no pin installation or process execution.
    #[test]
    fn native_helper_rejects_scripts_and_wrong_pe_architecture_without_execution() {
        let root =
            std::env::temp_dir().join(format!("quicksave-pe-fixture-{}", uuid::Uuid::new_v4()));
        std::fs::create_dir(&root).unwrap();
        let path = root.join("synthetic-helper.exe");
        std::fs::write(&path, b"not a PE executable").unwrap();
        let mut file = noland_snapshot::SourcePath::new(&path)
            .unwrap()
            .open_regular()
            .unwrap();
        assert!(verify_executable(&mut file).is_err());
        drop(file);
        let mut header = [0u8; 128];
        header[..2].copy_from_slice(b"MZ");
        header[60..64].copy_from_slice(&64u32.to_le_bytes());
        header[64..68].copy_from_slice(b"PE\0\0");
        header[68..70].copy_from_slice(&0xffffu16.to_le_bytes());
        header[86..88].copy_from_slice(&2u16.to_le_bytes());
        std::fs::write(&path, header).unwrap();
        let mut file = noland_snapshot::SourcePath::new(&path)
            .unwrap()
            .open_regular()
            .unwrap();
        assert!(verify_executable(&mut file).is_err());
        drop(file);
        std::fs::remove_dir_all(root).unwrap();
    }
}
