// SPDX-License-Identifier: GPL-3.0-only
//! Procfs recovery adapted conceptually from No Land's generation/open-FD path.
//! No runtime namespace translation, agent launch, or guessed fallback paths.
use crate::*;
use anyhow::{ensure, Context, Result};
use std::{
    fs::{self, File, OpenOptions},
    io::Read,
    os::unix::{
        ffi::OsStrExt,
        fs::{MetadataExt, OpenOptionsExt},
    },
    path::{Path, PathBuf},
};

pub struct LinuxProcfs {
    uid: u32,
    mount_namespace: PathBuf,
}

impl LinuxProcfs {
    pub fn new(scope: &ObservationScope) -> Result<Self> {
        // Explicit same-user observation; never attempt a permission escalation.
        ensure!(
            scope.uid() == unsafe { libc::geteuid() },
            "procfs observation requires the approved effective UID"
        );
        let path = std::ffi::CString::new("/proc").expect("constant has no NUL");
        let mut stat: libc::statfs = unsafe { std::mem::zeroed() };
        // SAFETY: initialized native struct, NUL-terminated constant.
        ensure!(
            unsafe { libc::statfs(path.as_ptr(), &mut stat) } == 0 && stat.f_type as u64 == 0x9fa0,
            "the local /proc mount is not procfs"
        );
        Ok(Self {
            uid: scope.uid(),
            mount_namespace: fs::read_link("/proc/self/ns/mnt")?,
        })
    }
}

impl ProcessProbe for LinuxProcfs {
    fn capabilities(&self) -> SourceCapabilities {
        SourceCapabilities {
            source: SourceKind::LinuxProcfs, state: CapabilityState::Available,
            process_generations: true, executable_stamps: true, running_image_native_identity: true, native_open_file_identity: true,
            bundle_identifier_verification: false, complete_lifecycle_stream: false,
            complete_file_stream: false,
            reason: "Same-user, same-mount-namespace procfs generation/image/open-FD sampling; short-lived opens and exec-and-back remain unknown.",
        }
    }

    fn processes(&mut self, _: &ObservationScope, max: usize) -> Result<ProbeListing<u32>> {
        let mut listing = ProbeListing {
            items: Vec::new(),
            complete: true,
        };
        // Bounded directory iteration even when most tasks are outside UID scope.
        let mut visited = 0_usize;
        for entry in fs::read_dir("/proc")? {
            visited += 1;
            if visited > max.saturating_mul(4).saturating_add(256) {
                listing.complete = false;
                break;
            }
            let entry = entry?;
            let Some(pid) = entry
                .file_name()
                .to_str()
                .and_then(|name| name.parse::<u32>().ok())
            else {
                continue;
            };
            if listing.items.len() >= max {
                listing.complete = false;
                break;
            }
            listing.items.push(pid);
        }
        listing.items.sort_unstable();
        listing.items.dedup();
        Ok(listing)
    }

    fn process(&mut self, scope: &ObservationScope, pid: u32) -> Result<Option<ProcessDescriptor>> {
        ensure!(pid > 0 && pid <= i32::MAX as u32, "invalid procfs PID");
        let directory = PathBuf::from(format!("/proc/{pid}"));
        let before = match fs::metadata(&directory) {
            Ok(metadata) if metadata.uid() == self.uid => metadata,
            Ok(_) => return Ok(None),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
            Err(error) => return Err(error.into()),
        };
        let stat = read_stat(&directory.join("stat"))?;
        let start = parse_start_ticks(&stat).context("invalid kernel process stat")?;
        let executable = fs::read_link(directory.join("exe"))?;
        if scope
            .locate(&executable, ObservationRootKind::Executable)
            .is_none()
        {
            return Ok(None);
        }
        let namespace = fs::read_link(directory.join("ns/mnt"))?;
        ensure!(
            namespace == self.mount_namespace,
            "foreign process mount namespace is not approved"
        );
        // Only AFTER lexical approved-scope filtering do we inspect the native
        // image referred to by this kernel magic link. The common collector also
        // checks the no-symlink pinned host file against this exact native ID.
        let image = fs::metadata(directory.join("exe"))?;
        ensure!(image.is_file(), "procfs executable is not regular");
        let after = fs::metadata(&directory)?;
        ensure!(
            before.ino() == after.ino() && before.dev() == after.dev() && after.uid() == self.uid,
            "procfs process generation changed"
        );
        ensure!(
            parse_start_ticks(&read_stat(&directory.join("stat"))?) == Some(start)
                && fs::read_link(directory.join("exe"))? == executable
                && fs::read_link(directory.join("ns/mnt"))? == namespace,
            "procfs process changed during native image inspection"
        );
        let namespace_inode = namespace
            .to_str()
            .and_then(|value| value.strip_prefix("mnt:["))
            .and_then(|value| value.strip_suffix(']'))
            .and_then(|value| value.parse().ok())
            .context("invalid kernel namespace identity")?;
        Ok(Some(ProcessDescriptor {
            generation: ProcessGeneration {
                pid,
                uid: self.uid,
                start: [start, before.ino()],
                namespace: [namespace_inode, before.dev()],
            },
            executable,
            executable_identity: identity(&image),
            image_binding: ImageIdentityBinding::MappedImageNativeFile,
            bundle_identifier: None,
        }))
    }

    fn descriptors(&mut self, pid: u32, max: usize) -> Result<ProbeListing<u64>> {
        let mut listing = ProbeListing {
            items: Vec::new(),
            complete: true,
        };
        for entry in fs::read_dir(format!("/proc/{pid}/fd"))? {
            if listing.items.len() >= max {
                listing.complete = false;
                break;
            }
            let entry = entry?;
            if let Some(fd) = entry
                .file_name()
                .to_str()
                .and_then(|name| name.parse::<u64>().ok())
            {
                listing.items.push(fd);
            } else {
                anyhow::bail!("invalid kernel descriptor name");
            }
        }
        listing.items.sort_unstable();
        Ok(listing)
    }

    fn descriptor(
        &mut self,
        scope: &ObservationScope,
        pid: u32,
        descriptor: u64,
    ) -> Result<Option<DescriptorSample>> {
        ensure!(descriptor <= i32::MAX as u64, "invalid native descriptor");
        let magic = PathBuf::from(format!("/proc/{pid}/fd/{descriptor}"));
        let path = fs::read_link(&magic)?;
        if path.as_os_str().as_bytes().ends_with(b" (deleted)") {
            anyhow::bail!("deleted descriptor cannot name a live scoped leaf");
        }
        if scope.locate(&path, ObservationRootKind::Data).is_none() {
            return Ok(None);
        }
        let metadata = fs::metadata(&magic)?;
        ensure!(
            metadata.is_file(),
            "native descriptor is not a regular file"
        );
        ensure!(
            fs::read_link(&magic)? == path,
            "native descriptor was swapped"
        );
        Ok(Some(DescriptorSample {
            path,
            identity: identity(&metadata),
        }))
    }
}

fn identity(metadata: &fs::Metadata) -> NativeFileIdentity {
    NativeFileIdentity {
        device: metadata.dev(),
        file_id: [metadata.ino(), 0],
    }
}

fn read_stat(path: &Path) -> Result<Vec<u8>> {
    // This is kernel-generated process metadata, not an application file read.
    let file: File = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(path)?;
    let mut bytes = Vec::new();
    file.take(8193).read_to_end(&mut bytes)?;
    ensure!(
        bytes.len() <= 8192,
        "kernel process metadata exceeds the byte bound"
    );
    Ok(bytes)
}

pub(crate) fn parse_start_ticks(bytes: &[u8]) -> Option<u64> {
    let text = std::str::from_utf8(bytes).ok()?;
    // comm may contain ')' and spaces; only the LAST ')' terminates it.
    let rest = text.get(text.rfind(')')? + 1..)?;
    rest.split_whitespace().nth(19)?.parse().ok()
}

#[cfg(test)]
mod tests {
    #[test]
    fn proc_stat_parser_handles_parentheses_without_real_procfs() {
        let mut fields = vec!["0"; 20];
        fields[0] = "S";
        fields[19] = "4321";
        let input = format!("41 (same ) name) {}", fields.join(" "));
        assert_eq!(super::parse_start_ticks(input.as_bytes()), Some(4321));
    }
}
