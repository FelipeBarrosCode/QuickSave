// SPDX-License-Identifier: GPL-3.0-only
//! Native read-only directory handles for bounded metadata discovery.
//! Every ancestor is opened no-follow. Directory enumeration and file opens are
//! relative to pinned handles, not a check-then-follow traversal by path.
//! This is NOT the engine's backup confinement API and supplies no write access.

use anyhow::{ensure, Context, Result};
use std::ffi::{CStr, CString};
#[cfg(test)]
use std::fs;
use std::fs::{File, Metadata};
use std::io::{self, Read};
use std::os::fd::{AsRawFd, FromRawFd};
use std::os::unix::fs::MetadataExt;
use std::path::{Component, Path, PathBuf};

const DIRECTORY_FLAGS: i32 =
    libc::O_RDONLY | libc::O_CLOEXEC | libc::O_NOFOLLOW | libc::O_DIRECTORY;

pub(crate) struct Directory {
    file: File,
    path: PathBuf,
}

pub(crate) struct Listing {
    pub names: Vec<String>,
    pub truncated: bool,
}

impl Directory {
    /// Wrap an owned directory handle obtained from a retained native SafeRoot.
    /// This never opens `path`; it is display/relative-routing metadata only.
    pub(crate) fn from_pinned(file: File, path: PathBuf) -> Result<Self> {
        validate_absolute(&path)?;
        ensure!(
            file.metadata()?.is_dir(),
            "pinned metadata handle is not a directory"
        );
        Ok(Self { file, path })
    }

    pub fn open(path: &Path) -> Result<Self> {
        validate_absolute(path)?;
        // Start at the real root and inspect every component relative to a
        // pinned parent. A path-based lstat here would still follow symlinked
        // ancestors before we had a chance to reject them.
        let file = open_at(libc::AT_FDCWD, c"/", DIRECTORY_FLAGS)?;
        let mut directory = Self {
            file,
            path: PathBuf::from("/"),
        };
        for component in path.components() {
            match component {
                Component::RootDir => {}
                Component::Normal(name) => {
                    let name = name.to_str().context("non-UTF8 discovery path")?;
                    directory = directory.child(name)?;
                }
                _ => anyhow::bail!("invalid absolute discovery path"),
            }
        }
        Ok(directory)
    }

    pub fn child(&self, name: &str) -> Result<Self> {
        let name_c = component(name)?;
        let path = self.path.join(name);
        let metadata = stat_at(self.file.as_raw_fd(), &name_c)?;
        ensure!(
            metadata.st_mode & libc::S_IFMT == libc::S_IFDIR,
            "not a real directory"
        );
        let file = open_at(self.file.as_raw_fd(), &name_c, DIRECTORY_FLAGS)?;
        let opened = file.metadata()?;
        ensure!(
            metadata.st_dev as u64 == opened.dev() && metadata.st_ino as u64 == opened.ino(),
            "discovery directory changed during opening"
        );
        Ok(Self { file, path })
    }

    pub fn path(&self) -> &Path {
        &self.path
    }

    pub fn metadata(&self) -> Result<Metadata> {
        Ok(self.file.metadata()?)
    }

    /// Inspect a real regular-file handle without reading its contents.
    pub fn regular_file_metadata(&self, name: &str) -> Result<Metadata> {
        let name = component(name)?;
        let file = open_at(
            self.file.as_raw_fd(),
            &name,
            libc::O_RDONLY | libc::O_CLOEXEC | libc::O_NOFOLLOW | libc::O_NONBLOCK,
        )?;
        let metadata = file.metadata()?;
        ensure!(metadata.is_file(), "native identity is not a regular file");
        Ok(metadata)
    }

    pub fn entries(&self, max_entries: usize) -> Result<Listing> {
        // openat(".") gets an independent directory offset; dup would share it.
        let file = open_at(self.file.as_raw_fd(), c".", DIRECTORY_FLAGS)?;
        let fd = std::os::fd::IntoRawFd::into_raw_fd(file);
        // SAFETY: ownership of this fresh descriptor is transferred to the DIR
        // on success, or explicitly closed on failure.
        let stream = unsafe { libc::fdopendir(fd) };
        if stream.is_null() {
            let error = io::Error::last_os_error();
            unsafe {
                libc::close(fd);
            }
            return Err(error.into());
        }
        let stream = DirectoryStream(stream);
        let mut names = Vec::new();
        let mut truncated = false;
        loop {
            reset_errno();
            // SAFETY: stream owns a live directory descriptor; no other thread
            // accesses its DIR, and d_name is copied before the next readdir.
            let entry = unsafe { libc::readdir(stream.0) };
            if entry.is_null() {
                let error = io::Error::last_os_error();
                if error.raw_os_error() != Some(0) {
                    return Err(error.into());
                }
                break;
            }
            let name = unsafe { CStr::from_ptr((*entry).d_name.as_ptr()) };
            if name.to_bytes() == b"." || name.to_bytes() == b".." {
                continue;
            }
            if names.len() >= max_entries {
                truncated = true;
                break;
            }
            let name = name.to_str().context("non-UTF8 discovery entry rejected")?;
            component(name)?;
            names.push(name.to_owned());
        }
        names.sort();
        Ok(Listing { names, truncated })
    }

    pub fn read_file(&self, name: &str, max_bytes: usize) -> Result<Vec<u8>> {
        Ok(self.read_file_with_metadata(name, max_bytes)?.0)
    }

    pub fn read_file_with_metadata(
        &self,
        name: &str,
        max_bytes: usize,
    ) -> Result<(Vec<u8>, Metadata)> {
        let name = component(name)?;
        // O_NONBLOCK prevents a malicious FIFO from blocking before fstat.
        let mut file = open_at(
            self.file.as_raw_fd(),
            &name,
            libc::O_RDONLY | libc::O_CLOEXEC | libc::O_NOFOLLOW | libc::O_NONBLOCK,
        )?;
        let before = file.metadata()?;
        ensure!(before.is_file(), "discovery metadata is not a regular file");
        ensure!(
            before.nlink() == 1,
            "multiply linked metadata cannot establish scoped ownership"
        );
        ensure!(
            before.len() <= max_bytes as u64,
            "discovery metadata exceeds size limit"
        );
        let mut bytes = Vec::with_capacity(before.len() as usize);
        (&mut file)
            .take(max_bytes as u64 + 1)
            .read_to_end(&mut bytes)?;
        ensure!(
            bytes.len() <= max_bytes,
            "discovery metadata exceeds size limit"
        );
        let after = file.metadata()?;
        ensure!(
            same_stamp(&before, &after) && bytes.len() as u64 == after.len(),
            "discovery metadata changed while being read"
        );
        let named = stat_at(self.file.as_raw_fd(), &name)?;
        ensure!(
            named.st_dev as u64 == after.dev()
                && named.st_ino as u64 == after.ino()
                && named.st_mode & libc::S_IFMT == libc::S_IFREG,
            "discovery metadata filename changed while being read"
        );
        Ok((bytes, after))
    }
}

fn same_stamp(before: &Metadata, after: &Metadata) -> bool {
    before.dev() == after.dev()
        && before.ino() == after.ino()
        && before.len() == after.len()
        && before.mtime() == after.mtime()
        && before.mtime_nsec() == after.mtime_nsec()
        && before.ctime() == after.ctime()
        && before.ctime_nsec() == after.ctime_nsec()
}

fn validate_absolute(path: &Path) -> Result<()> {
    ensure!(path.is_absolute(), "discovery path must be absolute");
    let text = path.to_str().context("non-UTF8 discovery path")?;
    ensure!(
        text.len() <= 4096 && !text.chars().any(char::is_control),
        "invalid discovery path"
    );
    ensure!(
        !text.split('/').any(|part| part == "." || part == ".."),
        "dot path components are not accepted"
    );
    Ok(())
}

fn component(name: &str) -> Result<CString> {
    ensure!(
        !name.is_empty()
            && name.len() <= 255
            && name != "."
            && name != ".."
            && !name.contains('/')
            && !name.contains('\\')
            && !name.chars().any(char::is_control),
        "invalid discovery path component"
    );
    CString::new(name).context("invalid discovery path component")
}

fn open_at(parent: i32, name: &CStr, flags: i32) -> Result<File> {
    // SAFETY: name is NUL-terminated, flags never request creation, and the
    // returned descriptor is owned exactly once by File.
    let fd = unsafe { libc::openat(parent, name.as_ptr(), flags) };
    if fd < 0 {
        return Err(io::Error::last_os_error().into());
    }
    Ok(unsafe { File::from_raw_fd(fd) })
}

fn stat_at(parent: i32, name: &CStr) -> Result<libc::stat> {
    let mut metadata = std::mem::MaybeUninit::<libc::stat>::uninit();
    // SAFETY: parent is a live pinned descriptor; name is NUL-terminated and
    // fstatat initializes the entire stat on success. No ancestor or final link
    // is traversed by this handle-relative metadata lookup.
    if unsafe {
        libc::fstatat(
            parent,
            name.as_ptr(),
            metadata.as_mut_ptr(),
            libc::AT_SYMLINK_NOFOLLOW,
        )
    } != 0
    {
        return Err(io::Error::last_os_error().into());
    }
    Ok(unsafe { metadata.assume_init() })
}

struct DirectoryStream(*mut libc::DIR);

impl Drop for DirectoryStream {
    fn drop(&mut self) {
        // SAFETY: this is the sole owner of the stream returned by fdopendir.
        unsafe {
            libc::closedir(self.0);
        }
    }
}

fn reset_errno() {
    // SAFETY: libc exposes this thread's errno storage.
    #[cfg(target_os = "macos")]
    unsafe {
        *libc::__error() = 0;
    }
    #[cfg(target_os = "linux")]
    unsafe {
        *libc::__errno_location() = 0;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn temporary() -> tempfile::TempDir {
        let base = fs::canonicalize(std::env::temp_dir()).unwrap();
        tempfile::tempdir_in(base).unwrap()
    }

    #[test]
    fn rejects_symlink_files_directories_and_ancestors() {
        use std::os::unix::fs::symlink;
        let temp = temporary();
        fs::create_dir(temp.path().join("real")).unwrap();
        fs::create_dir(temp.path().join("real/child")).unwrap();
        fs::write(temp.path().join("real/metadata"), b"fixture").unwrap();
        symlink(temp.path().join("real"), temp.path().join("alias")).unwrap();
        symlink("metadata", temp.path().join("real/link")).unwrap();
        assert!(Directory::open(&temp.path().join("alias")).is_err());
        assert!(Directory::open(&temp.path().join("alias/child")).is_err());
        let real = Directory::open(&temp.path().join("real")).unwrap();
        assert!(real.read_file("link", 64).is_err());
        assert!(real.read_file("../real/metadata", 64).is_err());
        assert_eq!(real.read_file("metadata", 64).unwrap(), b"fixture");
        assert!(real.read_file("metadata", 2).is_err());
    }

    #[test]
    fn directory_reads_are_pinned_after_an_ancestor_is_renamed() {
        let temp = temporary();
        let old = temp.path().join("old");
        fs::create_dir(&old).unwrap();
        fs::write(old.join("metadata"), b"original").unwrap();
        let pinned = Directory::open(&old).unwrap();
        fs::rename(&old, temp.path().join("moved")).unwrap();
        fs::create_dir(&old).unwrap();
        fs::write(old.join("metadata"), b"replacement").unwrap();
        assert_eq!(pinned.read_file("metadata", 64).unwrap(), b"original");
    }

    #[test]
    fn bounded_enumeration_reports_truncation() {
        let temp = temporary();
        for name in ["one", "two", "three"] {
            fs::write(temp.path().join(name), b"").unwrap();
        }
        let directory = Directory::open(temp.path()).unwrap();
        let limited = directory.entries(2).unwrap();
        assert_eq!(limited.names.len(), 2);
        assert!(limited.truncated);
        assert_eq!(directory.entries(4).unwrap().names.len(), 3);
    }
}
