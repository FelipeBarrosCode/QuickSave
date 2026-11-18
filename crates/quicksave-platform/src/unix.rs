// SPDX-License-Identifier: GPL-3.0-only

use crate::{
    validate_component, validate_link_target, validate_relative, DirectoryIdentity, Entry,
    EntryKind, FileStamp, MetadataEntry, NativeLinkStamp, MAX_DEPTH, MAX_PATH_BYTES,
    MAX_TREE_ENTRIES, MAX_TREE_PATH_BYTES,
};
use anyhow::{bail, ensure, Context, Result};
use rand::{rngs::OsRng, RngCore};
use std::{
    ffi::{CStr, CString},
    fs::File,
    io,
    mem::MaybeUninit,
    os::{
        fd::{AsRawFd, FromRawFd, IntoRawFd, RawFd},
        unix::ffi::OsStrExt,
    },
    path::{Component, Path, PathBuf},
};

mod overlap;
mod privacy;

const DIR_FLAGS: libc::c_int =
    libc::O_RDONLY | libc::O_DIRECTORY | libc::O_CLOEXEC | libc::O_NOFOLLOW;
const READ_FLAGS: libc::c_int =
    libc::O_RDONLY | libc::O_CLOEXEC | libc::O_NOFOLLOW | libc::O_NONBLOCK;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct Identity {
    device: u64,
    inode: u64,
}

impl Identity {
    // libc's inode/device aliases have different widths across Unix targets.
    #[allow(clippy::unnecessary_cast)]
    fn of(stat: &libc::stat) -> Self {
        Self {
            device: stat.st_dev as u64,
            inode: stat.st_ino as u64,
        }
    }
}

struct Directory {
    file: File,
    identity: Identity,
    /// The edge from the preceding pinned directory, or None for "/".
    name: Option<CString>,
}

pub(crate) struct Root {
    ancestors: Vec<Directory>,
}

impl Root {
    pub(crate) fn open(path: &Path) -> Result<Self> {
        Self::open_impl(path, false)
    }

    fn open_impl(path: &Path, create_missing: bool) -> Result<Self> {
        let absolute = absolute_path(path)?;
        let slash = CString::new("/")?;
        // SAFETY: slash is a live NUL-terminated string; no variadic mode is
        // needed because O_CREAT is absent.
        let fd = unsafe { libc::open(slash.as_ptr(), DIR_FLAGS) };
        let file = file_from_result(fd).context("open filesystem root without following links")?;
        let stat = fstat(&file)?;
        require_directory(&stat)?;
        let mut root = Self {
            ancestors: vec![Directory {
                file,
                identity: Identity::of(&stat),
                name: None,
            }],
        };

        for component in absolute.components() {
            match component {
                Component::RootDir => {}
                Component::Normal(component) => {
                    ensure!(root.ancestors.len() <= MAX_DEPTH, "root path is too deep");
                    let component = component.to_str().context("root path must be UTF-8")?;
                    // Root names need not be portable to Windows, but must be
                    // ordinary single native components.
                    ensure!(
                        !component.is_empty() && component.len() <= 255,
                        "invalid root component"
                    );
                    let name = CString::new(component)?;
                    root.check()?;
                    let parent = root.file();
                    let mut created = false;
                    let child = match openat_file(parent, &name, DIR_FLAGS, 0) {
                        Ok(file) => file,
                        Err(error)
                            if create_missing && error.raw_os_error() == Some(libc::ENOENT) =>
                        {
                            mkdirat(parent, &name)?;
                            created = true;
                            openat_file(parent, &name, DIR_FLAGS, 0)
                                .context("open newly created private directory")?
                        }
                        Err(error) => return Err(error).context("open no-follow root component"),
                    };
                    let stat = fstat(&child)?;
                    require_directory(&stat)?;
                    ensure_edge(parent, &name, Identity::of(&stat))?;
                    if created {
                        require_private_directory(&child)?;
                        child.sync_all().context("flush newly created directory")?;
                        parent.sync_all().context("flush new directory's parent")?;
                    }
                    root.ancestors.push(Directory {
                        file: child,
                        identity: Identity::of(&stat),
                        name: Some(name),
                    });
                }
                _ => bail!("root path cannot contain '.' or '..' components"),
            }
        }
        root.check()?;
        Ok(root)
    }

    fn file(&self) -> &File {
        &self.ancestors[self.ancestors.len() - 1].file
    }

    pub(crate) fn check(&self) -> Result<()> {
        for (index, directory) in self.ancestors.iter().enumerate() {
            let stat = fstat(&directory.file)?;
            require_directory(&stat)?;
            ensure!(
                Identity::of(&stat) == directory.identity,
                "pinned root directory identity changed"
            );
            if let Some(name) = &directory.name {
                ensure_edge(&self.ancestors[index - 1].file, name, directory.identity)
                    .context("root or one of its ancestors was replaced")?;
            }
        }
        Ok(())
    }

    pub(crate) fn ancestors_overlap(&self, other: &Self) -> bool {
        let own = self.ancestors.last().unwrap().identity;
        let theirs = other.ancestors.last().unwrap().identity;
        self.ancestors
            .iter()
            .any(|ancestor| ancestor.identity == theirs)
            || other
                .ancestors
                .iter()
                .any(|ancestor| ancestor.identity == own)
    }

    pub(crate) fn directory_identity(&self, relative: Option<&str>) -> Result<DirectoryIdentity> {
        self.check()?;
        let identity = if let Some(relative) = relative {
            let (parent, name) = self.parent(relative)?;
            let before = statat(parent.file(), &name)?;
            require_directory(&before)?;
            let directory = openat_file(parent.file(), &name, DIR_FLAGS, 0)?;
            let opened = fstat(&directory)?;
            require_directory(&opened)?;
            let identity = Identity::of(&opened);
            ensure!(
                identity == Identity::of(&before),
                "directory identity changed while opening for overlap inspection"
            );
            ensure_edge(parent.file(), &name, identity)?;
            parent.check()?;
            identity
        } else {
            let stat = fstat(self.file())?;
            require_directory(&stat)?;
            Identity::of(&stat)
        };
        self.check()?;
        Ok(DirectoryIdentity {
            device: identity.device,
            file_id: [identity.inode, 0],
        })
    }

    fn parent<'a>(&'a self, relative: &str) -> Result<(Parent<'a>, CString)> {
        let components = validate_relative(relative)?;
        self.check()?;
        let mut parent = Parent {
            root: self,
            descendants: Vec::with_capacity(components.len() - 1),
        };
        for component in &components[..components.len() - 1] {
            let name = CString::new(*component)?;
            let file = openat_file(parent.file(), &name, DIR_FLAGS, 0)
                .context("open no-follow relative parent")?;
            let stat = fstat(&file)?;
            require_directory(&stat)?;
            let identity = Identity::of(&stat);
            ensure_edge(parent.file(), &name, identity)?;
            parent.descendants.push(Directory {
                file,
                identity,
                name: Some(name),
            });
        }
        parent.check()?;
        Ok((parent, CString::new(*components.last().unwrap())?))
    }

    pub(crate) fn read_file(&self, relative: &str) -> Result<(File, FileStamp)> {
        let (parent, name) = self.parent(relative)?;
        let before =
            statat(parent.file(), &name).context("inspect source without following links")?;
        require_regular(&before)?;
        let file = openat_file(parent.file(), &name, READ_FLAGS, 0)
            .context("open no-follow source file")?;
        let opened = fstat(&file)?;
        require_regular(&opened)?;
        ensure!(
            stamp(&before)? == stamp(&opened)?,
            "source changed while opening"
        );
        let after = statat(parent.file(), &name)?;
        require_regular(&after)?;
        let opened_stamp = stamp(&opened)?;
        ensure!(
            opened_stamp == stamp(&after)?,
            "source name changed while opening"
        );
        parent.check()?;
        Ok((file, opened_stamp))
    }

    pub(crate) fn file_metadata(&self, relative: &str) -> Result<FileStamp> {
        let (parent, name) = self.parent(relative)?;
        let before = statat(parent.file(), &name)
            .context("inspect native regular-file metadata without following links")?;
        require_regular(&before)?;
        let before = stamp(&before)?;
        parent.check()?;
        let after = statat(parent.file(), &name)?;
        require_regular(&after)?;
        ensure!(
            before == stamp(&after)?,
            "native file metadata changed during inspection"
        );
        self.check()?;
        Ok(before)
    }

    pub(crate) fn open_directory(&self, relative: &str) -> Result<File> {
        let (parent, name) = self.parent(relative)?;
        let before = statat(parent.file(), &name)?;
        require_directory(&before)?;
        let directory = openat_file(parent.file(), &name, DIR_FLAGS, 0)
            .context("open real no-follow relative directory")?;
        let opened = fstat(&directory)?;
        require_directory(&opened)?;
        let identity = Identity::of(&opened);
        ensure!(
            identity == Identity::of(&before),
            "directory changed while opening"
        );
        let after = statat(parent.file(), &name)?;
        require_directory(&after)?;
        ensure!(
            identity == Identity::of(&after),
            "relative directory name changed while opening"
        );
        parent.check()?;
        ensure_edge(parent.file(), &name, identity)?;
        Ok(directory)
    }

    pub(crate) fn clone_root_directory_handle(&self) -> Result<File> {
        self.check()?;
        let before = fstat(self.file())?;
        require_directory(&before)?;
        let directory = openat_file(self.file(), c".", DIR_FLAGS, 0)?;
        let opened = fstat(&directory)?;
        require_directory(&opened)?;
        ensure!(
            Identity::of(&opened) == Identity::of(&before),
            "pinned root handle identity changed"
        );
        self.check()?;
        Ok(directory)
    }

    pub(crate) fn entries(&self) -> Result<Vec<Entry>> {
        self.check()?;
        let mut output = Vec::new();
        let mut path_bytes = 0;
        let mut discovered = DiscoveryBudget::default();
        self.walk(
            self.file(),
            "",
            0,
            &mut output,
            &mut path_bytes,
            &mut discovered,
        )?;
        self.check()?;
        output.sort_unstable_by(|a, b| a.relative_path.cmp(&b.relative_path));
        Ok(output)
    }

    pub(crate) fn read_link(&self, relative: &str) -> Result<NativeLinkStamp> {
        let (parent, name) = self.parent(relative)?;
        let observed = read_link_at(parent.file(), &name, relative)?;
        parent.check()?;
        ensure!(
            read_link_at(parent.file(), &name, relative)? == observed,
            "symlink changed during namespace validation"
        );
        Ok(observed)
    }

    pub(crate) fn metadata_entries(&self) -> Result<Vec<MetadataEntry>> {
        self.check()?;
        let mut output = Vec::new();
        let mut discovered = DiscoveryBudget::default();
        let mut bytes = 0;
        self.walk_metadata(self.file(), "", 0, &mut output, &mut discovered, &mut bytes)?;
        self.check()?;
        output.sort_unstable_by(|a, b| a.relative_path.cmp(&b.relative_path));
        Ok(output)
    }

    fn walk_metadata(
        &self,
        directory: &File,
        prefix: &str,
        depth: usize,
        output: &mut Vec<MetadataEntry>,
        discovered: &mut DiscoveryBudget,
        bytes: &mut usize,
    ) -> Result<()> {
        ensure!(depth <= MAX_DEPTH, "tree exceeds maximum depth");
        let before = fstat(directory)?;
        require_directory(&before)?;
        for name in directory_names(directory, prefix, discovered)? {
            let text = name.to_str().context("tree contains a non-UTF8 name")?;
            validate_component(text)?;
            let relative = if prefix.is_empty() {
                text.to_owned()
            } else {
                format!("{prefix}/{text}")
            };
            ensure!(
                depth < MAX_DEPTH
                    && relative.len() <= MAX_PATH_BYTES
                    && output.len() < MAX_TREE_ENTRIES,
                "tree exceeds entry, depth, or path limit"
            );
            *bytes = bytes
                .checked_add(relative.len())
                .context("tree size overflow")?;
            let observed = statat(directory, &name)?;
            let mut entry = MetadataEntry {
                relative_path: relative.clone(),
                kind: EntryKind::File,
                stamp: stamp(&observed)?,
                link: None,
            };
            match observed.st_mode & libc::S_IFMT {
                libc::S_IFDIR => {
                    entry.kind = EntryKind::Directory;
                    let child = openat_file(directory, &name, DIR_FLAGS, 0)?;
                    require_directory(&fstat(&child)?)?;
                    ensure!(
                        stamp(&fstat(&child)?)? == entry.stamp,
                        "directory changed while opening metadata"
                    );
                    let identity = Identity::of(&observed);
                    ensure_edge(directory, &name, identity)?;
                    output.push(entry);
                    self.walk_metadata(&child, &relative, depth + 1, output, discovered, bytes)?;
                    ensure_edge(directory, &name, identity)?;
                }
                libc::S_IFREG => {
                    require_regular(&observed)?;
                    output.push(entry);
                }
                libc::S_IFLNK => {
                    let link = read_link_at(directory, &name, &relative)?;
                    ensure!(
                        link.stamp == entry.stamp,
                        "symlink replaced during metadata walk"
                    );
                    *bytes = bytes
                        .checked_add(link.target.len())
                        .context("link metadata size overflow")?;
                    entry.kind = EntryKind::Symlink;
                    entry.link = Some(link);
                    output.push(entry);
                }
                _ => bail!("tree contains an unsupported special file: {relative}"),
            }
            ensure!(
                *bytes <= MAX_TREE_PATH_BYTES,
                "tree metadata exceeds memory limit"
            );
        }
        ensure!(
            stamp(&fstat(directory)?)? == stamp(&before)?,
            "directory changed during metadata enumeration"
        );
        self.check()
    }

    pub(crate) fn create_new_relative_symlink(
        &self,
        relative: &str,
        target: &str,
        target_is_directory: Option<bool>,
    ) -> Result<NativeLinkStamp> {
        require_durable_platform()?;
        validate_link_target(relative, target)?;
        ensure!(
            target_is_directory.is_none(),
            "Unix symlinks have no directory-link kind"
        );
        let (parent, name) = self.parent(relative)?;
        parent.check()?;
        let target = CString::new(target)?;
        // SAFETY: exactly one leaf beneath a pinned, no-follow parent. symlinkat
        // is create-exclusive and never resolves or accesses the target.
        if unsafe { libc::symlinkat(target.as_ptr(), parent.file().as_raw_fd(), name.as_ptr()) }
            != 0
        {
            return Err(io::Error::last_os_error())
                .context("create confined symlink without replacement");
        }
        let link = read_link_at(parent.file(), &name, relative)?;
        ensure!(
            link.target.as_bytes() == target.as_bytes(),
            "new symlink was replaced"
        );
        parent
            .file()
            .sync_all()
            .context("flush new symbolic link namespace")?;
        parent.check()?;
        ensure!(
            read_link_at(parent.file(), &name, relative)? == link,
            "new symlink changed during durability check"
        );
        Ok(link)
    }

    fn walk(
        &self,
        directory: &File,
        prefix: &str,
        depth: usize,
        output: &mut Vec<Entry>,
        path_bytes: &mut usize,
        discovered: &mut DiscoveryBudget,
    ) -> Result<()> {
        ensure!(depth <= MAX_DEPTH, "tree exceeds maximum depth");
        let before = fstat(directory)?;
        require_directory(&before)?;
        let names = directory_names(directory, prefix, discovered)?;
        for name in names {
            let text = name.to_str().context("tree contains a non-UTF8 name")?;
            validate_component(text)?;
            let relative = if prefix.is_empty() {
                text.to_owned()
            } else {
                format!("{prefix}/{text}")
            };
            ensure!(
                depth < MAX_DEPTH && relative.len() <= MAX_PATH_BYTES,
                "tree exceeds depth or path-length limit"
            );
            ensure!(output.len() < MAX_TREE_ENTRIES, "tree exceeds entry limit");
            *path_bytes = path_bytes
                .checked_add(relative.len())
                .context("tree path size overflow")?;
            ensure!(
                *path_bytes <= MAX_TREE_PATH_BYTES,
                "tree exceeds total path-memory limit"
            );
            let stat =
                statat(directory, &name).context("inspect tree entry without following links")?;
            match stat.st_mode & libc::S_IFMT {
                libc::S_IFDIR => {
                    let child = openat_file(directory, &name, DIR_FLAGS, 0)?;
                    let child_stat = fstat(&child)?;
                    require_directory(&child_stat)?;
                    let identity = Identity::of(&stat);
                    ensure!(
                        Identity::of(&child_stat) == identity,
                        "directory identity changed while traversing"
                    );
                    ensure_edge(directory, &name, identity)?;
                    output.push(Entry {
                        relative_path: relative.clone(),
                        is_directory: true,
                        size: 0,
                    });
                    self.walk(&child, &relative, depth + 1, output, path_bytes, discovered)?;
                    ensure_edge(directory, &name, identity)?;
                }
                libc::S_IFREG => {
                    output.push(Entry {
                        relative_path: relative,
                        is_directory: false,
                        size: u64::try_from(stat.st_size).context("negative source file length")?,
                    });
                }
                _ => bail!("tree contains a symlink or unsupported special file: {relative}"),
            }
        }
        let after = fstat(directory)?;
        ensure!(
            stamp(&before)? == stamp(&after)?,
            "directory changed during tree traversal"
        );
        self.check()?;
        Ok(())
    }

    pub(crate) fn create_dir(&self, relative: &str) -> Result<()> {
        require_durable_platform()?;
        let (parent, name) = self.parent(relative)?;
        let created = match mkdirat(parent.file(), &name) {
            Ok(()) => true,
            Err(error) if error.raw_os_error() == Some(libc::EEXIST) => false,
            Err(error) => return Err(error).context("create directory beneath pinned root"),
        };
        let child = openat_file(parent.file(), &name, DIR_FLAGS, 0)
            .context("created/existing entry is not a safe directory")?;
        let stat = fstat(&child)?;
        require_directory(&stat)?;
        if created {
            require_private_directory(&child)?;
        }
        ensure_edge(parent.file(), &name, Identity::of(&stat))?;
        child.sync_all().context("flush directory")?;
        parent
            .file()
            .sync_all()
            .context("flush directory's parent")?;
        parent.check()?;
        ensure_edge(parent.file(), &name, Identity::of(&stat))?;
        Ok(())
    }

    pub(crate) fn write_new(
        &self,
        relative: &str,
        writer: impl FnOnce(&mut File) -> Result<()>,
    ) -> Result<()> {
        require_durable_platform()?;
        let (parent, name) = self.parent(relative)?;
        require_absent(parent.file(), &name)?;
        // Use an operation-private 0700 directory. The callback never receives
        // the staging pathname, and publication is a native create-new link.
        let mut stage = Stage::new(parent.file())?;
        let operation = (|| -> Result<()> {
            writer(&mut stage.file).context("writer/verification failed before publication")?;
            stage.check()?;
            let verified = stamp(&fstat(&stage.file)?)?;
            stage
                .file
                .sync_all()
                .context("flush new file data and metadata")?;
            stage
                .directory
                .sync_all()
                .context("flush private staging directory")?;
            // Reject filesystems that cannot flush directories before exposing
            // a final target, and then flush the final namespace after linking.
            parent
                .file()
                .sync_all()
                .context("flush destination directory before publication")?;
            parent.check()?;
            stage.check()?;
            let before = fstat(&stage.file)?;
            ensure!(
                stamp(&before)? == verified,
                "staging file changed after writer verification"
            );
            let source = CString::new("content")?;
            // SAFETY: both native directory handles and strings remain live;
            // linkat flags zero does not follow a symbolic-link source.
            let result = unsafe {
                libc::linkat(
                    stage.directory.as_raw_fd(),
                    source.as_ptr(),
                    parent.file().as_raw_fd(),
                    name.as_ptr(),
                    0,
                )
            };
            if result != 0 {
                return Err(io::Error::last_os_error())
                    .context("publish create-new target (existing entries are never replaced)");
            }
            let published = statat(parent.file(), &name)?;
            require_regular(&published)?;
            ensure!(
                Identity::of(&published) == stage.identity
                    && published.st_size == before.st_size
                    && modified_time(&published) == modified_time(&before),
                "published file identity/content metadata changed"
            );
            parent.check()?;
            stage.cleanup()?;
            stage
                .file
                .sync_all()
                .context("flush published file metadata after staging cleanup")?;
            parent
                .file()
                .sync_all()
                .context("flush published file's directory")?;
            parent.check()?;
            let final_stat = statat(parent.file(), &name)?;
            require_regular(&final_stat)?;
            ensure!(
                Identity::of(&final_stat) == stage.identity
                    && final_stat.st_size == before.st_size
                    && modified_time(&final_stat) == modified_time(&before),
                "published target changed during final durability check"
            );
            Ok(())
        })();
        match operation {
            Ok(()) => Ok(()),
            Err(error) => match stage.cleanup() {
                Ok(()) => Err(error),
                Err(cleanup) => Err(error.context(format!(
                    "staging cleanup also failed; no unrelated entry was removed: {cleanup:#}"
                ))),
            },
        }
    }
}

struct Parent<'a> {
    root: &'a Root,
    descendants: Vec<Directory>,
}

impl Parent<'_> {
    fn file(&self) -> &File {
        self.descendants
            .last()
            .map(|directory| &directory.file)
            .unwrap_or_else(|| self.root.file())
    }

    fn check(&self) -> Result<()> {
        self.root.check()?;
        let mut parent = self.root.file();
        for directory in &self.descendants {
            let stat = fstat(&directory.file)?;
            require_directory(&stat)?;
            ensure!(
                Identity::of(&stat) == directory.identity,
                "relative parent identity changed"
            );
            ensure_edge(parent, directory.name.as_ref().unwrap(), directory.identity)?;
            parent = &directory.file;
        }
        Ok(())
    }
}

/// A private staging namespace. Cleanup checks identities before removing only
/// its own entries. Like all Unix pathnames, these names must not be tampered
/// with by another process running with the same UID/ptrace privileges.
struct Stage<'a> {
    parent: &'a File,
    name: CString,
    directory: File,
    directory_identity: Identity,
    file: File,
    identity: Identity,
    content_removed: bool,
    directory_removed: bool,
}

impl<'a> Stage<'a> {
    fn new(parent: &'a File) -> Result<Self> {
        for _ in 0..16 {
            let mut random = [0; 16];
            OsRng
                .try_fill_bytes(&mut random)
                .context("obtain secure staging-name randomness")?;
            let random = u128::from_ne_bytes(random);
            let name = CString::new(format!(".quicksave-stage-{random:032x}"))?;
            match mkdirat(parent, &name) {
                Ok(()) => {}
                Err(error) if error.raw_os_error() == Some(libc::EEXIST) => continue,
                Err(error) => return Err(error).context("create private staging directory"),
            }
            let created_stat = statat(parent, &name).context(
                "inspect new staging directory; creation may have left a temporary entry",
            )?;
            require_directory(&created_stat)?;
            let directory_identity = Identity::of(&created_stat);
            let prepare = (|| -> Result<(File, File, Identity)> {
                require_private(&created_stat)?;
                let directory = openat_file(parent, &name, DIR_FLAGS, 0)
                    .context("open newly created staging directory")?;
                ensure!(
                    Identity::of(&fstat(&directory)?) == directory_identity,
                    "staging directory was replaced while opening"
                );
                ensure_edge(parent, &name, directory_identity)?;
                // Validate inherited native ACLs before even creating the
                // staging file, and certainly before invoking the writer.
                require_private_directory(&directory)?;
                let content = CString::new("content")?;
                let file = openat_file(
                    &directory,
                    &content,
                    libc::O_RDWR
                        | libc::O_CREAT
                        | libc::O_EXCL
                        | libc::O_NOFOLLOW
                        | libc::O_CLOEXEC,
                    0o600,
                )
                .context("create private staging file")?;
                let stat = fstat(&file).context(
                    "inspect staging file; failure may leave a temporary entry (not a final target)"
                )?;
                Ok((directory, file, Identity::of(&stat)))
            })();
            let (directory, file, identity) = match prepare {
                Ok(prepared) => prepared,
                Err(error) => {
                    // If content creation succeeded but fstat failed, rmdir
                    // fails rather than guessing which file may be removed.
                    let cleanup = (|| -> Result<()> {
                        ensure_edge(parent, &name, directory_identity)?;
                        unlinkat(parent, &name, libc::AT_REMOVEDIR)?;
                        parent
                            .sync_all()
                            .context("flush staging preparation cleanup")?;
                        Ok(())
                    })();
                    return match cleanup {
                        Ok(()) => Err(error),
                        Err(cleanup) => Err(error
                            .context(format!("staging preparation cleanup failed: {cleanup:#}"))),
                    };
                }
            };
            let mut stage = Self {
                parent,
                name,
                directory,
                directory_identity,
                file,
                identity,
                content_removed: false,
                directory_removed: false,
            };
            if let Err(error) = stage.check() {
                return match stage.cleanup() {
                    Ok(()) => Err(error),
                    Err(cleanup) => {
                        Err(error
                            .context(format!("staging validation cleanup failed: {cleanup:#}")))
                    }
                };
            }
            return Ok(stage);
        }
        bail!("unable to allocate a unique staging directory")
    }

    fn check(&self) -> Result<()> {
        ensure_edge(self.parent, &self.name, self.directory_identity)?;
        require_private_directory(&self.directory)?;
        verify_private_file(&self.file)?;
        let file_stat = fstat(&self.file)?;
        require_regular(&file_stat)?;
        ensure!(
            Identity::of(&file_stat) == self.identity,
            "writer replaced the staging file handle"
        );
        let content_stat = statat(&self.directory, &CString::new("content")?)?;
        require_regular(&content_stat)?;
        ensure!(
            stamp(&file_stat)? == stamp(&content_stat)?,
            "staging entry changed during writing"
        );
        ensure!(
            file_stat.st_mode & 0o7777 == 0o600 && file_stat.st_uid == unsafe { libc::geteuid() },
            "writer changed staging file privacy"
        );
        ensure!(
            file_stat.st_nlink == 1,
            "staging file has an unexpected hard link"
        );
        Ok(())
    }

    fn cleanup(&mut self) -> Result<()> {
        if self.directory_removed {
            return Ok(());
        }
        ensure_edge(self.parent, &self.name, self.directory_identity)?;
        if !self.content_removed {
            let content = CString::new("content")?;
            let stat = statat(&self.directory, &content)?;
            ensure!(
                Identity::of(&stat) == self.identity,
                "refusing to remove a replaced staging entry"
            );
            unlinkat(&self.directory, &content, 0)?;
            self.content_removed = true;
            self.directory
                .sync_all()
                .context("flush staging-file cleanup")?;
        }
        ensure_edge(self.parent, &self.name, self.directory_identity)?;
        unlinkat(self.parent, &self.name, libc::AT_REMOVEDIR)?;
        self.directory_removed = true;
        self.parent
            .sync_all()
            .context("flush staging-directory cleanup")?;
        Ok(())
    }
}

impl Drop for Stage<'_> {
    fn drop(&mut self) {
        // Explicit paths report cleanup errors. During unwinding only, best
        // effort is unavoidable; no successful result is returned in that case.
        let _ = self.cleanup();
    }
}

pub(crate) fn ensure_private_directory(path: &Path) -> Result<()> {
    require_durable_platform()?;
    let root = Root::open_impl(path, true)?;
    require_private_directory(root.file())?;
    root.file()
        .sync_all()
        .context("flush private application directory")?;
    root.check()
}

fn require_durable_platform() -> Result<()> {
    ensure!(
        cfg!(any(target_os = "macos", target_os = "linux")),
        "durable writes have not been implemented for this Unix platform"
    );
    Ok(())
}

fn absolute_path(path: &Path) -> Result<PathBuf> {
    let text = path.to_str().context("root path must be UTF-8")?;
    ensure!(
        !text.is_empty() && !text.contains('\0'),
        "invalid root path"
    );
    ensure!(text.len() <= MAX_PATH_BYTES, "root path exceeds path limit");
    ensure!(
        !text.split('/').any(|part| part == "." || part == ".."),
        "root path cannot contain '.' or '..'"
    );
    let path = if path.is_absolute() {
        path.to_path_buf()
    } else {
        std::env::current_dir()
            .context("resolve current directory")?
            .join(path)
    };
    ensure!(
        path.as_os_str().as_bytes().len() <= MAX_PATH_BYTES,
        "absolute root path exceeds path limit"
    );
    Ok(path)
}

fn require_directory(stat: &libc::stat) -> Result<()> {
    ensure!(
        stat.st_mode & libc::S_IFMT == libc::S_IFDIR,
        "entry is not a real no-follow directory"
    );
    Ok(())
}

fn require_regular(stat: &libc::stat) -> Result<()> {
    ensure!(
        stat.st_mode & libc::S_IFMT == libc::S_IFREG,
        "entry is a symlink or unsupported special file"
    );
    ensure!(stat.st_size >= 0, "file has a negative length");
    Ok(())
}

fn require_private(stat: &libc::stat) -> Result<()> {
    require_directory(stat)?;
    ensure!(stat.st_nlink > 0, "private directory is no longer linked");
    ensure!(
        stat.st_uid == unsafe { libc::geteuid() } && stat.st_mode & 0o7777 == 0o700,
        "private directory must be owned by this user with mode 0700"
    );
    Ok(())
}

fn require_private_directory(file: &File) -> Result<()> {
    let before = fstat(file)?;
    require_private(&before)?;
    privacy::reject_extended_acl(file, true)?;
    let after = fstat(file)?;
    require_private(&after)?;
    ensure!(
        stamp(&before)? == stamp(&after)?,
        "private directory changed during native ACL verification"
    );
    Ok(())
}

pub(crate) fn verify_private_file(file: &File) -> Result<()> {
    let before = fstat(file)?;
    let check_metadata = |stat: &libc::stat| -> Result<()> {
        require_regular(stat)?;
        ensure!(
            stat.st_uid == unsafe { libc::geteuid() } && stat.st_mode & 0o7777 == 0o600,
            "private file must be owned by this user with mode 0600"
        );
        ensure!(
            stat.st_nlink == 1,
            "private file must have exactly one native hard link"
        );
        Ok(())
    };
    check_metadata(&before)?;
    privacy::reject_extended_acl(file, false)?;
    let after = fstat(file)?;
    check_metadata(&after)?;
    ensure!(
        stamp(&before)? == stamp(&after)?,
        "private file changed during native ACL verification"
    );
    Ok(())
}

fn ensure_edge(parent: &File, name: &CStr, identity: Identity) -> Result<()> {
    let stat = statat(parent, name)?;
    require_directory(&stat)?;
    ensure!(
        Identity::of(&stat) == identity,
        "directory name was replaced or moved"
    );
    Ok(())
}

fn require_absent(parent: &File, name: &CStr) -> Result<()> {
    match statat(parent, name) {
        Err(error) if error.raw_os_error() == Some(libc::ENOENT) => Ok(()),
        Err(error) => Err(error).context("inspect destination name"),
        Ok(_) => bail!("destination already exists; refusing overwrite"),
    }
}

fn file_from_result(fd: RawFd) -> io::Result<File> {
    if fd < 0 {
        Err(io::Error::last_os_error())
    } else {
        // SAFETY: successful open/openat returns a new owned descriptor.
        Ok(unsafe { File::from_raw_fd(fd) })
    }
}

fn openat_file(
    parent: &File,
    name: &CStr,
    flags: libc::c_int,
    mode: libc::mode_t,
) -> io::Result<File> {
    // SAFETY: parent descriptor and NUL-terminated name are valid for this call.
    file_from_result(unsafe {
        libc::openat(
            parent.as_raw_fd(),
            name.as_ptr(),
            flags,
            mode as libc::c_uint,
        )
    })
}

fn mkdirat(parent: &File, name: &CStr) -> io::Result<()> {
    // SAFETY: valid parent descriptor and name.
    if unsafe { libc::mkdirat(parent.as_raw_fd(), name.as_ptr(), 0o700) } == 0 {
        Ok(())
    } else {
        Err(io::Error::last_os_error())
    }
}

fn unlinkat(parent: &File, name: &CStr, flags: libc::c_int) -> io::Result<()> {
    // SAFETY: valid parent descriptor and name, and flags are 0 or AT_REMOVEDIR.
    if unsafe { libc::unlinkat(parent.as_raw_fd(), name.as_ptr(), flags) } == 0 {
        Ok(())
    } else {
        Err(io::Error::last_os_error())
    }
}

fn fstat(file: &File) -> io::Result<libc::stat> {
    let mut stat = MaybeUninit::uninit();
    // SAFETY: fstat initializes stat on success; descriptor is live.
    if unsafe { libc::fstat(file.as_raw_fd(), stat.as_mut_ptr()) } == 0 {
        Ok(unsafe { stat.assume_init() })
    } else {
        Err(io::Error::last_os_error())
    }
}

fn statat(parent: &File, name: &CStr) -> io::Result<libc::stat> {
    let mut stat = MaybeUninit::uninit();
    // SAFETY: fstatat initializes stat on success; no symlink is followed.
    if unsafe {
        libc::fstatat(
            parent.as_raw_fd(),
            name.as_ptr(),
            stat.as_mut_ptr(),
            libc::AT_SYMLINK_NOFOLLOW,
        )
    } == 0
    {
        Ok(unsafe { stat.assume_init() })
    } else {
        Err(io::Error::last_os_error())
    }
}

fn read_link_at(parent: &File, name: &CStr, relative: &str) -> Result<NativeLinkStamp> {
    let before = statat(parent, name)?;
    ensure!(
        before.st_mode & libc::S_IFMT == libc::S_IFLNK,
        "entry is not a symlink"
    );
    ensure!(
        before.st_size >= 0 && before.st_size <= MAX_PATH_BYTES as _,
        "symlink target exceeds size limit"
    );
    let mut bytes = vec![0u8; MAX_PATH_BYTES + 1];
    // SAFETY: live no-follow parent and one name, with a bounded writable buffer.
    let length = unsafe {
        libc::readlinkat(
            parent.as_raw_fd(),
            name.as_ptr(),
            bytes.as_mut_ptr().cast(),
            bytes.len(),
        )
    };
    if length < 0 {
        return Err(io::Error::last_os_error()).context("read symbolic link without following");
    }
    ensure!(
        length as usize <= MAX_PATH_BYTES,
        "symlink target exceeds size limit"
    );
    bytes.truncate(length as usize);
    let target = String::from_utf8(bytes).context("symlink target is not UTF-8")?;
    validate_link_target(relative, &target)?;
    let after = statat(parent, name)?;
    ensure!(
        after.st_mode & libc::S_IFMT == libc::S_IFLNK && stamp(&before)? == stamp(&after)?,
        "symlink changed while reading its text"
    );
    Ok(NativeLinkStamp {
        stamp: stamp(&after)?,
        target,
        target_is_directory: None,
    })
}

#[cfg(any(target_os = "macos", target_os = "ios"))]
fn modified_time(stat: &libc::stat) -> (i64, i64) {
    (stat.st_mtime, stat.st_mtime_nsec)
}

#[cfg(not(any(target_os = "macos", target_os = "ios")))]
// Normalize libc's time aliases, including narrower supported Unix ABIs.
#[allow(clippy::unnecessary_cast)]
fn modified_time(stat: &libc::stat) -> (i64, i64) {
    (stat.st_mtime as i64, stat.st_mtime_nsec as i64)
}

// Normalize target-specific libc stat integer aliases into the wire stamp.
#[allow(clippy::unnecessary_cast)]
fn stamp(stat: &libc::stat) -> Result<FileStamp> {
    let (modified_seconds, modified_nanoseconds) = modified_time(stat);
    let changed_seconds = stat.st_ctime as i64;
    let changed_nanoseconds = stat.st_ctime_nsec as i64;
    ensure!(
        (0..1_000_000_000).contains(&modified_nanoseconds)
            && (0..1_000_000_000).contains(&changed_nanoseconds),
        "invalid native timestamp"
    );
    Ok(FileStamp {
        device: stat.st_dev as u64,
        file_id: [stat.st_ino as u64, 0],
        size: u64::try_from(stat.st_size).context("negative native file length")?,
        modified_seconds,
        modified_nanoseconds: modified_nanoseconds as u32,
        changed_seconds,
        changed_nanoseconds: changed_nanoseconds as u32,
    })
}

struct DirectoryStream(*mut libc::DIR);

impl Drop for DirectoryStream {
    fn drop(&mut self) {
        // SAFETY: fdopendir transferred ownership to this stream exactly once.
        unsafe { libc::closedir(self.0) };
    }
}

#[derive(Default)]
struct DiscoveryBudget {
    entries: usize,
    path_bytes: usize,
}

fn directory_names(
    directory: &File,
    prefix: &str,
    budget: &mut DiscoveryBudget,
) -> Result<Vec<CString>> {
    // A dup would share the directory's enumeration offset and make a second
    // entries() call silently empty. A fresh openat(".") has an independent one.
    let dot = CString::new(".")?;
    let enumeration = openat_file(directory, &dot, DIR_FLAGS, 0)?;
    let fd = enumeration.into_raw_fd();
    // SAFETY: fd is a freshly owned readable directory descriptor.
    let raw = unsafe { libc::fdopendir(fd) };
    if raw.is_null() {
        let error = io::Error::last_os_error();
        // SAFETY: failed fdopendir did not take descriptor ownership.
        unsafe { libc::close(fd) };
        return Err(error).context("open native directory stream");
    }
    let stream = DirectoryStream(raw);
    let mut names = Vec::new();
    loop {
        clear_errno();
        // SAFETY: stream is live, and readdir's returned buffer is copied before
        // the next call.
        let entry = unsafe { libc::readdir(stream.0) };
        if entry.is_null() {
            let error = io::Error::last_os_error();
            if error.raw_os_error() != Some(0) {
                return Err(error).context("read native directory stream");
            }
            break;
        }
        let name = unsafe { CStr::from_ptr((*entry).d_name.as_ptr()) };
        if name.to_bytes() == b"." || name.to_bytes() == b".." {
            continue;
        }
        budget.entries = budget
            .entries
            .checked_add(1)
            .context("entry count overflow")?;
        budget.path_bytes = budget
            .path_bytes
            .checked_add(name.to_bytes().len())
            .and_then(|bytes| {
                bytes.checked_add(if prefix.is_empty() {
                    0
                } else {
                    prefix.len() + 1
                })
            })
            .context("name size overflow")?;
        ensure!(
            budget.entries <= MAX_TREE_ENTRIES && budget.path_bytes <= MAX_TREE_PATH_BYTES,
            "tree exceeds discovery entry or name-memory limit"
        );
        names.push(name.to_owned());
    }
    Ok(names)
}

#[cfg(any(target_os = "macos", target_os = "ios", target_os = "freebsd"))]
fn clear_errno() {
    // SAFETY: __error returns the current thread's errno pointer.
    unsafe { *libc::__error() = 0 };
}

#[cfg(not(any(target_os = "macos", target_os = "ios", target_os = "freebsd")))]
fn clear_errno() {
    // SAFETY: __errno_location returns the current thread's errno pointer.
    unsafe { *libc::__errno_location() = 0 };
}
