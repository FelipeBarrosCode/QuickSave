// SPDX-License-Identifier: GPL-3.0-only
//! Directory-only, handle-relative approval census. No payload descriptor,
//! readlink, timestamp comparison, UTF-8 requirement, or permission repair.

use super::*;
use crate::overlap::{with_census_location, CensusBudget};

#[derive(PartialEq, Eq)]
struct Child {
    name: CString,
    identity: Identity,
}

impl Root {
    pub(crate) fn visit_directory_identities(
        &self,
        visit: &mut impl FnMut(&[u8], DirectoryIdentity) -> Result<()>,
    ) -> Result<()> {
        let mut parent = Parent {
            root: self,
            descendants: Vec::new(),
        };
        let mut relative = Vec::new();
        let result = walk(
            &mut parent,
            &mut relative,
            &mut CensusBudget::default(),
            &mut CensusBudget::default(),
            visit,
        );
        self.check()?;
        with_census_location(
            result.with_context(|| {
                format!(
                    "directory-identity census at {:?}",
                    String::from_utf8_lossy(&relative)
                )
            }),
            &relative,
        )
    }
}

fn walk(
    parent: &mut Parent<'_>,
    relative: &mut Vec<u8>,
    discovery: &mut CensusBudget,
    confirmation: &mut CensusBudget,
    visit: &mut impl FnMut(&[u8], DirectoryIdentity) -> Result<()>,
) -> Result<()> {
    let label = || format!("directory {:?}", String::from_utf8_lossy(relative));
    parent.check().with_context(label)?;
    let before = fstat(parent.file())?;
    require_directory(&before)?;
    let identity = Identity::of(&before);
    visit(
        relative,
        DirectoryIdentity {
            device: identity.device,
            file_id: [identity.inode, 0],
        },
    )?;
    let children = directory_children(parent.file(), relative, discovery).with_context(|| {
        format!(
            "enumerate directory {:?}",
            String::from_utf8_lossy(relative)
        )
    })?;
    for child in &children {
        ensure!(
            parent.descendants.len() < MAX_DEPTH,
            "directory-identity census exceeds depth limit at {:?}",
            String::from_utf8_lossy(relative)
        );
        let length = relative.len();
        if length != 0 {
            relative.push(b'/');
        }
        relative.extend_from_slice(child.name.to_bytes());
        parent.check()?;
        let namespace = statat(parent.file(), &child.name).with_context(|| {
            format!(
                "inspect directory edge {:?}",
                String::from_utf8_lossy(relative)
            )
        })?;
        require_directory(&namespace)?;
        ensure!(
            Identity::of(&namespace) == child.identity,
            "directory replaced after identity enumeration at {:?}",
            String::from_utf8_lossy(relative)
        );
        // A directory graph cycle is not disjointness, nor a reason to recurse
        // forever. Repeated IDs on separate branches remain in the inventory.
        ensure!(
            child.identity != parent.root.ancestors.last().unwrap().identity
                && parent
                    .descendants
                    .iter()
                    .all(|ancestor| ancestor.identity != child.identity),
            "directory alias cycle during identity approval at {:?}",
            String::from_utf8_lossy(relative)
        );
        let file = openat_file(parent.file(), &child.name, DIR_FLAGS, 0).with_context(|| {
            format!(
                "open read-only no-follow directory {:?}",
                String::from_utf8_lossy(relative)
            )
        })?;
        let opened = fstat(&file)?;
        require_directory(&opened)?;
        ensure!(
            Identity::of(&opened) == child.identity,
            "directory changed while opening at {:?}",
            String::from_utf8_lossy(relative)
        );
        ensure_edge(parent.file(), &child.name, child.identity)?;
        parent.descendants.push(Directory {
            file,
            identity: child.identity,
            name: Some(child.name.clone()),
        });
        walk(parent, relative, discovery, confirmation, visit)?;
        parent.check()?;
        parent.descendants.pop();
        relative.truncate(length);
        ensure_edge(parent.file(), &child.name, child.identity)?;
    }
    parent.check()?;
    let after = directory_children(parent.file(), relative, confirmation).with_context(|| {
        format!(
            "recheck directory children {:?}",
            String::from_utf8_lossy(relative)
        )
    })?;
    ensure!(
        after == children,
        "directory children changed during identity approval at {:?}",
        String::from_utf8_lossy(relative)
    );
    parent.check()?;
    Ok(())
}

fn directory_children(
    directory: &File,
    prefix: &[u8],
    budget: &mut CensusBudget,
) -> Result<Vec<Child>> {
    // Fresh readable descriptor: dup() would share an enumeration offset.
    let enumeration = openat_file(directory, c".", DIR_FLAGS, 0)?;
    ensure!(
        Identity::of(&fstat(directory)?) == Identity::of(&fstat(&enumeration)?),
        "directory stream identity changed"
    );
    let fd = enumeration.into_raw_fd();
    // SAFETY: fd is owned and readable; successful fdopendir owns it.
    let stream = unsafe { libc::fdopendir(fd) };
    if stream.is_null() {
        let error = io::Error::last_os_error();
        unsafe { libc::close(fd) };
        return Err(error).context("open directory-identity stream");
    }
    let stream = DirectoryStream(stream);
    let mut children = Vec::new();
    loop {
        clear_errno();
        // SAFETY: the native buffer is copied before the next readdir call.
        let entry = unsafe { libc::readdir(stream.0) };
        if entry.is_null() {
            let error = io::Error::last_os_error();
            if error.raw_os_error() != Some(0) {
                return Err(error).context("read directory-identity stream");
            }
            break;
        }
        let entry = unsafe { &*entry };
        let name = unsafe { CStr::from_ptr(entry.d_name.as_ptr()) };
        if name.to_bytes() == b"." || name.to_bytes() == b".." {
            continue;
        }
        budget.entry(prefix.len(), name.to_bytes().len())?;
        // d_type is only a directory-entry hint, not alias/topology authority
        // (notably for filesystem-specific directory aliases). Inspect kind
        // with fstatat(NO_FOLLOW), but never stamp or open a non-directory.
        let stat = match statat(directory, name) {
            Ok(stat) => stat,
            Err(error)
                if entry.d_type != libc::DT_DIR && error.kind() == io::ErrorKind::NotFound =>
            {
                // No directory was observed. A transient file disappearing is
                // not an approval failure; both directory censuses still have
                // to agree. Known directory disappearance always fails.
                continue;
            }
            Err(error) => {
                return Err(error).with_context(|| {
                    format!(
                        "classify native child under {:?} named {:?}",
                        String::from_utf8_lossy(prefix),
                        name
                    )
                });
            }
        };
        if entry.d_type == libc::DT_DIR {
            require_directory(&stat).context("enumerated directory changed native type")?;
        }
        if stat.st_mode & libc::S_IFMT != libc::S_IFDIR {
            // Even escaping links, sockets, or unreadable regular files have no
            // directory edge here. No payload or link target was opened/read.
            continue;
        }
        ensure!(
            !name.to_bytes().is_empty()
                && name.to_bytes().len() <= 255
                && !name.to_bytes().contains(&b'/'),
            "invalid native directory component"
        );
        budget.directory(prefix.len() + usize::from(!prefix.is_empty()) + name.to_bytes().len())?;
        children.push(Child {
            name: name.to_owned(),
            identity: Identity::of(&stat),
        });
    }
    children.sort_unstable_by(|left, right| left.name.as_bytes().cmp(right.name.as_bytes()));
    ensure!(
        children.windows(2).all(|pair| pair[0].name != pair[1].name),
        "duplicate native directory name during identity approval"
    );
    Ok(children)
}
