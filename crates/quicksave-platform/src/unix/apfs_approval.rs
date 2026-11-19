// SPDX-License-Identifier: GPL-3.0-only
//! Narrow macOS boot Data-volume namespace proof; not a content/readability
//! check. No directory streams, payload reads, link following, or key inventory.
//!
//! APFS advertises directory-hard-link support through ATTR_VOL_CAPABILITIES.
//! Boot firmlinks originate on the System volume and terminate on Data (Apple,
//! WWDC19 session 710). We require the sealed, read-only System + writable Data
//! layout, explicit absence of directory hard links, no custom/alias mounts,
//! and descriptor-derived NOFIRMLINK paths reopened through pinned native edges.
//! Unknown capabilities/layouts return Unsupported, never "disjoint".
use super::*;

const MAX_MOUNTS: usize = 128;
const PATH_CAP: usize = 1024; // Darwin MAXPATHLEN / F_GETPATH_NOFIRMLINK buffer.
const DIR_HARDLINKS: u32 = 0x0004_0000;
const VOL_GROUPS: u32 = 0x0100_0000;
const SEALED: u32 = 0x0200_0000;
const LOCAL: u32 = libc::MNT_LOCAL as u32;
const READONLY: u32 = libc::MNT_RDONLY as u32;
const UNION: u32 = libc::MNT_UNION as u32;

#[repr(C)]
struct AttrList {
    count: u16,
    reserved: u16,
    common: u32,
    volume: u32,
    directory: u32,
    file: u32,
    fork: u32,
}
#[repr(C)]
#[derive(Default)]
struct VolumeCaps {
    length: u32,
    capabilities: [u32; 4],
    valid: [u32; 4],
}

#[derive(Clone, PartialEq, Eq)]
struct Mount {
    path: Vec<u8>,
    kind: Vec<u8>,
    fsid: [i32; 2],
    flags: u32,
}
#[derive(Clone, PartialEq, Eq)]
struct Volume {
    mount: Mount,
    format: u32,
    valid: u32,
}

impl Root {
    pub(crate) fn apfs_data_overlap_proof(&self, protected: &Self) -> Result<Option<bool>> {
        self.check()?;
        protected.check()?;
        let selected_volume = match volume(self.file())? {
            Some(v) => v,
            None => return Ok(None),
        };
        let protected_volume = match volume(protected.file())? {
            Some(v) => v,
            None => return Ok(None),
        };
        if selected_volume != protected_volume {
            return Ok(None);
        }
        let system = Root::open_metadata(Path::new("/"))?;
        let system_volume = match volume(system.file())? {
            Some(v) => v,
            None => return Ok(None),
        };
        let before_mounts = mounts()?;
        if !supported(&selected_volume, &system_volume, &before_mounts) {
            return Ok(None);
        }

        // Native IDs, not prefix/case/realpath guesses. Reopening the exact
        // kernel path checks every no-follow edge and the original final ID.
        let selected_canonical = match canonical_root(self)? {
            Some(v) => v,
            None => return Ok(None),
        };
        let protected_canonical = match canonical_root(protected)? {
            Some(v) => v,
            None => return Ok(None),
        };
        let data = Root::open_metadata(Path::new("/System/Volumes/Data"))?;
        if volume(data.file())?.as_ref() != Some(&selected_volume) {
            return Ok(None);
        }
        let data_id = Identity::of(&fstat(data.file())?);
        if !selected_canonical
            .ancestors
            .iter()
            .any(|d| d.identity == data_id)
            || !protected_canonical
                .ancestors
                .iter()
                .any(|d| d.identity == data_id)
        {
            return Ok(None);
        }
        let selected_id = Identity::of(&fstat(selected_canonical.file())?);
        let protected_id = Identity::of(&fstat(protected_canonical.file())?);
        let mut parent_names = std::collections::BTreeSet::new();
        let mut portal_parents = Vec::new();
        let mut portal_roots = Vec::new();
        let mut automounter = None;
        for entry in &before_mounts {
            if matches!(entry.path.as_slice(), b"/" | b"/System/Volumes/Data") {
                continue;
            }
            if entry.path == b"/System/Volumes/Data/home" {
                // Metadata of the automounter root only, not lookup of a map
                // key or a child. A symlink/name alias is not an opaque portal.
                let stat = statat(data.file(), c"home")?;
                require_directory(&stat)?;
                let id = Identity::of(&stat);
                if id.device == data_id.device {
                    return Ok(None);
                }
                automounter = Some(id);
                continue;
            }
            let path = Path::new(std::str::from_utf8(&entry.path)?);
            let parent = path.parent().context("invalid boot mount boundary")?;
            if parent_names.insert(parent.to_owned()) {
                let held = Root::open_metadata(parent)?;
                // Firmlinks may skip physical ancestors in the public spelling
                // of /Volumes or another boot mount parent. As with the two
                // approval roots, use its pinned NOFIRMLINK physical ancestry.
                let physical = match canonical_root(&held)? {
                    Some(root) => root,
                    None => return Ok(None),
                };
                if physical
                    .ancestors
                    .iter()
                    .any(|d| d.identity == selected_id || d.identity == protected_id)
                {
                    return Ok(None);
                }
                portal_parents.push((held, physical));
            }
            // Only local built-in filesystem roots admitted by supported().
            // Reopen NOFOLLOW to prove the mount table names the actual vnode,
            // rather than a textual alias to a private mount elsewhere.
            let portal = Root::open_metadata(path)?;
            if filesystem(portal.file())? != *entry {
                return Ok(None);
            }
            portal_roots.push(portal);
        }
        // /home is the only admitted portal whose parent is the Data root
        // itself. Never look up an automounter child. Physical approval-root
        // edges must all remain on Data; a crossing cannot masquerade as an
        // ordinary APFS ancestor.
        for canonical in [&selected_canonical, &protected_canonical] {
            let start = canonical
                .ancestors
                .iter()
                .position(|d| d.identity == data_id)
                .context("native Data ancestry disappeared")?;
            if canonical.ancestors[start..]
                .iter()
                .any(|d| d.identity.device != data_id.device)
            {
                return Ok(None);
            }
        }
        let result = selected_canonical.ancestors_overlap(&protected_canonical);
        ensure!(
            mounts()? == before_mounts,
            "native mount namespace changed during approval"
        );
        ensure!(
            volume(self.file())?.as_ref() == Some(&selected_volume)
                && volume(protected.file())?.as_ref() == Some(&protected_volume)
                && volume(system.file())?.as_ref() == Some(&system_volume),
            "native volume capabilities changed during approval"
        );
        selected_canonical.check()?;
        protected_canonical.check()?;
        data.check()?;
        system.check()?;
        for (parent, physical) in portal_parents {
            parent.check()?;
            physical.check()?;
        }
        for portal in portal_roots {
            portal.check()?;
        }
        if let Some(before) = automounter {
            ensure!(
                Identity::of(&statat(data.file(), c"home")?) == before,
                "native automounter boundary changed during approval"
            );
        }
        self.check()?;
        protected.check()?;
        Ok(Some(result))
    }
}

fn c_bytes(bytes: &[libc::c_char]) -> Result<Vec<u8>> {
    let length = bytes
        .iter()
        .position(|byte| *byte == 0)
        .context("unterminated native mount metadata")?;
    Ok(bytes[..length].iter().map(|byte| *byte as u8).collect())
}

fn mount(stat: &libc::statfs) -> Result<Mount> {
    Ok(Mount {
        path: c_bytes(&stat.f_mntonname)?,
        kind: c_bytes(&stat.f_fstypename)?,
        // Darwin fsid_t is an opaque struct containing two int32 words. No
        // field is interpreted; transmute's size check enforces the SDK ABI.
        fsid: unsafe { std::mem::transmute::<libc::fsid_t, [i32; 2]>(stat.f_fsid) },
        flags: stat.f_flags,
    })
}

fn volume(file: &File) -> Result<Option<Volume>> {
    let fs = filesystem(file)?;
    if fs.kind != b"apfs" {
        return Ok(None);
    }
    let mut attrs = AttrList {
        count: 5,
        reserved: 0,
        common: 0,
        volume: 0x8000_0000 | 0x0002_0000, // ATTR_VOL_INFO | ATTR_VOL_CAPABILITIES
        directory: 0,
        file: 0,
        fork: 0,
    };
    let mut caps = VolumeCaps::default();
    // SAFETY: the documented fixed-size Darwin attrlist/capability layouts,
    // live fd, exact writable capacity, no path or content access.
    let result = unsafe {
        libc::fgetattrlist(
            file.as_raw_fd(),
            (&mut attrs as *mut AttrList).cast(),
            (&mut caps as *mut VolumeCaps).cast(),
            std::mem::size_of::<VolumeCaps>(),
            0,
        )
    };
    if result != 0 || caps.length as usize != std::mem::size_of::<VolumeCaps>() {
        return Ok(None);
    }
    Ok(Some(Volume {
        mount: fs,
        format: caps.capabilities[0],
        valid: caps.valid[0],
    }))
}

fn filesystem(file: &File) -> Result<Mount> {
    let mut fs = MaybeUninit::<libc::statfs>::zeroed();
    // SAFETY: live descriptor and writable native statfs storage.
    if unsafe { libc::fstatfs(file.as_raw_fd(), fs.as_mut_ptr()) } != 0 {
        return Err(io::Error::last_os_error()).context("inspect approval volume metadata");
    }
    let fs = unsafe { fs.assume_init() };
    mount(&fs)
}

fn mounts() -> Result<Vec<Mount>> {
    // MNT_NOWAIT: kernel mount metadata only, no refresh of network filesystems.
    // A fixed buffer avoids unbounded allocation and a count/allocation race.
    let mut raw: Vec<libc::statfs> = (0..MAX_MOUNTS)
        .map(|_| unsafe { std::mem::zeroed() })
        .collect();
    let bytes = std::mem::size_of::<libc::statfs>()
        .checked_mul(raw.len())
        .and_then(|size| i32::try_from(size).ok())
        .context("mount metadata bound exceeded")?;
    let count = unsafe { libc::getfsstat(raw.as_mut_ptr(), bytes, libc::MNT_NOWAIT) };
    ensure!(count >= 0, "native mount metadata is unavailable");
    ensure!(
        (count as usize) < MAX_MOUNTS,
        "native mount table exceeds approval bound"
    );
    let mut result = raw[..count as usize]
        .iter()
        .map(mount)
        .collect::<Result<Vec<_>>>()?;
    result.sort_by(|a, b| a.path.cmp(&b.path));
    ensure!(
        result.windows(2).all(|pair| pair[0].path != pair[1].path),
        "ambiguous native mount metadata"
    );
    Ok(result)
}

fn supported(data: &Volume, system: &Volume, entries: &[Mount]) -> bool {
    support_rejection(data, system, entries).is_none()
}

fn support_rejection(data: &Volume, system: &Volume, entries: &[Mount]) -> Option<&'static str> {
    let required = DIR_HARDLINKS | VOL_GROUPS | SEALED;
    if data.mount.path != b"/System/Volumes/Data"
        || system.mount.path != b"/"
        || data.mount.kind != b"apfs"
        || system.mount.kind != b"apfs"
        || data.mount.fsid == system.mount.fsid
        || data.valid & required != required
        || system.valid & required != required
        || data.format & required != VOL_GROUPS
        || system.format & required != (VOL_GROUPS | SEALED)
        || data.mount.flags & (LOCAL | READONLY | UNION) != LOCAL
        || system.mount.flags & (LOCAL | READONLY | UNION) != (LOCAL | READONLY)
        || entries.iter().filter(|m| m.fsid == data.mount.fsid).count() != 1
        || !entries.contains(&data.mount)
        || !entries.contains(&system.mount)
    {
        return Some("volume_capability_or_mount_identity");
    }
    if !entries.iter().all(admitted_mount_boundary) {
        return Some("additional_mount_boundary");
    }
    None
}

fn admitted_mount_boundary(m: &Mount) -> bool {
    match m.path.as_slice() {
        b"/" | b"/System/Volumes/Data" => m.kind == b"apfs",
        b"/dev" => m.kind == b"devfs",
        b"/System/Volumes/Data/home" => m.kind == b"autofs",
        _ => {
            let Ok(text) = std::str::from_utf8(&m.path) else {
                return false;
            };
            // These strings limit which *public mount parents* may be probed.
            // They do not prove disjointness: held parent/root IDs and actual
            // native mount metadata must still be checked above.
            let system_auxiliary = text.starts_with("/System/Volumes/")
                && !text
                    .get(.."/System/Volumes/Data/".len())
                    .is_some_and(|prefix| prefix.eq_ignore_ascii_case("/System/Volumes/Data/"));
            let local_volume = Path::new(text).parent() == Some(Path::new("/Volumes"));
            // Modern macOS also mounts the immutable PKI trust-store asset on
            // the sealed System namespace. Admit only its exact structural
            // shape and read-only local APFS metadata. As with other portals,
            // the proof still pins/reopens its parent and mount-root vnodes.
            let trust_store =
                text.strip_prefix(
                    "/System/Library/AssetsV2/com_apple_MobileAsset_PKITrustStore/purpose_auto/",
                )
                .and_then(|suffix| suffix.strip_suffix(".asset/.AssetData"))
                .is_some_and(|hash| {
                    hash.len() == 64 && hash.bytes().all(|byte| byte.is_ascii_hexdigit())
                }) && m.flags & (LOCAL | READONLY | UNION) == (LOCAL | READONLY);
            (system_auxiliary || local_volume || trust_store)
                && m.kind == b"apfs"
                && m.flags & (LOCAL | UNION) == LOCAL
        }
    }
}

fn canonical_root(root: &Root) -> Result<Option<Root>> {
    let mut bytes = [0u8; PATH_CAP];
    let result = unsafe { libc::fcntl(root.file().as_raw_fd(), 102, bytes.as_mut_ptr()) };
    if result != 0 {
        return Ok(None);
    } // F_GETPATH_NOFIRMLINK, SDK sys/fcntl.h
    let Some(end) = bytes.iter().position(|byte| *byte == 0) else {
        return Ok(None);
    };
    let Ok(text) = std::str::from_utf8(&bytes[..end]) else {
        return Ok(None);
    };
    let reopened = Root::open_metadata(Path::new(text))?;
    ensure!(
        Identity::of(&fstat(root.file())?) == Identity::of(&fstat(reopened.file())?),
        "descriptor-derived approval path no longer names the pinned directory"
    );
    root.check()?;
    Ok(Some(reopened))
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn immutable_system_trust_store_is_a_pinned_portal_not_a_writable_alias() {
        let path = format!(
            "/System/Library/AssetsV2/com_apple_MobileAsset_PKITrustStore/purpose_auto/{}.asset/.AssetData",
            "a".repeat(64));
        let mount = Mount {
            path: path.as_bytes().to_vec(),
            kind: b"apfs".to_vec(),
            fsid: [8, 0],
            flags: LOCAL | READONLY,
        };
        assert!(admitted_mount_boundary(&mount));
        for flags in [LOCAL, READONLY, LOCAL | READONLY | UNION] {
            assert!(!admitted_mount_boundary(&Mount {
                flags,
                ..mount.clone()
            }));
        }
        for wrong in [
            path.replace("/purpose_auto/", "/other/"),
            path.replace(".asset/.AssetData", ".asset/child"),
            path.replace(&"a".repeat(64), "../../Data"),
            path.replace("/System/Library/", "/System/Volumes/Data/Library/"),
        ] {
            assert!(!admitted_mount_boundary(&Mount {
                path: wrong.into_bytes(),
                ..mount.clone()
            }));
        }
        assert!(!admitted_mount_boundary(&Mount {
            kind: b"smbfs".to_vec(),
            ..mount
        }));
    }
    fn fixture_volumes() -> (Volume, Volume, Vec<Mount>) {
        let valid = DIR_HARDLINKS | VOL_GROUPS | SEALED;
        let data = Volume {
            mount: Mount {
                path: b"/System/Volumes/Data".to_vec(),
                kind: b"apfs".to_vec(),
                fsid: [2, 0],
                flags: LOCAL,
            },
            format: VOL_GROUPS,
            valid,
        };
        let system = Volume {
            mount: Mount {
                path: b"/".to_vec(),
                kind: b"apfs".to_vec(),
                fsid: [1, 0],
                flags: LOCAL | READONLY,
            },
            format: VOL_GROUPS | SEALED,
            valid,
        };
        let entries = vec![data.mount.clone(), system.mount.clone()];
        (data, system, entries)
    }

    #[test]
    fn native_layouts_and_missing_capabilities_are_never_guessed() {
        let (data, system, entries) = fixture_volumes();
        assert!(supported(&data, &system, &entries));
        for bit in [DIR_HARDLINKS, VOL_GROUPS, SEALED] {
            let mut unknown = data.clone();
            unknown.valid &= !bit;
            assert!(!supported(&unknown, &system, &entries));
            let mut unknown = system.clone();
            unknown.valid &= !bit;
            assert!(!supported(&data, &unknown, &entries));
        }
        let mut links = data.clone();
        links.format |= DIR_HARDLINKS;
        assert!(!supported(&links, &system, &entries));
        let mut unsealed = system.clone();
        unsealed.format &= !SEALED;
        assert!(!supported(&data, &unsealed, &entries));
        for (path, kind) in [
            ("/synthetic/alias", "nullfs"),
            ("/synthetic/other", "apfs"),
            ("/Volumes/External", "smbfs"),
            ("/System/Volumes/Data/private/custom", "apfs"),
        ] {
            let mut changed = entries.clone();
            changed.push(Mount {
                path: path.as_bytes().to_vec(),
                kind: kind.as_bytes().to_vec(),
                fsid: [3, 0],
                flags: LOCAL,
            });
            assert!(!supported(&data, &system, &changed));
        }
        let mut duplicate = entries.clone();
        duplicate.push(Mount {
            path: b"/synthetic/data-alias".to_vec(),
            ..data.mount.clone()
        });
        assert!(!supported(&data, &system, &duplicate));
        assert_eq!(std::mem::size_of::<AttrList>(), 24);
        assert_eq!(std::mem::size_of::<VolumeCaps>(), 36);
    }

    #[test]
    fn readonly_union_or_incomplete_mount_facts_cannot_certify_a_data_namespace() {
        let (data, system, entries) = fixture_volumes();
        for flags in [0, LOCAL | READONLY, LOCAL | UNION] {
            let mut changed = data.clone();
            changed.mount.flags = flags;
            let mut mounts = entries.clone();
            mounts[0] = changed.mount.clone();
            assert!(!supported(&changed, &system, &mounts));
        }
        for flags in [0, LOCAL, LOCAL | READONLY | UNION] {
            let mut changed = system.clone();
            changed.mount.flags = flags;
            let mut mounts = entries.clone();
            mounts[1] = changed.mount.clone();
            assert!(!supported(&data, &changed, &mounts));
        }
        assert!(!supported(&data, &system, &entries[..1]));
        assert!(!supported(&data, &system, &entries[1..]));
        for path in [
            "/System/Volumes/Data/hidden",
            "/System/Volumes/data/hidden",
            "/Volumes/External/private",
        ] {
            assert!(!admitted_mount_boundary(&Mount {
                path: path.as_bytes().to_vec(),
                kind: b"apfs".to_vec(),
                fsid: [3, 0],
                flags: LOCAL,
            }));
        }
    }

    #[test]
    fn native_data_proof_never_enumerates_an_opaque_protected_directory() -> Result<()> {
        use std::os::unix::fs::PermissionsExt;
        let base = std::env::temp_dir().canonicalize()?;
        let preferred = base.join("opencode");
        let temporary = tempfile::tempdir_in(if preferred.is_dir() { preferred } else { base })?;
        let selected_path = temporary.path().join("selected");
        let protected_path = temporary.path().join("protected");
        let blocked = protected_path.join("id_rsa");
        std::fs::create_dir(&selected_path)?;
        std::fs::create_dir_all(&blocked)?;
        std::fs::set_permissions(&blocked, std::fs::Permissions::from_mode(0o000))?;
        let selected = Root::open(&selected_path)?;
        let protected = Root::open(&protected_path)?;
        let proof = selected.apfs_data_overlap_proof(&protected);
        // Restore no permissions: remove the empty synthetic denied directory
        // through its writable fixture parent before asserting the result.
        std::fs::remove_dir(&blocked)?;
        let dv = volume(selected.file())?;
        let sv = volume(Root::open(Path::new("/"))?.file())?;
        let admitted = match (&dv, &sv) {
            (Some(d), Some(s)) => supported(d, s, &mounts()?),
            _ => false,
        };
        let rejection = match (&dv, &sv) {
            (Some(d), Some(s)) => support_rejection(d, s, &mounts()?),
            _ => Some("volume_capabilities_unavailable"),
        };
        let additional = mounts()?
            .iter()
            .filter(|m| !admitted_mount_boundary(m))
            .take(8)
            .map(|m| {
                let path = std::str::from_utf8(&m.path).unwrap_or("<native path>");
                let label =
                    if path.starts_with("/System/") && !path.starts_with("/System/Volumes/Data/") {
                        path.to_owned()
                    } else {
                        "<non-system mount>".into()
                    };
                (label, String::from_utf8_lossy(&m.kind).into_owned())
            })
            .collect::<Vec<_>>();
        let volume_identity = match (&dv, &sv) {
            (Some(d), Some(s)) => Some((
                d.mount.path == b"/System/Volumes/Data",
                s.mount.path == b"/",
                d.mount.flags,
                s.mount.flags,
                mounts()?.iter().filter(|m| m.fsid == d.mount.fsid).count(),
                mounts()?.contains(&d.mount),
                mounts()?.contains(&s.mount),
            )),
            _ => None,
        };
        // Boot layout is a real runtime precondition, not an invariant of the
        // CPU or OS label. Extra mounts MUST retain Unsupported (None), not
        // acquire a fabricated disjointness proof just to satisfy CI.
        assert_eq!(proof?,admitted.then_some(false),
            "native proof unavailable: data-capabilities={:?}, system-capabilities={:?}, layout-admitted={admitted}, rejection={rejection:?}, volume-identity={volume_identity:?}, additional={additional:?}",
            dv.as_ref().map(|v|(v.format,v.valid)),sv.as_ref().map(|v|(v.format,v.valid)));
        assert_eq!(
            selected.apfs_data_overlap_proof(&selected)?,
            admitted.then_some(true)
        );
        let child_path = selected_path.join("child");
        std::fs::create_dir(&child_path)?;
        let child = Root::open(&child_path)?;
        assert_eq!(
            selected.apfs_data_overlap_proof(&child)?,
            admitted.then_some(true)
        );
        std::fs::rename(&selected_path, temporary.path().join("moved"))?;
        assert!(selected.apfs_data_overlap_proof(&protected).is_err());
        Ok(())
    }
}
