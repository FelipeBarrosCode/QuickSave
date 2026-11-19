<!-- SPDX-License-Identifier: GPL-3.0-only -->
# Non-enumerating macOS approval proof

This is **directory-overlap approval**, not file readability, app consistency,
capture completion, provider authentication, or permission to mark anything Saved.

## Supported, measured conditions

`SafeRoot::overlaps_for_approval` first tries a narrow native proof on macOS:

- Selected and protected handles identify the same local writable boot APFS Data
  filesystem, mounted once at `/System/Volumes/Data`.
- The native System root is a different, read-only sealed APFS group volume.
- `fgetattrlist(ATTR_VOL_CAPABILITIES)` explicitly reports the relevant format
  bits **valid**, including **no directory hard links**. A filesystem name alone
  is insufficient.
- `fcntl(F_GETPATH_NOFIRMLINK)` returns each held root's physical namespace path.
  It is reopened with no-follow metadata-only native descriptors and its final
  device/object ID must equal the original. Native ancestor IDs prove both roots
  belong to Data; no lexical prefix or application name proves disjointness.
- A bounded `getfsstat(MNT_NOWAIT)` snapshot accounts for namespace portals.
  Only native local APFS mounts with public boot/volume parents, the System
  `devfs`, and the known opaque boot automounter boundary are eligible.
  NULLFS, FUSE, remote/private mount layouts, duplicate Data mounts, missing
  capabilities, union mounts, and unrepresentable metadata do not get a negative
  overlap answer from this proof.
- Admitted local mount roots and their parents are held by **O_EVTONLY** metadata
  descriptors. Each kernel record must name the actual no-follow mounted root;
  its parent's native ancestry must not place a portal inside either subtree.
  No remote filesystem or automounter child is opened.
- Mount snapshots, volume capabilities, and pinned namespace edges are checked
  again before returning.

APFS's native absence of directory hard links gives its physical Data namespace
single-parent directory ancestry. Boot firmlinks originate on System and lead to
Data, so physical descriptor paths remove their alternative boot spelling.
Checking namespace portals is essential: ancestor IDs alone are **not** a
general proof on filesystems with directory hard links or bind-style mounts.

The proof reads only filesystem/root/mount metadata; it does not list `.ssh`,
open its descendants, read link targets or key bytes, alter permissions, or
perform a Keychain operation. A denied protected child does not need approval.
Source indexing/capture still applies all existing file/link, stable-handle,
resource, ownership, and cryptographic checks.

## Unsupported conditions

If these conditions cannot be established, the existing complete bounded
directory-ID census remains the fallback. A denied or incomplete census still
fails closed. This does **not** promise that every Mac volume/mount layout can be
approved without a census. Other platforms retain their native census behavior.

The proof is not an atomic mount lock. Native capture/publication guards and
dirty/gap handling remain mandatory if topology or contents change later.

## Sources and validation

- [Apple WWDC19 session 710](https://developer.apple.com/videos/play/wwdc2019/710):
  boot firmlinks traverse from System directories to Data directories.
- Darwin SDK `sys/attr.h`: `ATTR_VOL_CAPABILITIES`,
  `VOL_CAP_FMT_DIR_HARDLINKS`, `VOL_CAP_FMT_VOL_GROUPS`, `VOL_CAP_FMT_SEALED`,
  capability validity masks and fixed result layout.
- Darwin SDK `sys/fcntl.h`: `F_GETPATH_NOFIRMLINK`.
- Darwin SDK `sys/mount.h`: native mount identifiers, flags and `getfsstat`.

Native fixtures use temporary directories, including a mode-000 synthetic
`protected/id_rsa` directory. They compare the failing census with the successful
approval proof, test native containment and replacement, and verify actual
container-child metadata indexing with zero selected payload bytes/hashes.
Pure negative tests reject missing capability bits, directory-hard-link support,
unsealed/ambiguous volume facts and unknown/alias mount boundaries. Real remote,
NULLFS, privileged mount mutation, and other-OS execution are not acceptance
claims of this checkpoint.
