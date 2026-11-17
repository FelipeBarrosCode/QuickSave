# Platform support and acceptance

**Target platforms are Windows, macOS and Linux. Targeting an OS, compiling on it
and accepting native behavior are three different states.** The first slice is
explicit-folder/local-repository only. Read the running application's capability
report; unavailable native operations must return an explicit unsupported error.

The CI definitions are future execution recipes, not evidence of completed runs.
No Windows/Linux native acceptance or signed/packaged acceptance is established
by local macOS development.
The parent reports an interim macOS backend check, 23 macOS platform tests and
Windows/Linux library cross-checks. Subsequent security hardening still requires
revalidation; see [the checkpoint](VALIDATION.md#security-review-checkpoint-not-final-acceptance).

## Current boundary

| Surface | Initial scope | Not implied |
| --- | --- | --- |
| Content algorithms | Native-independent bounded hashing/chunking/authentication | Whole upstream engine or repository compatibility |
| Native filesystem | Platform adapter contract for pinned roots, regular-file capture and new-file restore | Every OS/filesystem, links, metadata fidelity or network volumes |
| CLI / desktop | Initialize, explicit folder backup, list, empty-target restore with external key file | Background service, scheduling, cloud or app-aware full restore |
| Directories / capabilities | Non-secret native discovery and truthful availability | Permission to recursively back up discovered locations |
| UI build | Frontend compilation | Tauri backend compilation, installer behavior or native safety |

If a platform adapter is not complete, its report and error path must say so.
Tests may skip a positive fixture only for a **specific asserted unavailable
capability**, while still testing the unsupported refusal. Do not blanket-skip an
OS or mark a missing capability as a successful backup.

The current Windows adapter reports handle-anchored reads/identity checks, but
**durable new-file/directory writes and private ACL creation are unsupported**.
Consequently Windows backup/restore and desktop-operation persistence are not
accepted capabilities. The CLI smoke verifies explicit initialization refusal
there rather than treating it as a successful Windows round trip.
The macOS private-secret policy is being hardened to reject extended ACLs before
secret-writing callbacks and to verify imported keys through
`verify_private_file`. Native `same_root`/`overlaps`/`contains_file_identity`
checks are also in progress. These APIs are not accepted on all platforms merely
because earlier tests or library cross-checks passed.

## Adapter roadmap

| Area | Windows | macOS | Linux |
| --- | --- | --- | --- |
| Confined filesystem access | Native handles, reparse-tag/ancestor refusal, file-ID/volume identity, exclusive publication | Descriptor-relative no-follow access, device/inode identity, safe publication and directory sync | Descriptor-relative no-follow access, device/inode identity, safe publication and directory sync |
| Paths/directories | Known Folders; drive/device/UNC, reserved names, ADS and case rules | User-selected directories, Application Support/container roots, Unicode/case collisions and TCC | XDG configuration/data/state roots, case-sensitive names, explicit non-UTF-8 policy |
| Change tracking (planned) | ReadDirectoryChangesW; optional reviewed USN support | FSEvents/kqueue with gaps and remount handling | inotify/fanotify where authorized; bounded overflow/restart recovery |
| Process evidence (planned) | OS process creation identity; no PID-only trust | Native process identity subject to permissions | `/proc` identity/cgroups only where supported and authorized |
| Secret vault (planned) | Credential Manager/DPAPI design and scope review | Keychain with QuickSave-specific service/account identifiers | Secret Service; explicit unavailable/locked-session behavior |
| Consistency (planned) | VSS only with required privileges and tested lifecycle | Reviewed APFS/application-quiescence capability, not “copy equals snapshot” | Btrfs/reflink/quiescence only when filesystem and permissions qualify |
| Packaging (planned) | Installer, runtime dependencies, upgrade/uninstall tests, authorized signing | App bundle, entitlements/TCC, upgrade tests, authorized signing/notarization | Chosen package formats and distro/WebKit dependencies, upgrade tests |

This table describes adapter requirements, not shipped integrations. The platform
agent's implemented capability flags and native test evidence decide availability.

## Required native evidence

For each supported OS/version/filesystem combination, record:

1. OS/version/architecture/filesystem, toolchain, source revision and exact commands.
2. Successful local encrypted round trip with byte-for-byte verification.
3. Rejection of links/reparse points at leaves and ancestors, traversal, root
   replacement, case aliases/collisions and source/repository/key overlap.
4. Existing destination preservation, empty-target preflight and racing new-file
   creation; partial-restore behavior under disk-full/permission failure.
5. Wrong-key, corrupt/truncated/oversized manifest/content and foreign-repository
   refusal, with no successful unverified publication.
6. Actual durable-publication/restart fault tests appropriate to the supported
   native primitives; compilation alone cannot certify power-loss behavior.
7. Native GUI file/key dialogs and backend execution separately from frontend
   compilation; packaged permission behavior separately from a development app.

Case folding and normalization must be checked on the actual target volume.
Reject unsupported metadata/filenames instead of claiming a faithful restore.
Network shares, cloud-sync folders, FAT/exFAT and privilege-dependent snapshots
require their own evidence; a local APFS fixture cannot certify them.

## CI scope

`.github/workflows/ci.yml` runs workspace tests on `windows-latest`,
`macos-latest` and `ubuntu-latest`, with formatting/lint and frontend checks.
The tests use `-- --test-threads=1` to bound simultaneous memory-heavy fixtures.
An optional, manually selected native Tauri-check job installs Linux WebKit
dependencies and checks the separate desktop manifest on all three runners.
It does not sign, package, release, deploy or touch a live provider.
