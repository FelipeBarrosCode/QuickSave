# Initial implementation status — November 17, 2026

QuickSave is a separate local Git repository. The No Land desktop, Android,
iOS and source worktree were not moved, edited, reset, merged or released.
No production machine, cloud repository, credential store or backup was used.

## Implemented and locally checked

- Minimal Tauri/React desktop and an independently runnable CLI.
- Encrypted, additive local-folder snapshots; no automatic pruning/deletion.
- Bounded upstream-equivalent FastCDC/BLAKE3 content processing.
- Reviewed-library XChaCha20-Poly1305/HKDF with a version-2 envelope identifier
  bound into every record, preventing cross-generation record splicing.
- Handle-confined macOS/Linux filesystem writes, source/tree revalidation,
  native overlap checks, no-clobber publication and native ACL privacy checks.
- External recovery-key files; no key bytes in webview state or operation logs.
- Empty-destination restore with complete content preflight. Late failures
  retain already published new files; whole-tree rollback is not implemented.
- Exact-scope, expiring one-use native approvals and bounded worker admission.
- Read-only macOS/Linux/Steam metadata discovery and declarative integration
  descriptions. Discovery does not authorize application backup.
- An unmodified, hash-verified upstream reference with provenance/license notes.
- Native CI recipes, a porting roadmap and explicit unsupported-capability gates.

## Recorded validation

| Check | Actual result | What it does not prove |
| --- | --- | --- |
| macOS workspace tests | **134 passed**, one child-process-only helper marked ignored and exercised by its parent test | Native Windows/Linux execution or all application types |
| Capacity fixture | **186,735 entries**, in-memory serialization/deserialization passed within unchanged document guards | A 34 GiB filesystem benchmark |
| Built macOS CLI smoke | **15 commands passed**, both snapshot versions restored byte-for-byte | Cloud transfer, installed-app reconstruction or launchability |
| Frontend | **56 tests passed**, typecheck/production Vite build passed | Actual native dialogs, visual review or packaged UX |
| Python verification | **28 tests passed**; all **227 upstream files** verified unchanged | A complete third-party/license/SBOM audit |
| macOS core and backend | Strict Clippy/checks passed with `-D warnings` | Linked GUI runtime, signing, installer or update acceptance |
| Linux cross-target | Workspace/all-target strict Clippy passed | Execution on a Linux machine/filesystem |
| Windows cross-target | Workspace/all-target strict Clippy passed after reclaiming only QuickSave compiler caches | Native Windows execution; writes remain unsupported regardless of compilation result |

The browser visual check could not connect to Chrome. No native GUI dialog flow,
installer, signed bundle, live cloud provider or Windows/Linux runtime acceptance
has been claimed. Disposable compiler caches may be cleaned to keep the host
usable; logs and an optional tested macOS CLI are retained under ignored
`artifacts/`. No No Land cache or existing user backup was removed.

## Not yet implemented

1. Native Windows durable writes and private ACL creation/verification.
2. Cloud transport/OAuth and native key-vault integration.
3. Automatic complete-application backup/restore, installer/registry/prerequisite
   reconstruction and certified cross-OS save mappings.
4. Filesystem observers, process-aware automation and a standalone login worker.
5. VSS/APFS/Btrfs application-consistency integrations.
6. Original permissions, ACLs, xattrs, symlink and hardlink fidelity.
7. Overwrite restore with crash-safe rollback and resumable capture/restore.
8. Compression, optimized multi-file packs and the full upstream parallel data
   pipeline. The initial local engine is intentionally not advertised as
   performance-equivalent to the optimized remote engine.
9. Native packaging/signing/updater acceptance and production-scale benchmarks.
10. Final owner/license review of the GPL-root/MIT-workspace source discrepancy.

These are genuine implementation gates, not working features hidden behind UI
labels. Follow [PORTING-PLAN.md](PORTING-PLAN.md) for the remaining milestones.
The existing No Land repositories and their cloud behavior are not changed by
QuickSave's new format or policy.
