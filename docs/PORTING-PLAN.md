# QuickSave port plan

This is the durable handoff for a **new, separate** desktop backup application.
The reference is the local, read-only No Land snapshot recorded in
[`upstream/SOURCE.json`](../upstream/SOURCE.json), not a running service or an
existing user's repository. Do not modify any No Land checkout or worktree.

## Product boundary and current scope

The long-term product is user-controlled backup and versioned recovery of folders,
application state and selected game saves on Windows, macOS and Linux. Local and
optional cloud repositories share a reviewed content engine. Profiles, discovery,
watchers and scheduling should make a safe operation easier, not expand its scope
without consent.

**The initial implementation is only a vertical slice:** explicit folder selection,
a local encrypted QuickSave repository, additive snapshots, an external recovery-key
file, snapshot listing and restore into an approved **empty** directory. CLI and
desktop UI must use the same native safety boundary. A successful folder capture is
validated stable-file capture, **not application-wide atomic consistency**.

This document describes acceptance gates, not a claim that all gates have passed.
In particular, cloud uploads, automatic tracking, usable app/game profiles,
application-consistent capture, overwrite/rollback restore, native credential
vaults, packaging and all three operating systems' native acceptance remain
separate work. See [platform status](PLATFORM-SUPPORT.md) and
[validation](VALIDATION.md). A capability report or an explicitly unsupported API
is not implementation of that capability.

The current security-review increment adds exact-scope native desktop approval,
handle/file-identity alias and ACL checks, and an independently versioned
anti-splicing envelope. These changes require post-change revalidation; prior
compilation/test counts are interim evidence only, not completion of a phase.

## Port rather than transplant

1. Preserve the snapshot and its notices; record each derived algorithm.
2. Extract portable content algorithms behind new QuickSave APIs.
3. Replace Linux/cloud-agent assumptions with per-OS desktop adapters.
4. Create a new, versioned repository namespace. Do **not** imply existing No Land
   repository compatibility or point the new application at production storage.
5. Keep historical snapshots additive. Do not import upstream one-current-bundle,
   automatic generation retirement, reclamation or cloud deletion behavior.
6. Move decisions into an inspectable engine. The UI presents real capabilities,
   errors and results; it does not simulate a successful backup.

The detailed [reuse matrix](REUSE-AND-LICENSE.md) identifies local source evidence
and the unresolved GPL-root/MIT-workspace licensing conflict.

## Phases and exit criteria

| Phase | Deliverable | Exit criterion |
| --- | --- | --- |
| 0 — isolation and provenance | New workspace, copied read-only reference, GPL-3.0-only new code pending review, dependency boundary checks | Pinned reference digest verifies; no production state, remote services or vendor runtime dependency |
| 1 — first local slice | Native-safe explicit-folder capture, bounded chunking/authentication, immutable commit, external-key CLI, minimal desktop flow | Wrong-key/corruption/path/overlap/overwrite refusal tests, isolated round trip, source-change rejection; unsupported OS paths fail closed |
| 2 — native filesystem acceptance | Complete Windows, macOS and Linux adapters; explicit metadata/filename policy | Native race, reparse/symlink, locking, crash and permission fixtures on each supported OS/filesystem; no cross-compile substitution |
| 3 — secret lifecycle | Windows credential protection, macOS Keychain, Linux Secret Service; offline recovery workflow | Locked/missing vault fails safely; export/import verification and key-loss drill; no plaintext settings or webview keys |
| 4 — app/game profiles | Versioned, user-reviewed root mappings; allowlisted discovery; app-close guidance | Synthetic per-OS profiles recover only selected roots, detect ownership uncertainty, preserve unsupported-state diagnostics |
| 5 — observation and scheduling | Per-OS change/process signals, persisted dirty epochs, resumable job state | Lost/overflowed/restarted watcher forces reconciliation; cancellation drains work; no “unchanged” proof from silence |
| 6 — optional cloud transport | Isolated credentialed rclone/provider adapters and additive authenticated commits | Local-provider fault fixtures, bounded subprocess output, remote-root identity and conflict tests; live provider tests only with separate authorization |
| 7 — transactional full restore | Preflight, dry-run conflict preview, durable rollback journal and restart recovery | Kill/fault injection at every publication barrier; existing data survives cancellation, disk-full and crash; explicit destructive consent |
| 8 — release readiness | Native installers, accessibility, signing/update design, migration and recovery documentation | License review, OS-specific packaged acceptance, reproducible test evidence, recovery drill; no release/signing resource use without authorization |

Phase 1 is intentionally useful without the later phases. Do not report a scaffold,
an adapter enum or a successful frontend build as completion of phases 2–8.

## Implementation workstreams

- **Platform:** pinned filesystem handles, native identity and metadata, directory
  discovery, path rules, capability reporting, later watcher/vault/snapshot APIs.
- **Content:** FastCDC/BLAKE3 fixture equivalence, reviewed AEAD/HKDF, zeroizing key
  ownership and record limits. Compression/packing is a separate bounded-format
  change, not permission to increase global metadata limits.
- **Engine:** repository identity, safe namespace, capture validation, commit-last
  publication, authenticated manifest validation, additive enumeration and restore.
- **Integrations:** profile schemas, app/game discovery, provider configuration and
  future native secret references. No service deployment or live credentials.
- **Desktop/CLI:** external key-file selection, operation admission, off-UI-thread
  work and actual terminal status. Desktop key/data operations require exact-scope
  native approval with a bounded expiring single-use token; the CLI API remains
  explicit invocation. No fake percent, remote control or key exposure.
- **Validation/docs:** native matrix, isolated adversarial fixtures, provenance,
  explicit limitations and release review. Keep API coordination in
  [the implementation contract](IMPLEMENTATION-CONTRACT.md).

## Decisions to preserve during the full port

- **Repository and paths:** independent format version, authenticated repository
  identity and record context; logical roots plus a versioned OS/path model rather
  than replaying another computer's absolute paths. See [architecture](ARCHITECTURE.md).
- **Restore is not installation:** copying files does not reinstall services,
  registry state, drivers, entitlements, launchers, licensed binaries or credentials.
  A profile must disclose exclusions and prerequisites; cross-OS restore is not
  automatic path translation.
- **Credentials:** CLI key material stays in an explicit external file until native
  vault support is accepted. Future provider tokens and repository keys use
  QuickSave-specific vault namespaces, never No Land's state/vault namespace.
- **Recovery:** a vault is not a backup. Require a verified external recovery copy,
  warn that a lost key means lost access, and design rotation/wrapping as a new
  reviewed format operation rather than rewriting history opportunistically.
- **Retention:** all committed history remains available. Show storage growth.
  Any eventual deletion/GC needs a separately approved policy, authenticated
  reference inventory, conflict/recovery protocol and explicit consent; it is not
  authorized by this plan.
- **Performance:** measure whole-operation time, memory, scratch disk and integrity
  on synthetic workloads. Deduplication does not mean “no reads”; uploaded bytes
  do not mean manifest publication is complete. No unmeasured speed or capacity
  promise.

## Handoff checklist

Before extending a phase, identify its native API, bounded resources, untrusted
inputs, recovery behavior and acceptance tests. Update the capability report and
limitations together. Record exact commands, host OS and skipped tests. Never
replace “not implemented” with success, and never inherit upstream test counts or
production acceptance as QuickSave evidence.
