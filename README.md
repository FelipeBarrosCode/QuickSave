# QuickSave

**Encrypted, versioned backups for the computer you are using.**

QuickSave is a new, standalone native desktop application for Windows, macOS,
and Linux. It is being extracted from No Land's Shared Storage engine, with
native platform adapters instead of SSH and remote Linux provisioning.

> **Development preview, not a production release.** The software/provider
> workspace revision uses **Overview, Backup and Restore**, non-secret
> `state.json` settings, native vault references and a separate No Land library
> fork. The binding requirement is the
> [whole optimized Shared Storage contract](docs/FULL-SHARED-STORAGE-CONTRACT.md).
> See [current integration status](docs/SHARED-STORAGE-INTEGRATION-STATUS.md) and
> [optimization evidence](docs/OPTIMIZATIONS-PARITY.md) for measured results and
> unresolved gates. The older workspace-v2 acceptance record is historical;
> source integration or provider definitions do not establish full feature parity.
>
> The earlier explicit local-folder CLI remains a separate implementation with
> a **different QuickSave repository/envelope format** and external recovery-key
> files. Its successful tests do not establish No Land bundle interoperability.

The [initial local-engine status](docs/IMPLEMENTATION-STATUS.md) and
[original porting plan](docs/PORTING-PLAN.md) remain historical context, not
acceptance of the new workspace revision.

## Independence and safety

- No Land remains in its original repository and directory. Nothing is moved.
- `upstream/no-land/` is an attributed, unmodified source reference pinned to
  `e81238a7536aae201540956ce76981364fd36595`.
- `shared-storage/` is the separate active, provenance-tracked library fork;
  no provisioning, remote-agent deployment or lifecycle execution is authorized.
- QuickSave never implicitly connects to existing No Land cloud storage or loads
  No Land credentials, runtime databases, or application state.
- No automatic source deletion, cloud retirement or version pruning is allowed.
  Workspace-v2 explicit cloud deletion requires a fresh frozen preview, native
  confirmation and separate dependent-backup acknowledgement.
- No Land import is an explicit native-consented, read-only source import into
  QuickSave's own vault. Development/tests never use actual No Land state or
  live credential stores.
- A file copy is **not** advertised as an application-consistent snapshot.

## Repository

```text
apps/desktop/                 Tauri + React desktop application
crates/quicksave-cli/         Explicit local CLI
crates/quicksave-client/      Shared key-file and owned-operation control
crates/quicksave-control/     Exact-scope approvals and bounded native worker admission
crates/quicksave-engine/      Encrypted repository, snapshot, backup and restore
crates/quicksave-content/     Bounded chunking, hashing and authenticated encryption
crates/quicksave-platform/    Native paths, identity and confined filesystem IO
crates/quicksave-integrations/Read-only discovery and integration capability models
crates/quicksave-state/       Workspace settings, provider references and native vault boundary
crates/quicksave-tracking/    Approved software roots, reconciliation and opt-in autosave
crates/quicksave-observation/ Scoped native process/file-use evidence and uncertainty
crates/quicksave-noland/      Private native Shared Storage library bridge
crates/quicksave-service/     Software/provider workspace orchestration
shared-storage/              Active library fork; no remote deployment
upstream/                    Pinned source provenance; not a runtime deployment
docs/                        Architecture, porting plan, support matrix and threats
scripts/                     Isolated verification and smoke checks
```

## Development

Prerequisites: Rust 1.89 or newer, Node.js 22.12 or newer, npm, and the
[native Tauri prerequisites](https://v2.tauri.app/start/prerequisites/) for your OS.
Use the lockfiles for reproducible builds.

```sh
cargo test --locked --workspace
cargo run --locked -p quicksave-cli -- capabilities
```

Desktop:

```sh
cd apps/desktop
npm ci
npm run build
npm run tauri dev
```

Linux desktop builds additionally need the documented WebKitGTK/GTK development
packages. Cross-compilation or a successful macOS test run is not native Windows
or Linux acceptance.

The desktop exposes only `workspace_query`, `workspace_prepare` and
`workspace_execute`. Legacy local-repository/discovery commands are not a UI
fallback; selected filesystem/provider operations require exact native tickets.

## Explicit CLI workflow

This is the **legacy local format**, not the provider workspace/No Land bundle
flow. Its external key-file requirement does not describe the normal workspace
UI, where secret keys remain native.

Use dedicated test directories to begin with. The repository and recovery-key
parent folders must exist. Paths must not traverse symlinks. On macOS, use
resolved `/private/...` temporary paths rather than the `/tmp` alias.

On macOS/Linux, an existing repository folder must already be owned by you with
mode `0700` and without extended ACLs. QuickSave does not change existing folder
permissions. The CLI can create a missing private repository directory. Key files
require `0600`, one hard link, and native ACL verification. These are local CLI
rules, not a repository/key-file setup form for workspace v2. Windows writes in
this local engine remain explicitly unavailable in this preview.

```sh
quicksave capabilities
quicksave directories
quicksave discover

quicksave init --repository /absolute/test-repository --key-file /absolute/private/quicksave.key
quicksave backup --repository /absolute/test-repository --source /absolute/source --key-file /absolute/private/quicksave.key
quicksave list --repository /absolute/test-repository --key-file /absolute/private/quicksave.key
quicksave restore --repository /absolute/test-repository --snapshot SNAPSHOT_ID --destination /absolute/empty-destination --key-file /absolute/private/quicksave.key
```

The recovery key is a private, external 32-byte file. **Keep a second secure copy.**
It is never printed, passed as a command-line value, or stored inside the
repository. A lost key cannot be recovered by QuickSave.

Restore refuses an occupied destination. This preview does not overwrite an
installed application, migrate it into a sandbox, reinstall system services, or
claim arbitrary cross-OS binary portability.

## License and provenance

New QuickSave code is conservatively marked **GPL-3.0-only**. The source repository
has GPLv3 at its root but MIT in engine workspace declarations. Original notices
are preserved; the ownership/licensing discrepancy requires review before
distribution or any alternative licensing. See `LICENSE`, `upstream/SOURCE.json`,
and `docs/REUSE-AND-LICENSE.md`.

No public GitHub repository, release, signing identity, paid resource, or
production cloud operation is created by the local development setup.
