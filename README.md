# QuickSave

**Encrypted, versioned backups for the computer you are using.**

QuickSave is a new, standalone native desktop application for Windows, macOS,
and Linux. It is being extracted from No Land's Shared Storage engine, with
native platform adapters instead of SSH and remote Linux provisioning.

> **Development preview, not a production release.** The first implemented flow
> is explicit local-folder backup into a separate encrypted local repository,
> immutable version history, and verified restore into an empty folder.
> Cloud transfer, automatic complete-application coverage, overwrite recovery,
> native credential-vault integration, and a standalone background service must
> pass their own implementation and acceptance gates before being enabled.

See [the actual implementation status](docs/IMPLEMENTATION-STATUS.md) and
[the remaining porting plan](docs/PORTING-PLAN.md). A populated capability model
is not a completed integration.

## Independence and safety

- No Land remains in its original repository and directory. Nothing is moved.
- `upstream/no-land/` is an attributed, unmodified source reference pinned to
  `e81238a7536aae201540956ce76981364fd36595`.
- QuickSave never implicitly connects to existing No Land cloud storage or loads
  No Land credentials, runtime databases, or application state.
- No source deletion, cloud deletion, automatic version pruning, or arbitrary
  executable restore hooks are exposed.
- Native capability reporting distinguishes implemented functionality from
  planned integrations and unsupported operations.
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

## Explicit CLI workflow

Use dedicated test directories to begin with. The repository and recovery-key
parent folders must exist. Paths must not traverse symlinks. On macOS, use
resolved `/private/...` temporary paths rather than the `/tmp` alias.

On macOS/Linux, an existing repository folder must already be owned by you with
mode `0700` and without extended ACLs. QuickSave does not change existing folder
permissions. The CLI can create a missing private repository directory; for the
GUI, prepare an empty private folder first (for example, `mkdir -m 700
/absolute/test-repository`). Key files require `0600`, one hard link, and native
ACL verification. Windows writes remain explicitly unavailable in this preview.

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
