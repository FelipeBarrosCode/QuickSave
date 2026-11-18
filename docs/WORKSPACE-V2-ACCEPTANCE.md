# Workspace v2 acceptance — November 17, 2026

**Development integration, not release or full No Land parity acceptance.**
The authority and interface requirements are in
[`WORKSPACE-V2-CONTRACT.md`](WORKSPACE-V2-CONTRACT.md).

This document separates source implementation, isolated test evidence, native
runtime acceptance and distribution approval. A provider definition, test double,
cross-target check or successful build is not an actual provider connection or
an end-to-end native backup.

## Scope and format boundary

- Normal desktop navigation is **Overview / Backup / Restore**. Provider
  connection belongs in an Overview dialog, not a separate capability page.
- Workspace settings use non-secret `state.json` and native vault references.
  Import is explicitly native-consented and read-only at the No Land source;
  imported profiles start read-only in QuickSave.
- The workspace bridge reuses `shared-storage/`, a provenance-tracked library
  fork of the pinned source. `upstream/no-land/` stays byte-for-byte unchanged.
- The older local CLI uses `quicksave-engine` / `quicksave-content`, an external
  recovery-key file and its **different QuickSave repository/envelope format**.
  It is not a No Land bundle migration utility. Earlier local smoke results do
  not prove workspace interoperability or cloud durability.
- Stable-file capture is not an app-wide atomic snapshot. Downloading a Linux
  bundle as files does not make its executable native to Windows or macOS.
- Local files and additive cloud history remain. Automatic source deletion,
  cloud convergence/retirement and deployment/lifecycle execution are excluded.

## Evidence matrix

“Pending” means not accepted by this record; source presence is not a substitute
for the missing test or runtime evidence.

| Area | Evidence currently recorded here | Remaining acceptance gate |
| --- | --- | --- |
| Immutable upstream | Existing SHA-256 file manifest and pinned 227-file tree; verifier regression tests retain byte/path/metadata tamper cases | Final verifier run against the settled integration; never regenerate the upstream baseline |
| Active-fork dependency boundary | Isolated synthetic-repository tests cover exact/aliased local packages, inherited paths, unused fork manifests, target/dev/build dependencies, source paths, Git/lifecycle exclusion and symlink breakouts | Final `SOURCE.json` adaptation list, original license copy and exact fork-change hash ledger |
| New-code licensing | Guard requires GPL-3.0-only on new QuickSave manifests/new fork Rust files and preserves original fork manifest notices | Owner/rights-holder review, third-party inventory and distribution obligations remain unresolved |
| Native authorization | Source contains exact one-use ticket storage, path proofs and sanitized native confirmation inputs | Final parent test run plus actual native-dialog review; inspect every destination and frozen deletion dependency in the visible prompt |
| Overview / Backup / Restore | New frontend source uses those three pages and paginated file browsing | Final frontend tests/build, browser visual review and native IPC/dialog flows |
| State/vault/import | Separate state/provider implementation exists; development must use injected stores and synthetic imports only | Parent-recorded isolated tests; native vault persistence/permission/error handling and consented import on each supported OS |
| Tracking/autosave | Dedicated native tracking/scheduling source exists | Parent-recorded isolated tests and real native watcher/restart/overflow/mid-upload-change acceptance; never clear dirty state without exact durable completion |
| Shared-engine operations | Native bridge/source adaptations exist for capture, catalog, restore and operation protocols | Parent-recorded isolated interoperability tests; authenticated generation/receipt, scope confinement, failure/recovery, cancellation and exact retry evidence |
| Explicit cloud deletion | Frozen-preview/dependency-acknowledgement interfaces exist | Parent-recorded isolated safety tests and native visible-scope review; no live deletion is authorized by this implementation task |
| All 14 provider kinds | Shared adapter/state definitions cover the kinds listed below | **No live accounts/connections tested here.** Each needs its own authentication/list/read/write/failure evidence; OAuth needs private native callback/token handling |
| macOS | Development host for this verifier slice | Parent's final Rust/frontend checks are separate from launched-app, native vault/dialog and filesystem acceptance |
| Windows | No native Windows execution recorded here; bridge has explicit unsupported-platform handling | Native engine/path/ACL/durability port and native runtime suite, not merely cross-compilation |
| Linux | No native Linux execution recorded here | Native runtime/filesystem/vault/watcher tests and desktop dependencies; macOS success does not transfer |
| Background operation | In-process queue/worker/shutdown interfaces exist | Joined shutdown, hidden-window behavior and pending finalization tests; a separately installed/login-started service is not accepted |
| Packaging/distribution | No signing, installers or release acceptance recorded | Per-OS package/install/update/uninstall tests, license approval, signing approval and any distribution authorization |

The 14 adapter kinds are Amazon S3, Backblaze B2, Cloudflare R2, Wasabi,
DigitalOcean Spaces, generic S3, Google Drive, Google Cloud Storage, Microsoft
OneDrive, Dropbox, Box, Azure Blob, SFTP and WebDAV. Their presence is not a claim
of working OAuth, valid account credentials, provider-specific durability or
live connection acceptance.

## Recorded validation

This verifier/documentation slice runs only Python tests against newly created
synthetic clone trees under the approved temporary parent. It does not compile
Cargo, start the native application, read an actual credential vault, import
live No Land state or contact a provider.

```sh
QUICKSAVE_TEST_TMPDIR=/absolute/approved/temp-parent \
PYTHONDONTWRITEBYTECODE=1 \
python3 -m unittest discover -s tests -p test_repository_guards.py -v
```

Recorded result on the macOS development host: **75 tests passed** (5.436 s;
the final invocation used `-q` instead of `-v`). Every fixture was constructed
inside a newly created synthetic temporary repository. No Cargo build or native
provider/vault test was run by this slice. `git diff --check` on the assigned
paths also passed.

The parent integration owner must record final Rust/frontend/bridge results
separately, including exact commands and limitations. Historical counts in
[`IMPLEMENTATION-STATUS.md`](IMPLEMENTATION-STATUS.md) describe the earlier local
engine, not automatic acceptance of this workspace revision.

## Release blockers that cannot be inferred away

1. Native safety and runtime acceptance on each OS; no Windows/Linux acceptance
   based on a macOS build.
2. All supported real provider flows, credential errors, connectivity failures
   and operation durability. Live testing needs separate authorization and
   isolated disposable accounts/repositories.
3. Original bundle/pack interoperability with isolated fixtures, without
   weakening source authentication, metadata, generation, path or overwrite
   guards. Explicit errors are required where the native port is unsupported.
4. Autosave restart/overflow/retry/mutation correctness, persistent signed
   authority and no automatic local/cloud physical deletion.
5. Actual native confirmation, accessibility and lifecycle/shutdown behavior;
   no successful UI status from stubs or optimistic progress.
6. Native packaging, signing/update security and the GPL-root/MIT-workspace
   license discrepancy. Local implementation authorizes no publication,
    production account access, remote deployment or paid resources.

## Explicit integration gates

- **Transport prerequisite:** this development host has no installed `rclone`.
  Native transport preflight requires a separately installed trusted executable
  at version **1.76 or later** with the required checksum/immutable flags. No
  helper was downloaded, installed globally, or tested against a live account.
- **OAuth storage:** the private PKCE implementation is not proof of durable
  storage authentication. OAuth-backed rclone operations remain gated until
  refreshed/rotated tokens have a checked native-vault persistence handoff.
  Google desktop clients use loopback redirects; Microsoft/Dropbox require the
  documented registered callback. Box fails explicitly without verified public
  PKCE support. There is no embedded production No Land client secret.
- **Restore recovery:** the native host does not replay legacy path-based rollback
  journals. Failed/cancelled downloads retain new outputs and artifacts. Automatic
  cleanup and restore retry are unsupported until created-file identities and
  authenticated recovery authority are verified; choose a newly approved empty
  destination instead. No old journal may grant deletion authority.
- **Scope remains explicit:** this native-host path uses approved-root watching
  and reconciliation, not Linux process/eBPF attribution on any OS. Discovery
  alone cannot grant a tracked root.
  Empty-directory and local-deletion snapshot fidelity are not accepted.

## Isolated native development launch

For launch/visibility checks, the debug-only `QUICKSAVE_DEV_WORKSPACE` override
must name a private real directory **under the native temporary directory**.
QuickSave uses its `data/` and `home/` children instead of real application state.
The window title identifies isolated development; the webview is incognito.
Release builds ignore this override.

The normal native vault is still lazy and never replaced with fake durability:
an idle empty workspace reads no credential entries. Automated acceptance must
not connect providers, import real No Land state or approve real cloud actions.
Vault tests use injected stores; UI geometry uses the separate synthetic WebKit
harness. Window visibility alone does not accept native consent or backup flows.
Native startup also retains legacy credential artifacts instead of deriving
cleanup authority from their paths. Live session cleanup uses its owned native
directory and removes only known leaves; it never wipes hardlinked outside data
or recursively sweeps a replacement directory. Authenticated crash-artifact
cleanup and secure SSD erasure are not accepted.
