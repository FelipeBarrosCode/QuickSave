# Validation and evidence

For the integrated initial-implementation results, see
[IMPLEMENTATION-STATUS.md](IMPLEMENTATION-STATUS.md). The security-review
checkpoint below is retained as historical evidence, not the final result.

All fixtures must use isolated temporary directories and synthetic data. No
production credentials, app state, cloud repository, remote machine or No Land
worktree is a test fixture. The read-only vendor snapshot may be read as reference.

## Repeatable checks

From the QuickSave root:

```sh
python3 scripts/verify_repository.py
python3 -m unittest discover -s tests -p 'test_*.py' -v
cargo fmt --all -- --check
cargo test --locked --workspace -- --test-threads=1
cargo build --locked -p quicksave-cli
python3 scripts/cli_smoke.py --binary target/debug/quicksave
cargo clippy --locked --workspace --all-targets -- -D warnings
```

Python 3.11+ is required for the standard-library TOML parser. Cargo `--locked`
requires the root lockfile to have been generated and committed by the integrator.
The source verifier does not resolve dependencies, change locks or execute vendor
code.

Use `target/debug/quicksave.exe` on Windows. `--temp-dir <approved-parent>` or
`QUICKSAVE_TEST_TMPDIR` selects an isolated temporary parent; the script resolves
that parent to avoid macOS symlink aliases.

Frontend checks, from `apps/desktop/`:

```sh
npm ci
npm run build
```

Native backend check, from the root, after installing the platform's Tauri
prerequisites:

```sh
cargo check --locked --manifest-path apps/desktop/src-tauri/Cargo.toml
```

The backend has a separate Cargo lock/workspace. A frontend build is **not** this
native check; neither is an installer/release test. The CI native-check option
installs Linux `libwebkit2gtk-4.1-dev`, `libappindicator3-dev`, `librsvg2-dev` and
`patchelf`. No signing, packaging or release is performed.
The separate desktop lockfile now exists. This does not mean its native CI matrix
or any packaging acceptance has run. Workspace tests use one test thread to avoid
overlapping memory-heavy fixtures.

## Security-review checkpoint: not final acceptance

The following is a **parent-reported interim checkpoint**, not a rerun by the
documentation agent and not a final all-green result:

| Scope | Reported evidence | Boundary |
| --- | --- | --- |
| macOS native Tauri backend | Check passed in 2m41s | Compilation at that checkpoint, not acceptance of subsequent approval/admission changes or packaging |
| Platform | 23 macOS tests passed; Windows/Linux library cross-checks passed | Cross-checks are compilation, not native Windows/Linux behavior; alias/ACL/private-file hardening needs revalidation |
| Integrations | 26 native tests passed | Does not implement cloud transports, vaults, observers or application-atomic capture |
| Content | 14 unit tests passed **before** the envelope-v2 security change | Not acceptance of v2 envelope identity, anti-splicing, compression or bounds after the change |
| Engine scale fixture | 186,735-file in-memory fixture added, **unrun** | Neither filesystem-scale capture nor a performance/durability result |

Security review is integrating: a random 32-byte v2 envelope ID in HKDF/all record
AAD; native root/key-identity overlap and macOS ACL/private-file checks; exact-scope
single-use desktop approvals; and bounded query/dialog/receipt/shutdown admission.
The global 512 MiB and per-record 16 MiB content ceilings are unchanged.
The engine preview allows 250,000 entries within a 32 MiB aggregate path budget,
64 MiB commits, 16 MiB per-file indexes and 8 MiB chunks. Those limits are not a
completed capacity test.

Re-run the relevant unit, integration, CLI/UI and native suites on the integrated
revision before replacing this checkpoint with final evidence. Do not carry a
passing result across changed security code. No final workspace, Windows/Linux
native, packaged, cloud or production-readiness acceptance is recorded here.

## Provenance/dependency guard

`scripts/verify_repository.py` checks:

- the pinned commit, recorded archive hash and selected paths in `upstream/SOURCE.json`;
- the unpacked snapshot's file-count and deterministic path/size/content-hash tree
  digest against `scripts/upstream-provenance.json`, and exact per-file hashes
  against `upstream/FILES.sha256.json`, rejecting links/special files;
- new Rust workspace membership and dependency declarations for vendor/No Land
  runtime dependencies, including target-specific tables and workspace inheritance.

It does not recreate the original source archive, prove legal rights, perform an
SBOM/security audit or establish that no developer copied code without attribution.
Keep derived-file notices and the reuse record under human review. Tests exercise
the verifier against their own tiny synthetic repositories, never by editing the
actual snapshot.

## Acceptance layers

| Layer | Required assertions |
| --- | --- |
| Content | Deterministic chunk boundaries/hashes versus reference fixtures; short reads; empty/large input; AEAD wrong-key/context/tamper/truncation and same-key/context cross-envelope splice refusal; compression/unsupported-encoding and hard record-limit tests |
| Platform | Native no-follow handle confinement; source identity; traversal and invalid paths; link/reparse ancestor rejection; native-root/key-hardlink aliases; ACL/private-key verification before secret writes; no overwrite; bounded enumeration; truthful unsupported cases |
| Engine | Isolated init/backup/list/restore round trip; additive snapshots; dedup scope; encrypted metadata/content; commit-last; corrupt existing object refusal; tree-change and overlap rejection |
| CLI | Help/capability output; external-key path policy; nonzero failure status; no key bytes in output; byte-identical restore; refuses source/key/repository overlap and nonempty target |
| Desktop | Exact-scope native approval, single-use/expiry/replay/mismatch/proof-replacement tests, no tokens/keys in history; two query slots/one dialog lane; receipt work off GUI thread; atomic quit/admission and owned-worker tests |
| Fault/recovery | Disk-full/permissions, interruption and publication faults; no successful incomplete commit; documented operation-owned restore leftovers; future overwrite needs journal crash tests |
| Native/package | Run on each claimed OS/filesystem; separately test packaged dialogs, permissions, startup and upgrade/uninstall behavior |
| Future cloud | Local-provider isolated config first; bounded subprocess/stream/error tests; authenticated remote commit/identity and concurrent-writer tests; live provider acceptance separately authorized |

Do not inherit upstream test counts, performance numbers or deployment results.
Do not globally skip Windows/Linux tests to obtain green CI: positive fixtures
must name and assert the unavailable capability, and test its fail-closed error.

## CLI smoke contract

`scripts/cli_smoke.py` invokes the **built binary**, not an engine mock. Actual
commands are `capabilities`, `init --repository --key-file`,
`backup --repository --source --key-file`, `list --repository --key-file`, and
`restore --repository --snapshot --destination --key-file`.

It creates disjoint synthetic source/repository/key/restore locations under one
resolved temporary parent, captures two versions, verifies additive history and
byte-identical recovery of both, refuses wrong keys and nonempty targets, and
checks reinitialization does not overwrite an existing recovery key. Recovery-key
output checks and bounded stdout/stderr capture include initialization. The smoke
does not run discovery or read actual app state.

When durable writes are explicitly unavailable, it instead requires a failed
initialization naming the unsupported operation, no key/repository publication,
and reports `unsupported-refusal-verified` with `round_trip: false`. That is a
passing refusal test, **not native backup acceptance**.

## Recording results

Record date, source revision/worktree state, host OS and filesystem, exact command,
pass/fail count, skipped capability tests and remaining limitations. A planned
workflow or “would pass” is not a test result. Local macOS build evidence does not
establish Windows/Linux acceptance or native packaging, and no successful local
provider fixture authorizes real cloud operations.
