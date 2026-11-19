<!-- SPDX-License-Identifier: GPL-3.0-only -->
# Desktop builds and tests

`.github/workflows/desktop-build.yml` runs on main pushes, PRs to main, and manual
dispatch. `.github/desktop-targets.json` defines six native build/test jobs:

| OS | Architecture | Runner | Packages |
| --- | --- | --- | --- |
| Windows | x64 | windows-2025 | unsigned NSIS installer |
| Windows | ARM64 | windows-11-arm | unsigned NSIS installer |
| macOS | Intel x64 | macos-15-intel | unsigned app in DMG |
| macOS | Apple Silicon ARM64 | macos-15 | unsigned app in DMG |
| Linux | x64 | ubuntu-24.04 | DEB and RPM |
| Linux | ARM64 | ubuntu-24.04-arm | DEB and RPM |

Runner labels are from the
[GitHub-hosted runner reference](https://docs.github.com/en/actions/reference/runners/github-hosted-runners).
Standard-runner availability depends on GitHub and account policy; private
repositories consume included minutes and can incur charges under account
billing settings. This workflow does not provision larger or self-hosted runners.
At most three matrix jobs run concurrently; failures do not cancel the other
platforms.

## Test gates

The preparation job verifies upstream/fork provenance and runs Python tests,
including matrix completeness and native-host guard tests. Every matrix job:

1. Confirms Python's OS/architecture and the Rust host match the target. A
   cross-compile or an x64 process posing as ARM64 does not pass this gate.
2. Re-verifies provenance on the target filesystem.
3. Installs locked frontend dependencies, runs frontend tests, typechecks/builds.
4. Executes all Rust workspace targets/tests natively, with one test thread.
5. Executes native desktop unit tests after frontend assets exist.
6. Builds release packages with signing disabled and locked Cargo dependencies.

No `continue-on-error`, test filter, or `--ignored` is used. Existing explicitly
ignored tests remain ignored and are visible in the logs; this is not a claim
that they passed. Tests use isolated temporary fixtures/injected authority, not
real providers, No Land state, account vaults or remote provisioning.
Known native limitations may produce real failures on a new platform; these must
be fixed or documented rather than converting the job into a compilation-only
success.

Packages and test evidence appear under the workflow run's **Artifacts**.
Frontend JUnit and Rust test logs are uploaded even when later steps fail.
Packages are uploaded only after the tests and packaging succeed; missing
packages fail the job. Artifacts expire after seven days.

## Scope and limitations

This is the three desktop OS families on x64/ARM64, **not every OS or CPU ever
made**. There are no Android/iOS, 32-bit x86/ARM, RISC-V, BSD, musl, or old-OS
acceptance claims. There is no separate macOS universal binary; both architectures
have their own natively tested package.

These jobs do not perform GUI installation/launch acceptance, real credential
vault authorization, cloud backup/restore, signing, notarization, or publishing a
GitHub Release. Unsupported runtime capabilities must still fail explicitly.
A six-platform green build is not whole Shared Storage acceptance.

The workflow cannot run until pushed to the user's chosen GitHub remote. Local
matrix/unit tests and a macOS host check are not Windows/Linux acceptance.
