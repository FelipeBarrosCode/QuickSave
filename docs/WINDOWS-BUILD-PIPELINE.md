<!-- SPDX-License-Identifier: GPL-3.0-only -->
# Windows build pipeline

`.github/workflows/windows-build.yml` builds the desktop on a native GitHub-hosted
Windows runner for pushes/PRs to `main`, or a manual Actions run.

The job verifies the pinned upstream/fork, installs locked npm dependencies, runs
frontend tests, checks Windows integration/service test sources, and builds an
unsigned x64 NSIS installer using Tauri and the MSVC Rust target.
The artifact is named `quicksave-windows-x64-unsigned-<commit>` and kept for 14
days. Download it from the successful workflow run's **Artifacts** section.

This does not publish a GitHub Release, sign an executable, configure a provider,
access user credentials, or execute remote provisioning code. No signing secrets
are needed. Windows/SmartScreen may warn about the unsigned installer.

A successful build is compilation/packaging evidence, not native backup/restore,
credential-vault, process-observation, or whole-feature acceptance. Known
unsupported Windows capabilities must continue to fail explicitly. The workflow
has not been executed until it is pushed to the chosen GitHub repository.
