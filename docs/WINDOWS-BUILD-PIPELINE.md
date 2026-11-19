<!-- SPDX-License-Identifier: GPL-3.0-only -->
# Windows build pipeline (now part of desktop CI)

Windows x64 and ARM64 are now included in
`.github/workflows/desktop-build.yml`. See
[DESKTOP-BUILD-PIPELINE.md](DESKTOP-BUILD-PIPELINE.md) for the full native test and
packaging matrix. The former Windows-only workflow was replaced, not duplicated.

Each Windows job verifies the pinned upstream/fork, runs frontend, native Rust
workspace and desktop unit tests, and builds an unsigned NSIS installer using
Tauri and a matching native MSVC Rust target.
Artifacts are named `quicksave-windows-<arch>-unsigned-<commit>` and kept for 7
days. Download it from the successful workflow run's **Artifacts** section.

This does not publish a GitHub Release, sign an executable, configure a provider,
access user credentials, or execute remote provisioning code. No signing secrets
are needed. Windows/SmartScreen may warn about the unsigned installer.

A successful build is compilation/packaging evidence, not native backup/restore,
credential-vault, process-observation, or whole-feature acceptance. Known
unsupported Windows capabilities must continue to fail explicitly. The workflow
has not been executed until it is pushed to the chosen GitHub repository.
