<!-- SPDX-License-Identifier: GPL-3.0-only -->
# November 19: live tracking failure investigation

Read-only inspection of QuickSave PID 66342 found approximately 90% CPU while
idle. A one-second native process sample is retained in
`artifacts/native-breaking-sample.txt`. The tracking worker stack repeatedly
entered `tick`, `validate_tracking`, automatic-enrollment verification and
workspace-state validation. The sampled hot path was not native app discovery.
This identifies excessive idle verification; it does not establish the cause of
every application enrollment/index failure.

The OS reports macOS 26.6.1. The running development executable is ad-hoc,
linker-signed with no TeamIdentifier or bound Info.plist. This is not proof of
either granted or denied Full Disk Access. WebKit-related sandbox messages in
the process-scoped unified logs cannot be treated as the tracking failure cause.
No QuickSave-named file log or crash report was found in the searched Logs
locations. Console output for this launch was discarded, so application error
messages cannot be reconstructed from stdout/stderr.

Changed the worker to skip authority IO on idle timer wakes and latched/paused
apps. Work due, queued hints/overflow, observation epochs and periodic audits
still trigger fresh authority verification before source work or publication.
No valid grant is cached. Explicit recovery remains required after denial.

Validation: all 130 `quicksave-tracking` library tests passed with
`CARGO_BUILD_JOBS=1 CARGO_INCREMENTAL=0 cargo test -p quicksave-tracking --lib -- --test-threads=1`.
The added fixture checks 100 idle ticks perform no grant verification and that
a due audit detects denial without repeated verification after the latch.
Only isolated temporary files and injected authority were used.

The patch has not been built into or activated in the running desktop app.
No restart, settings reset, permission change, credential import or upload was
performed during this investigation. Individual app failures still require the
current UI diagnostic text or a separately approved diagnostic capture.
