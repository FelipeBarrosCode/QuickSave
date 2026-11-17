# Review checklist before expanding scope

Use with [the plan](PORTING-PLAN.md). An unchecked item is not an implied feature.

## Baseline safety

- [ ] Provenance verifier passes; upstream snapshot/notices remain untouched.
- [ ] No runtime imports/dependencies on No Land services or production state.
- [ ] GPL-root/MIT-workspace conflict remains disclosed; release license review done.
- [ ] Capability report distinguishes implemented, unavailable and planned features.
- [ ] Native root pinning rejects link/reparse ancestors and invalid target paths.
- [ ] Authentication, integrity, resource limits, stable-file checks and overwrite
      refusal cannot return success when unsupported.
- [ ] Repository/source/destination/key-file overlap and existing-target safety tested.
- [ ] Native root aliases, namespace replacement and a key-file hardlink within a
      selected tree are refused through handle/file-identity checks.
- [ ] Only synthetic temporary data used; no remote resources/signing/releases.

## Secrets and recovery

- [ ] No key bytes in CLI arguments/stdout, logs, webview, JSON settings or fixtures.
- [ ] Key-file creation refuses overwrite; key is external to source/repository.
- [ ] Missing/wrong/locked key fails without replacing repository identity.
- [ ] macOS extended ACLs are rejected before secret-writing callbacks; imported
      key privacy is checked through `verify_private_file`.
- [ ] Native vault implementation, if enabled, has per-OS lock/unavailability tests.
- [ ] Recovery export/import verified; lost-key consequences are explicit.

## Versioned repository and restore

- [ ] QuickSave-native format/version documented; No Land interoperability not implied.
- [ ] Authenticated context binds repository and record type/identity.
- [ ] Envelope v2 binds a fresh random 32-byte envelope ID in HKDF/all record AAD;
      same-key/context cross-envelope splicing regressions pass after the change.
- [ ] Bounds, duplicate/colliding paths and unsupported metadata are validated.
- [ ] Commit publication follows all referenced verified content and required syncs.
- [ ] Snapshots remain additive; no inherited retirement/deletion/GC policy.
- [ ] Empty-target restore limitation and partial-output recovery are disclosed.
- [ ] Before enabling overwrite: dry-run scope, durable rollback journal, crash
      recovery and explicit consent have been accepted on each supported OS.

## Desktop authority and admission

- [ ] `authorize_operation` shows exact operation/scope in a native confirmation.
- [ ] Init, backup, list and restore require matching single-use `approvalId`;
      replay, absence, expiry (10-minute TTL) and proof/scope replacement fail.
- [ ] Outstanding approvals are bounded to 32; status/history/logs contain no
      keys or reusable approval tokens and grant no authority.
- [ ] Two query slots, one dialog lane and one mutation lane are enforced.
- [ ] Proof/receipt work stays off the GUI thread; atomic shutdown admission
      handles quit racing with accepted work and joins owned workers.
- [ ] Changed security code has post-change results; pre-change counts or a
      successful native compilation are not reused as acceptance.

## Advanced features: prove them before enabling them

- [ ] Profiles use reviewed, versioned logical-root mapping and scope preview.
- [ ] Discovery never grants permission to capture unrelated app/home state.
- [ ] App consistency label names the actual mechanism, not a folder copy.
- [ ] Watcher loss/restart/overflow invalidates fast-identity trust.
- [ ] Cloud profiles use isolated explicit credentials; subprocesses/output bounded.
- [ ] Live provider/native snapshot tests separately authorized and recorded.
- [ ] Native tests run on each claimed OS/filesystem; skips name missing capability.
- [ ] Frontend, Tauri compilation and native packaged acceptance reported separately.
- [ ] No “production ready,” “full app restore” or performance claim exceeds evidence.
