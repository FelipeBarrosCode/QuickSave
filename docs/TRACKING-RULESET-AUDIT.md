<!-- SPDX-License-Identifier: GPL-3.0-only -->
# Tracking ruleset audit — November 18, 2026

This is a source/isolated-fixture review, **not native user-account acceptance**.
No live app roots, SSH material, credential vault, No Land state or provider was
used for testing. The full Shared Storage contract remains binding.

## Rules reviewed

Native discovery follow-up: production macOS candidate enumeration now uses
NSWorkspace/Launch Services and scoped Spotlight application-bundle metadata,
not installation-folder crawling. See
[MACOS-NATIVE-APP-DISCOVERY.md](MACOS-NATIVE-APP-DISCOVERY.md).
OS records remain hints; every identity/root/permission check below still applies.

| Rule family | Required checks retained |
| --- | --- |
| macOS bundles | Exact bundle identity and bounded plist parsing; no app-name ownership fallback, execution, or alias following |
| macOS containers | Exact container owner; independently verified child roots for saves/settings-only policy; no whole-container fallback |
| Shared group containers | Validated signed application-group evidence, not a matching folder name |
| Steam | Exact numeric app/manifest/install identity and separately approved userdata scope; no account-file or credential discovery |
| Linux desktop / Flatpak | Exact desktop identifier and approved data scope; never run `Exec` or infer ownership from its parent |
| Windows registry / packages | Explicit native identity adapter and reviewed exact mappings; missing adapters fail unsupported |
| Manual selected files | Exact native parent/leaf identities and allowlist; parent approval does not authorize sibling enumeration/capture |
| All tree roles | Selected/protected root identity, descendant-alias guard, bounded census, change/replacement checks |
| Grant admission | Native MAC and fresh revocation/anchor verification; temporary failures retain references behind a denial latch |
| Source index | Authenticated frozen metadata, exact original roots/instance, source acknowledgement; no content hashing to paint the UI |

Native Windows/Linux execution and packaging are separate gates, not established
by these platform-shaped fixtures or the macOS run.

## Corrections from this review

### Follow-up after the two-app inventory report

- Mutual root anti-alias approval now uses `overlaps_for_approval`, not the
  stricter capture walk. An escaping link still prevents its entire independent
  root from being indexed. During initial automatic enrollment only, a typed
  out-of-root link layout may omit that whole root while retaining other verified
  roots with authenticated incomplete coverage. No target is followed, no leaf is
  silently skipped, and existing approved scopes may not shrink on refresh.
- An identical discovery batch no longer rotates its registry nonce on every
  refresh: an exact still-native-verified persisted certificate is reused.
  Explicit refresh can replace a superseded certificate only for identical
  policy/discovery/candidate bindings under a still-valid original tracking grant.
  The tracking scope/grant, roots and historical references are not replaced by
  this certificate renewal.
- A source import can reacquire a frozen index once when its cached revision
  changes under the same freshly verified tracking/root/policy authority.
  Revocation, scope changes and other failures are not that retry signal.
  Reacquisition is metadata-only; it does not recapture, upload or accept the
  obsolete index as current. Redacted native import subphases now distinguish
  admission, page validation/projection, database writes and final verification.
- Intentional-only omissions no longer use the "unavailable roots" message.

The user's source-import failures are not assumed solved solely by generic
diagnostics or by these narrower fixes. Native user-account acceptance and the
remaining unsupported identity/root mappings are still separate gates.

### Earlier review

1. **Actual platform wire value:** the native planner serializes `Platform::MacOs`
   as `mac_os`. The data-only container branch tested `macos`, also used by its
   fixture. Both authenticated spellings now take the narrower branch; fixture
   data uses the producer spelling. A service/Tracker integration test serializes
   the real producer enum, supplies a container with an escaping scaffold link,
   and verifies that only its independently owned Documents child is indexed.
   Whole-application capture remains denied for incomplete coverage.
2. **Omission is not an OS failure:** unselected roles and deliberately omitted
   container boundaries retain authenticated incomplete coverage, but no longer
   manufacture an app error or an unreadable-installation diagnostic. Actual
   inaccessible roots and integrity failures remain errors.
3. **Metadata-only executable registration:** source registration now checks the
   executable through stable no-follow native metadata rather than requesting a
   payload-read descriptor. Actual capture still requires readable stable payload
   handles. The fixture covers mode-000 regular files, directories, symlinks and
   relative paths.
4. **Shared protection failures:** the renderer projection groups the same
   protected path/stage/entry/reason instead of repeating it as a permission
   failure in every app. App blockers remain explicit; grouping is not permission
   and does not skip native safety checks.
5. **Source-index diagnostics:** failures identify a fixed stage (scope, current
   policy, frozen header/owner, source registration/import/acknowledgement) and
   redacted reason. Unknown backend bodies are never echoed or guessed to mean
   a permission denial.
6. **Admission/status race:** execution-time tracking verification now holds one
   state operation/OS-lock read scope while verifying native authority. It does
   not publish state. The end read still detects noncooperating state changes;
   fresh native authority, workspace identity and UI snapshot checks remain.
7. **Status isolation:** one quarantined automatic app no longer makes the entire
   native tracking-status enumeration fail.

## Protected-tree census constraint

**November 19 follow-up:** a narrowly scoped non-enumerating native proof has now
been implemented for certified boot APFS Data layouts; see
[MACOS-APFS-APPROVAL-PROOF.md](MACOS-APFS-APPROVAL-PROOF.md).
The limitation below continues to apply when those measured OS conditions are
unavailable. It is not bypassed by dropping exclusions or guessing disjointness.

The protected-descendant overlap algorithm still needs a complete validated
directory-ID census on both sides when no narrower OS proof excludes aliases.
It does **not** open key payloads, but a denied directory census under an excluded
tree can block unrelated tree approvals. File names alone do not prove type or
disjointness; this review did not inspect the reported live `id_rsa` entry.

The current implementation must **not** suppress EACCES, drop `.ssh` from the
exclusions, replace native proof with lexical prefixes, or change user permissions.
Selected-file scopes remain separately confined, not an automatic substitute for
whole-app support. A general non-enumerating native alias-exclusion proof is still
needed to remove this blocker without weakening protection. Diagnostic grouping
does not claim that this underlying blocker has been fixed.

## Validation commands

Use serialized Cargo jobs and canonical isolated temporary directories:

```sh
CARGO_BUILD_JOBS=1 CARGO_INCREMENTAL=0 cargo test -p quicksave-state -p quicksave-tracking -p quicksave-service -p quicksave-noland --lib -- --test-threads=1
CARGO_BUILD_JOBS=1 CARGO_INCREMENTAL=0 cargo test -p quicksave-integrations --lib -- --test-threads=1
CARGO_BUILD_JOBS=1 CARGO_INCREMENTAL=0 cargo test -p quicksave-platform --lib -- --test-threads=1
CARGO_BUILD_JOBS=1 CARGO_INCREMENTAL=0 cargo test -p quicksave-platform --test directory_identity_overlap_unix -- --test-threads=1
CARGO_BUILD_JOBS=1 CARGO_INCREMENTAL=0 cargo check --target x86_64-pc-windows-gnu -p quicksave-state -p quicksave-tracking -p quicksave-service --tests
npm --prefix apps/desktop test -- --run
python3 scripts/verify_repository.py
git diff --check
```

The first broader test attempts exposed a noncanonical temporary-directory
fixture (fixed only in the synthetic batch fixture) and the existing
metadata-projection race; failed attempts are not acceptance evidence.
Final results/remaining limits are recorded in the integration checkpoint.

The November 19 recovery follow-up passed **622 Rust tests** (including six
isolated native gateway tests), with one rclone test intentionally ignored,
and **184 frontend tests**. The frontend/native builds and Windows test-source /
Linux platform test-source cross-checks passed. See the integration checkpoint
for exact commands, current launch evidence and remaining acceptance limits.

Previous scoped results: **527 Rust tests passed**, one rclone test intentionally
ignored; **179 frontend tests passed**. Windows test-source cross-check and
repository verification passed. The native overlap fixtures confirm that an
unreadable ordinary payload does not require content access, while an unreadable
directory remains a denied proof—not a disjointness result. No privileged Linux
bind-mount test, native Windows execution, or real user-folder acceptance was run.
