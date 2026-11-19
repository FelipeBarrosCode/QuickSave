<!-- SPDX-License-Identifier: GPL-3.0-only -->
# macOS tracking diagnostics

See [the cross-ruleset audit](TRACKING-RULESET-AUDIT.md) for the producer/consumer
platform-value correction and the protected-tree census constraint.
Repeated references to `.ssh` are a shared safety-rule failure, not evidence that
each listed application needs more permissions. Do not change SSH permissions.

On supported boot APFS Data layouts, a
[native namespace proof](MACOS-APFS-APPROVAL-PROOF.md) now checks disjointness
without enumerating protected descendants. Other layouts retain the bounded
census and can still be blocked by denied traversal. Neither path removes
exclusions or grants access to restricted payloads.

## Repeated Keychain dialogs

### Local-first setup

The startup gate offers **Start local tracking** separately from bulk credential
import. This inventories only QuickSave account attributes and reads the existing
local signing key, if present; cloud/provider/repository values remain deferred.
The signing key and new aggregate vault item may still require native approval.
There is no promise of zero prompts or stable approval across development rebuilds.

Deferred account names live in the authenticated encrypted vault. A deferred read
fails explicitly, rather than returning “missing” and generating replacement keys.
New permissions and explicit deletions retire their matching deferred entries in
the same encrypted transaction. Later import reads only remaining entries and must
not overwrite newer local decisions. Legacy values/items remain unchanged.

Encrypted startup checks the one active item noninteractively. A failed check
keeps the startup gate closed until explicit native authorization or recovery;
no key reset or automatic bulk import occurs. This is local-storage readiness,
not a successful cloud login or backup.

Tracking defaults to saves/settings. Installation/runtime coverage remains an
explicit option. Data-only macOS selection omits whole-container boundaries in
favor of independently verified owned children; zero usable roots yields no
bundle. Omitted roles and inaccessible roots remain coverage gaps.

Temporary verification errors retain approvals and historical index/baseline
references behind a persisted denial latch. Unverified apps are not counted as
verified bundles or Saved. Explicit successful verification and reconciliation
are required before resuming; independent healthy apps remain usable.

**Refresh app tracking** explicitly rechecks paused approvals, then reconciles
metadata before clearing their denial latch. A deferred legacy local approval
can be freshly issued only for a never-captured metadata-only app with unchanged
exact roots/source identity and no baseline, history or pending work. Otherwise
the original references stay blocked and credential import may still be needed.
Refresh never performs that import, enables autosave, or starts uploads.

Authenticated cloud-history initialization failures are quarantined separately:
the dashboard reports history unavailable rather than declaring it empty or
discarding unfinished work.

**Current policy: ordinary/background vault access is noninteractive.**
After a spent native migration approval, a private migration-only backend may
allow Keychain authorization for that operation. Every native vault operation
uses one process-wide mutex around the macOS interaction flag. The flag is restored
to false before releasing the lock, including cancellation/error/unwind paths;
a failed reset blocks subsequent access. Background operations cannot inherit an
interactive window. Migration is admitted only before workspace workers start.

This does not unlock a keychain, bypass an ACL, or request a password in QuickSave.
macOS owns the dialogs. The user may need several one-time approvals for old
items; **Always Allow** is their choice. Credential values remain unchanged and
no old item is deleted. If access is denied, failure must never be treated as a
missing credential or permission to generate replacement keys.

Previously, `quicksave.desktop-secrets.v1` was displayed in native dialogs. It
is QuickSave's own credential service, not a
request to read another application's restricted files. Distinct accounts under
that service can produce identical-looking dialogs. **Always Allow** is scoped
by macOS to the item/application identity, not every item using the service name.
Development rebuilds may change that identity. A single password entry for every
existing item and all future builds is not currently guaranteed.

Workspace startup can wait for a native authorization dialog. Activity polling
and the initial app-tracking read must wait until the dashboard has loaded, rather
than queueing behind the dialog and exhausting read workers. If startup fails,
those background reads remain paused.

Native vault operations are serialized per workspace session. After the first
failed vault request, further reads/writes/deletes are blocked for that session;
restart is required to explicitly retry. A denied/cancelled request must not
trigger more dialogs for queued software scopes. This does not cache successful
authority records or hide revocation, grant other apps access, change Keychain
ACLs, save the login password, or bypass native write/read-back verification.

Consolidation removes per-item native accesses after migration; it cannot remove
the OS authorization required to read the old items first. Native acceptance of
the explicit authorization flow still requires a user-approved real operation.

Tracking/indexing and uploading are separate operations. A native application
identity or metadata index does not prove that every payload file is readable,
that application coverage is complete, or that anything has been backed up.

## Permission denied

`Permission denied (os error 13)` is an OS access denial, not a connection or
low-disk-space error. A denial can concern an installation file, a directory,
or app-private data. The diagnostic needs to identify which approved root and
stage failed before selecting a remedy.

Metadata-only indexing must not request payload read access just to obtain native
file identities and timestamps. Actual capture must still open real read handles,
check stable identities and fail if the OS denies the bytes.

For genuinely protected app-data folders, review **System Settings → Privacy &
Security → Full Disk Access** for the application actually running QuickSave.
Grant access only if you want those locations included. This is a user decision:
QuickSave does not grant itself access, change source permissions, or run as root.
Full Disk Access does not fix every ACL, unreadable directory or linked-root
restriction.

Do not infer that an application needs Full Disk Access solely from a failure
labelled `approve_directory_identity`. Approval also checks protected-folder
overlap. An earlier implementation walked file/link metadata on both sides,
so an unrelated protected-folder failure could be mislabelled as an app denial.
Identity-only overlap checks must distinguish the selected and protected sides,
without opening payload files or reading symbolic-link targets. Actual capture
remains subject to stricter file/link validation.

macOS containers may contain outward-pointing system scaffolding links. Those
links must not authorize following paths into unrelated home folders. Normalize
candidate container roots to independently verified app-owned subfolders before
deep auditing; omitted container contents keep coverage explicitly partial.

Never use recursive `chmod`/`chown`, disable SIP, or loosen another app's sandbox
as a tracking workaround. An inaccessible root must remain unresolved; omitting
its contents must not produce a complete-app or Saved claim.

## Activity checks

Idle/terminal Activity stops its two-second checks instead of consuming a
600-request budget while nothing is running. An accepted user action or explicit
resume starts another bounded status round; resumed checks share any in-flight
request. This is status checking, never automatic operation retry.

Unfinished operations absent from a later response retain their last known state
and an explicit warning, including when a full 128-row page would otherwise evict
them. An empty or unavailable history is not evidence of cancellation/completion.
Work started outside the UI is discovered on the next dashboard/status refresh;
an idle UI does not continuously scan sources or poll cloud catalogs.

## Invalid or non-portable filename

Unix files may legally contain `:` or a literal backslash. These names must not
be confused with Windows separators, alternate streams, or a different Unix
path. For example, `a\b` and `a/b` are distinct Unix paths.

Capture and same-platform restore must preserve the exact names. A Windows target
that cannot represent a selected source name must reject it before mutation,
not silently rename it or merge two files. File, provider and application IDs
remain separately validated; accepting a native filename does not widen IDs,
remote keys, parent traversal, or symlink permissions.

## Native identity could not be verified

This may indicate a linked installation, a replaced native entry, an unapproved
base, missing executable evidence, or an unsupported identity mechanism. It is
not permission to use an existence/name-only fallback. Read the concrete native
reason rather than assuming all cases need Full Disk Access.

No Land and QuickSave are excluded from automatic macOS application enrollment.
No Land configuration import is a separate, explicitly approved read-only flow;
automatic tracking must not probe its credentials or application state.

Development regression fixtures use temporary synthetic bundles and injected
vaults. They must never reproduce failures by reading real app-private folders,
No Land state, live providers, or credential-vault entries.
