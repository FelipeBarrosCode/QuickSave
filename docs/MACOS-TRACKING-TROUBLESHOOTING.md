<!-- SPDX-License-Identifier: GPL-3.0-only -->
# macOS tracking diagnostics

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
