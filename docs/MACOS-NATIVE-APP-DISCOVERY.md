<!-- SPDX-License-Identifier: GPL-3.0-only -->
# Native macOS application discovery

## November 19 protocol failure found and corrected

The first bridge boxed `started && status.finished` directly into `NSNumber`.
Objective-C's C logical expression has integer type, so the JSON field was
`"indexComplete": 1` (or `0`), not a boolean. Rust's strict `bool` decoder
rejected the whole response; the planner masked this as inventory unavailable.
This was a bridge protocol bug, not evidence of permission denial.

A user-authorized metadata-only probe of the linked helper returned 20 candidate
URLs and a completed query on both main and worker threads. Before the fix,
the decoded `indexComplete` NSNumber encoding was `q` (integer); after the fix
it was `c` (boolean), matching `limited`. The probe did not access application
data, tracking state, SQLite, credential vaults or provider accounts.
This is native candidate-gathering evidence, not full app-tracking acceptance.

The production encoder now takes explicit BOOL parameters. A linked pure
protocol fixture exercises that same encoder with no native inventory calls;
Rust decodes its output successfully and continues to reject numeric booleans.
All 63 integration library tests passed. Known base-validation, bridge,
Workspace, metadata and response-decoding failures now carry static redacted
stage diagnostics rather than discarding their distinction. No raw exception
body, credential or unapproved path is included.

The running desktop process has not been replaced as part of this diagnosis.
Source-import authority errors remain a separate unresolved issue.

Production macOS application discovery now uses public Apple application/index
records rather than enumerating installation folders:

- `NSWorkspace.runningApplications` supplies running application bundle URLs.
- `NSWorkspace.URLForApplicationWithBundleIdentifier` resolves known identifiers
  through Launch Services. The original URL is retained as well, so a preferred
  URL cannot conceal a second installation.
- A scoped `NSMetadataQuery` searches Spotlight's application-bundle content type
  for installed apps that are not running.

`NSWorkspace` alone does **not** provide an exhaustive installed-app list.
Unindexed, unregistered, inactive installations may be absent. Gathering failure,
timeout, output limits or rejected metadata produces explicit incomplete/unavailable
diagnostics, not an empty successful inventory or a folder-crawling fallback.

The linked Objective-C bridge uses Foundation/AppKit; it does not execute Swift,
`mdfind`, `lsregister`, applications, installers, private Launch Services APIs,
or external commands. Both the primary approved bundle planner and the legacy
read-only macOS discovery endpoint use these native sources. Old folder-based
macOS discovery remains only in isolated synthetic fixtures. Linux/Steam and
explicit Windows adapters keep their existing behavior.

## Authority and identity

Native URLs are **candidate hints**, not app identity, ownership, tracking,
readability or backup grants. The existing no-follow native handles, retained
policy bases, exact bundle metadata/executable checks, exclusions and verified
data-root mappings remain mandatory. An OS record cannot replace a missing
`CFBundleIdentifier` with a name, authorize a linked bundle, or expand an approved
base. Existing permissions, signing identities and source configuration are not
changed.

Only approved installation locations are queried/admitted by the tracking
backend. Discovering a registered app outside those bases does not authorize
opening it. Native directory/product/executable identities deduplicate alternate
spellings of one installation; different installations claiming the same bundle
identifier still have ambiguous shared-data ownership.

Discovery does not solve protected-data access, reconstruct every application's
save-folder layout, read No Land state, access a keychain, enable autosave, or
upload anything. Partial coverage and unsupported identity/root cases remain
explicit. No packaging, native permission, or whole-feature acceptance follows
from a build.

## Bounds and validation

- At most 128 supplied scope paths and 4,096 retained application paths.
- At most 2 MiB retained path bytes and a 4 MiB JSON response.
- At most 8,192 running-app records considered; oversized snapshots are flagged.
- Initial metadata gathering uses notification/run-loop events with a five-second
  deadline, stops the query and removes observers. No continuous query or polling.
  These are caller retention/gathering limits, not a claim to bound all internal
  allocation or latency inside Apple's services.
- Rust validates the entire response schema, counts, paths and byte limits again.
  Existing inventory metadata/entry/plan limits remain in force.
- Unit tests inject candidate records and isolated app bundles; they never query
  the user's actual application registry or running apps. One linked-C guard test
  passes invalid arguments and returns before any Objective-C/native inventory
  operation. Wire tests cover malformed paths, counts and incomplete responses.
- Planner fixtures prove that native records replace folder crawling, outside
  policy paths are not opened, case aliases are deduplicated by native identity,
  missing identity remains unresolved, and unavailable/partial inventory does not
  trigger filesystem fallback.

Real NSWorkspace/Spotlight gathering and OS permissions require a separate
user-approved native refresh; synthetic tests are not that acceptance evidence.
