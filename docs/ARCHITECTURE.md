# Architecture and format boundaries

## Software/provider workspace revision

The current desktop revision is specified in
[WORKSPACE-V2-CONTRACT.md](WORKSPACE-V2-CONTRACT.md); its acceptance evidence and
remaining limitations belong in
[WORKSPACE-V2-ACCEPTANCE.md](WORKSPACE-V2-ACCEPTANCE.md).
The local-preview architecture below remains relevant to the CLI, but does not
describe the new cloud workspace or imply that the two formats interoperate.

```text
Overview / Backup / Restore
    -> native workspace_query / workspace_prepare / workspace_execute
    -> quicksave-service
         + quicksave-state: private state.json, vault references, scope grants
         + quicksave-tracking: approved roots, reconciliation, autosave scheduling
         + quicksave-noland -> shared-storage: adapted native No Land libraries

CLI -> quicksave-client -> quicksave-engine -> local QuickSave preview format
```

`upstream/no-land/` is still immutable reference material. `shared-storage/` is
the separate active library fork: no remote lifecycle service, SSH provisioning,
or production No Land state is part of native workspace initialization. The cloud
path reuses the No Land wire format and repository keys, rather than treating
the independent local preview format as compatible.

The webview may submit transient provider fields, but never receives repository
key bytes, OAuth refresh tokens, or vault entries. Native preparation binds the
exact request to a deterministic authority snapshot, shows a native confirmation,
then pins real selected roots/files. Execution accepts only the opaque one-use
ticket. Tickets expire after ten minutes, are capacity-bounded, and are consumed
before filesystem/provider IO; a changed scope fails instead of being widened.
Cancellation of an IPC future does not detach its lane or shutdown guard.
The gateway hands prepared native IDs/stamps to service workers as protected
native-only metadata, preventing a re-pin from authorizing a replacement path.

Persistent manual tracking and autosave need authenticated scope grants, not
editable `state.json` booleans. Root identity, explicit file allowlists, software
identity, provider scope, and grant revocation must survive restart and be
revalidated by owned capture workers. Watcher events are hints; scanning a UI
list cannot establish a confirmed uploaded baseline. A change during upload,
overflow, failed capture, or unsupported local deletion remains pending.

No Land import is an explicit, read-only source operation into QuickSave's own
vault namespace. Imported connections start read-only; uploads require a separate
native write grant. Disconnecting does not remove cloud history or recovery keys.
QuickSave does not automatically run No Land's post-upload generation retirement.
Physical cloud deletion is a separate frozen-preview/dependency-acknowledgement
protocol, not an autosave side effect.

These are implementation boundaries, not cross-platform or live-provider
acceptance claims. Closing an autosave-enabled window hides it; macOS Dock
activation reopens it. Explicit quit is blocked during active/finalizing work,
then joins the tracker and owned queue before exit. Keep QuickSave running for
its in-process background worker; a separate OS login service is not implied.

## Initial local-preview architecture (retained CLI path)

Read [the plan](PORTING-PLAN.md) for sequencing and
[the implementation contract](IMPLEMENTATION-CONTRACT.md) for current APIs.
This document separates first-slice invariants from future format requirements.
The security-review updates below are being integrated; their description is not
post-change test acceptance. See [the evidence checkpoint](VALIDATION.md#security-review-checkpoint-not-final-acceptance).

## Layers

```text
Desktop webview (non-secret selections and operation summaries)
             -> Tauri native commands --+
CLI -----------------------------------+--> quicksave-client
                                                |
                                         quicksave-engine
                                           /          \
                              quicksave-platform   quicksave-content
                                native handles     chunks/hash/AEAD
                                      |
                               local repository
```

The parent workspace contains the platform/content/engine, integrations, shared
native client, portable approval/admission control, and CLI crates. The Tauri backend
has a separate manifest and native build dependencies. `upstream/no-land/` is
reference material, **not** a workspace member or linked runtime implementation.
Copying a reviewed algorithm requires a provenance notice; executing No Land
services, provisioning, remote RPC and lifecycle control are outside this design.

### Authority boundaries

- The webview supplies selections, not trusted manifest paths or key bytes.
- The backend/CLI opens external recovery-key files without logging their contents.
- The engine validates repository/source/destination separation, authenticates
  repository identity and manifests, and admits conflicting mutations safely.
- The platform adapter owns pinned directory/file handles, native identity checks,
  no-follow traversal, bounded enumeration and no-overwrite publication.
- The content layer accepts bounded byte records and authenticated context. It has
  no authority to discover the user's home or write arbitrary files.
- Configuration, manifests, ciphertext, profile definitions and future remote
  listings remain untrusted even when syntactically valid. Authentication does not
  make a path safe.

`quicksave-client` owns external-key-file validation and shared native entry
points. Its desktop operation manager uses private immutable JSON start/finish
receipts and owned workers. Receipt admission/persistence must run off the GUI
thread; atomic shutdown admission must prevent quit racing with accepted work,
and owned workers must be joined. These are security-review integration
requirements, not a completed shutdown/crash acceptance result. This is a
foreground application, **not** a standalone background daemon or an assertion
that the upstream SQLite database was ported.

`quicksave-integrations` currently provides read-only installation metadata
discovery and static profile/provider descriptions. These grant no capture
authority, and described cloud providers are not working transports.

`quicksave-control` owns the exact-scope token store, pinned proofs, bounded
worker lanes and shutdown admission. Tauri supplies the real native confirmation
dialog and calls that shared policy. Policy tests therefore exercise production
code without linking a GUI/WebKit test executable.

### Native desktop approval boundary

The updated desktop flow is:

1. Request `authorize_operation` for the exact operation and scope: repository,
   recovery-key file, applicable source/destination, and restore snapshot ID.
2. Show that exact scope in a **native confirmation dialog**, not a webview-only
   confirmation. Declining grants no authority.
3. On approval, issue an opaque, single-use `approvalId`, valid for at most
   **10 minutes**, with at most **32** outstanding approvals. Retain pinned-root
   and relevant file-identity proofs; a path string is not the proof.
4. Require that `approvalId` on desktop initialize, backup, list and restore
   invokes. Reject missing, expired, replayed or mismatched approval and revalidate
   native proofs before using the approved scope. Changing any scope requires a
   new native approval.

The UI wrapper must follow this handshake; an older direct invoke is not an
authorized fallback. Status/history are observation only: they contain no keys
or reusable approval authority, and editing a receipt cannot authorize an
operation. Approval IDs must not be persisted in status/history or logs.

Admission is bounded to **two query operations**, **one native-dialog lane** and
the existing single mutation lane. Proof checks and receipt work must not block
the GUI thread. These boundaries and their replay/expiry/scope/shutdown tests
are being integrated; a prior native compilation does not accept them.

The **CLI command API is unchanged**: explicit user invocation supplies scope
without a desktop `approvalId`, but still goes through shared key-file, overlap,
native-handle, authentication and overwrite checks. Native approval is not a
replacement for those checks or a guarantee against a compromised OS.

## First local data path

**Initialize:** create a new QuickSave namespace, generate a repository key, and
persist authenticated identity/format information. Never initialize over an
existing No Land or unknown nonempty repository. Recovery-key creation must not
overwrite an existing file; keep it outside both repository and capture source.
Before writing secret material, the private-directory/file policy must be
established. The macOS security update rejects extended ACLs before a secret
writer is invoked; imported keys use `verify_private_file`. Unix mode bits alone
must not be presented as proof that an extended ACL grants no other access.

**Capture:**

1. Approve and pin disjoint source/repository roots; enumerate a bounded tree.
2. Open each regular file without following links; record native identity,
   size and modification information.
3. Stream FastCDC chunks and file hashes; encrypt bounded records using reviewed
   cryptographic libraries and repository-specific authenticated context.
4. Reuse content only within the same repository/key after integrity checks.
5. Revalidate file identities and the selected tree before publishing a snapshot.
   Detection of a changed tree/file is failure, not a partial successful snapshot.
6. Publish the immutable snapshot commit only after all referenced content is
   durably written. Abandoned new objects must not make an uncommitted snapshot
   appear in the restore list.

The in-progress native alias checks use `SafeRoot::same_root`,
`SafeRoot::overlaps` and `SafeRoot::contains_file_identity` to bind decisions to
native roots/file identities, including a key-file alias inside a selected tree.
String equality/prefix checks do not suffice. Revalidation must also bind the
approved namespace to the pinned objects, rather than accepting a replaced name.
These changes need their own post-change native race/alias/ACL tests.

This is a stable-file capture check, not a multi-file transaction: a writer may
produce mutually inconsistent files without crossing the checks' observable
boundaries. Ask users to close the relevant application. Do not label this VSS,
APFS, Btrfs or application-consistent capture.

**Restore:**

1. Authenticate repository identity and the selected commit/manifest; validate
   bounds, chunk references, duplicate names, path components and target collisions.
2. Approve an empty destination and pin its handle. Refuse a nonempty target
   before writing. The first slice does not overwrite or merge existing data.
3. Authenticate each complete content record before use; reconstruct through the
   confined platform writer and verify file size/hash before publication.
4. Sync verified output and report completion only when publication succeeds.
   An interrupted multi-file restore may leave this operation's already published
   new files; do not claim whole-tree rollback or crash-atomic restore.

No cleanup may remove unrelated entries or historical snapshots.

## QuickSave-native repository

The format is **not No Land-compatible**, despite reused algorithms. New format
magic, versioning and cryptographic domain separation prevent accidental import
or cross-repository record substitution. Unknown format versions fail explicitly.

### Implemented preview layout

| Path | Meaning |
| --- | --- |
| `quicksave.repository.json` | Public format/version/repository ID and encrypted repository-key check; initialization publishes this last |
| `quicksave/writer.lock` | Native advisory writer lock on a pinned handle; not a remote-writer fencing protocol |
| `quicksave/objects/<hash>.qsobj` | Authenticated encrypted content chunks, addressed by plaintext BLAKE3 |
| `quicksave/indexes/<hash>.qsidx` | Authenticated encrypted bounded per-file chunk indexes |
| `quicksave/commits/<uuid>.qscommit` | Authenticated encrypted immutable snapshot manifest/summary; published after all references |

The repository format identifier is `QuickSave.Local.Encrypted`, version `1`.
Record context binds that version, repository ID, record kind and object/commit ID.
The content envelope is independently versioned. The security-review update is
**envelope v2**, with a fresh random **32-byte envelope ID** bound into key
derivation and every record's authenticated data. This must prevent splicing
records between independently sealed envelopes even under the same key/context;
record authentication without envelope identity is not a sufficient test.
Post-change security tests are pending, and earlier v1 results are not v2
acceptance or a compatibility/migration promise. Precise framing, compression,
cryptographic domains and bounds are recorded in
[`quicksave-content/PROVENANCE.md`](../crates/quicksave-content/PROVENANCE.md).

### Preview resource limits

| Scope | Limit under integration |
| --- | --- |
| Engine tree | 250,000 entries |
| Engine aggregate path budget | 32 MiB |
| Snapshot commit plaintext | 64 MiB |
| Per-file index plaintext | 16 MiB |
| Content chunk plaintext | 8 MiB |
| Content-envelope total plaintext/global metadata ceiling | 512 MiB, unchanged |
| Individual envelope record plaintext | 16 MiB, unchanged |

The more restrictive caller/content limit always applies. These ceilings are
rejection bounds, not memory-use targets or proof that every tree below the
entry count fits its metadata/path budgets. An added **186,735-file in-memory
fixture is unrun** at this checkpoint; it is not a filesystem-scale backup or a
performance result. CI serializes workspace tests to bound overlapping fixtures.

Compression is a content-envelope policy, not upstream pack compatibility,
configurable whole-repository compression or a promise that every input shrinks.
Unsupported compression encodings/flags must fail explicitly; decompression
must remain authenticated and bounded. No claim of an accepted compression or
record-splicing regression suite is made for the changed envelope.

There is no mutable `LATEST` pointer and no retirement/GC step. Unix output is
private new files/directories, not a promise to preserve original modes, ACLs,
xattrs, hardlink relationships or application launchability.

Current serialization is defined by the engine code and its tests. Before
declaring the format stable, freeze complete wire-format/golden fixtures covering:

- repository ID, format version, algorithm IDs and bounded encoding;
- key verification and key-derivation/authenticated-context domains;
- record envelope, nonce/tag handling and plaintext/ciphertext maxima;
- content ID, chunk sequence, full-file hash and file-length invariants;
- manifest/commit identity, metadata limits and immutable publication ordering;
- supported path subset and collision rules;
- incomplete publication/restart behavior and compatible reader versions.

Committed snapshots are additive. Local staging and deduplication are not
retention policies. Replaying an older valid repository state or removing history
cannot generally be detected without a separately trusted checkpoint; AEAD alone
does not solve rollback/deletion attacks.

Object/index filenames currently contain unkeyed plaintext-derived BLAKE3 content
IDs. Encryption therefore does not hide content equality or prevent an observer
from testing guesses of known content. Repository IDs, object counts, encrypted
lengths and filesystem timing are also observable. A future keyed-address/privacy
change requires a separately versioned format and migration review.

## Planned versioned OS/path manifest

**This is a design requirement for expanded profiles, not a claim that the first
slice already serializes all fields below.** Version the repository, manifest,
path encoding and profile schema independently. Readers reject unsupported
required versions/features instead of silently dropping metadata.

| Field group | Required meaning |
| --- | --- |
| `manifest_version`, `required_features` | Explicit compatibility gate, including restore-relevant metadata |
| `source_platform` | OS, architecture and native path/metadata model version; not permission to execute source binaries |
| `path_model` | Encoding and normalization rules, component/separator policy, case/collision behavior |
| `roots` | Stable profile/root identifiers and semantic roots; target mappings are separately approved |
| `entries` | Root ID, relative component path, entry kind, size/hash/chunks and declared metadata |
| `capture` | Actual consistency method and validation evidence; unsupported metadata and exclusions |
| `profile` | Profile ID/version, selected scope and prerequisites; no credentials or executable hooks |

Root examples are Windows Known Folder IDs, macOS application-support/container
roots, Linux XDG roots and explicit user-selected directories. A source path hint
is display-only, never restore authority. Store no usable master key in metadata.

The initial UTF-8 portable subset may reject non-UTF-8 names, Windows reserved
names/streams, traversal, special files and links. A later OS-native name encoding
requires a new reviewed path-model version and collision tests; lossy conversion
is not acceptable. A slash in serialized relative paths is not proof that a path
has the same meaning on all operating systems.

Cross-OS recovery must preview unmappable roots, case-folding/Unicode collisions,
unsupported permissions, alternate streams, ACLs/xattrs/resource forks, hardlinks
and symlinks. Default to refusal for required semantics, not a silently degraded
“full application restore.”

## Later adapters

- **Observation:** event streams are hints with bounded queues and gap epochs;
  reconcile after overflow, restart, lost permissions or mount replacement.
- **Consistency:** native snapshots/reflinks or application-quiescence hooks require
  their own capability and recovery tests. Copying is not atomic by renaming it.
- **Vault:** native vault references in non-secret settings; explicit verified
  recovery export. Unlock failure must not create a replacement empty repository.
- **Cloud:** narrow transport interface, bounded processes, credential lifetime,
  immutable content/commit upload, remote identity and concurrent-writer conflicts.
  No remote-shell execution or automatic history retirement.
- **Transactional restore:** durable intent/rollback journals and restart recovery
  before enabling overwrite. Reuse upstream design evidence, not its service paths
  or an unsupported claim of its existing guarantees.
