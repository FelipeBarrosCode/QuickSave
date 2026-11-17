# Threat model and safety boundaries

Scope: a local, user-invoked desktop/CLI backup tool. Read this with
[architecture](ARCHITECTURE.md) and the [review checklist](REVIEW-CHECKLIST.md).
These are required boundaries, not an independent security audit.
Native approval, alias/ACL hardening and envelope-v2 changes are under security
review/integration. Earlier passing checks do not accept the changed behavior.

## Assets and trust

Protect source files, existing destination data, historical snapshots, repository
and provider keys, and the truthfulness of success/recovery reports.

Trusted components are the authorized user, the local OS/native handle APIs and
reviewed cryptographic libraries. Source trees can change concurrently. Repository
bytes, manifests, paths, future cloud listings, profiles and webview messages are
untrusted inputs. A malicious/corrupt repository must not write outside an approved
destination or make the process allocate unbounded resources.

The initial threat model does **not** promise protection from an administrator,
kernel compromise, a compromised running application under the same user, key
capture from memory, hardware failure without an independent backup, or a hostile
filesystem that lies about native identity/durability. Network shares and removable
filesystems need separate capability/acceptance evidence.

Encryption is not metadata obliviousness. The initial repository exposes
repository identity, object/commit counts, encrypted lengths and filesystem
timing; object/index names use unkeyed plaintext-derived BLAKE3 hashes. An observer
can compare equality and test guesses of known content. File paths and snapshot
metadata belong inside authenticated encrypted records, but this does not remove
those content-address side channels.

## Threats and required behavior

| Threat | Boundary and response |
| --- | --- |
| Traversal, absolute/device/UNC paths, alternate streams or target-name collisions | Validate authenticated paths independently; reject unsupported components/encodings and platform aliases before writing |
| Symlink/reparse escape or swap between checking and using a path | Pin real native directory/file handles; use no-follow relative operations and identity checks; string prefix/canonicalization checks alone are insufficient |
| Same native root through a different namespace, or a key hardlink inside selected data | Require native `same_root`/`overlaps`/`contains_file_identity` checks and approved-namespace revalidation; pending hardening must not be replaced by lexical containment |
| Source mutation or tree membership changes | Compare native identities/stamps and re-enumerate before commit; fail capture on detected changes; never claim app-wide atomicity |
| Ciphertext substitution, tamper, truncation or wrong key | Authenticate repository identity and per-record context, check lengths/content/file hashes, fail without publishing unverified bytes |
| Record splicing across envelopes sharing key/context | Envelope-v2 update binds a fresh random 32-byte envelope ID into HKDF and every record's AAD; reject mixed envelopes and rerun security regressions before acceptance |
| Duplicate or corrupt content already in the repository | Verify before reuse; dedup only within a repository/key; no cross-user/global plaintext cache |
| Crash/disk-full during backup | Referenced content precedes immutable commit; no success before required syncs; incomplete snapshots stay uncommitted |
| Restore over existing user data | Initial slice accepts empty target only, uses exclusive new-file publication and refuses overwrite; no claimed multi-file rollback |
| Existing destination changes after preflight | Native no-overwrite operations still apply; fail, preserve unrelated entries and report any operation-owned output left behind |
| Oversized/deep trees, manifests, envelopes or decompression bombs | Fixed entry/depth/document/record/chunk bounds and streaming; reject rather than raise a global guard |
| Secret exposure through UI/settings/process arguments/logs | External key files initially; key bytes stay native; no Debug/Serialize of keys, plaintext master-key settings or key-valued CLI arguments |
| Extended ACL permits another principal to access a nominally private key | macOS hardening rejects extended ACLs before secret-writing callbacks and verifies imported keys with `verify_private_file`; do not infer privacy from mode bits alone |
| Webview invokes native file/key operations without approved scope | Require exact-scope native confirmation through `authorize_operation`, single-use expiring `approvalId` and pinned-root/file proofs; status/history confer no authority |
| UI false success or overlapping operations | Native result/status is authoritative, off-thread work is joined, conflicting mutation admission is serialized; no fake events/progress |
| Admission flooding or quit racing with accepted work | Two query slots, one native-dialog lane, one mutation lane; receipt work off GUI thread and atomic shutdown admission; integration tests still required |
| History loss or rollback by repository storage | Additive application behavior; AEAD does not prevent a storage owner deleting/replaying valid data; independent recovery backup/trusted checkpoints are future requirements |
| Watcher event loss or process/PID reuse | Watchers are future hints, not completeness proof; explicit loss/restart epochs invalidate trust and force a scan |
| Future credentialed subprocess/provider compromise | Narrow allowlisted arguments, isolated explicit configuration, bounded output/time/concurrency and no shell interpolation; unavailable providers stay unsupported |

## Desktop approval is scoped, temporary authority

The native confirmation must show the operation and exact repository, key-file
and applicable source/destination/snapshot scope. Its opaque approval token is
single-use, expires after at most 10 minutes, and is subject to a 32-outstanding
approval bound. Missing/expired/replayed tokens, scope substitutions and changed
native root/file proofs must fail closed. A webview confirmation, receipt or
operation ID is not an alternative grant. Desktop initialization, backup, listing
and restore all require the new handshake; the CLI's explicit command API stays
unchanged and still enforces the shared native safety checks.

This limits native authority granted to the webview; it does not make a
compromised OS trustworthy, remove the need to inspect the native dialog, or prove
the integration is race-free. Token replay/expiry, path/file replacement, bounded
admission and quit/admission races require post-change testing. Neither keys nor
reusable approval IDs belong in status/history, settings or logs.

## Recovery-key handling

The first slice requires a user-selected external recovery-key file; this is not
native vault protection. Create without overwrite, restrict permissions where
available, reject unsafe key paths, and keep it outside repository and source.
Do not scan the real home directory to find keys. A user who selects the file is
granting use for that operation, not permission to import No Land's credentials.
The ACL/private-file and native file-identity containment changes are still
undergoing integration; do not claim their native acceptance from earlier tests.

A copied repository without its key is intentionally not recoverable. A key stored
only on the same failed disk is not disaster recovery. Future vault support must
include verified external recovery/export, locked-vault behavior, failure-safe
migration and distinct QuickSave vault identifiers. It must not silently generate
a new key when unlocking the existing key fails.

## What the first slice does not guarantee

- Consistent live databases, registry hives, app state or a set of simultaneously
  changing files; application-aware quiescence/native snapshots are future work.
- Complete OS/application reconstruction, launchability, credential migration,
  ACL/xattr/resource-fork/ADS fidelity or cross-OS executable compatibility.
- Automatic cleanup of a partial multi-file restore, overwrite rollback or
  power-loss-atomic whole-directory recovery.
- Native vault protection, cloud confidentiality beyond the reviewed encryption
  format, provider durability, remote writer fencing or multi-machine correctness.
- Windows durable/private writes, unsupported compression/metadata encodings, or
  safe decoding of unknown format versions. Explicit refusal remains required.
- Automatic deletion, retention pruning, cloud quota reclamation or source removal.
- Product readiness from a compilation result or another project's test history.

## Work-environment restrictions

Run tests only in their own temporary roots and synthetic state. Never access
production cloud profiles, credentials, keys, app state or remote machines.
Do not follow links from the test fixtures into real directories. No remote
repository creation, push, merge, release, signing or paid-resource use is
authorized. `upstream/no-land/` and any other No Land worktree remain untouched.
