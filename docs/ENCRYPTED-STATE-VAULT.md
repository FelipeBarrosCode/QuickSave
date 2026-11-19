<!-- SPDX-License-Identifier: GPL-3.0-only -->
# Encrypted workspace vault

This is the user-approved replacement for per-account QuickSave vault storage.
It does **not** put plaintext keys, provider tokens, passwords, or native
authorization registry records in `state.json`.

## Using it

Restart the updated desktop app. A legacy workspace first shows **QuickSave
secret storage**, before workspace workers start. Choose **Encrypt QuickSave
secrets** and review the native confirmation. Migration runs only after that
one-use approval; success starts normal workspace loading.

Choosing **Continue without migration** retains legacy storage and starts the
normal workspace. Migration is then unavailable in that process; restart to
return to the pre-worker gate. Errors/cancellation stay at the gate without an
automatic retry. An already encrypted workspace starts normally, but local
format metadata is not proof that its native key is available.

### If migration stops

The desktop now reports a fixed migration phase and, when available, a numeric
native OS status. It never forwards credential values, account names, raw native
error bodies or private paths. A Keychain authorization error such as `-25308`
or `-25293` means the required access was not granted. Background requests cannot
prompt; explicit migration can request authorization, which the user or OS may
still deny. Consolidation does not bypass authorization. An already-encrypted state reports that
migration must not be repeated; restart or explicit recovery may be needed.

Diagnostic failures are tested using injected vaults. A phase-specific message
is evidence about a user's attempted operation, not permission for an automatic
retry, native-vault probing, resetting keys or weakening access controls.

## Storage and authority

- Existing non-secret workspace metadata stays readable.
- `encryptedSecrets` holds bounded XChaCha20-Poly1305 ciphertext, not secret
  values. It is excluded from service/IPC snapshots.
- One active native item, `QuickSaveEncryptedStateVault.v1` in QuickSave's
  existing namespace, holds the encryption key and mutable revision/digest anchor.
  It is bound to the actual native workspace-directory identity.
- Ciphertext AAD binds format, native workspace identity, and secret revision.
  Fresh random 24-byte nonces are generated for every encryption.
- A native anchor is reread for authority decisions. A local file's generation,
  an old decrypted map, or a cached key is not current revocation authority.
- Missing native items, modified ciphertext, older state, incompatible formats,
  and missing anchor-selected slots fail explicitly. They do not create a
  replacement key or fall back to old accounts.

The private native state file and existing OS lock remain authoritative for
serialization. Secret operations borrow that held lock through explicit
`SecretAccess` contexts; they do not recursively lock the state file.

## Independent durability and recovery

Secret mutations may need to remain durable even if an outer metadata update
fails—for example, revoking a tracking grant must not be undone by a later error.

1. Encrypt the candidate secret map and preflight the complete bounded state.
2. Durably publish current and candidate ciphertext slots with the **previously
   persisted** metadata.
3. Read back the exact state.
4. Update the single native anchor to select the candidate; verify read-back.
5. A later metadata publication merges the selected slot, never a stale copy.

The native anchor is the secret commit selector. A crash before anchor commitment
leaves the old slot selected; after commitment it selects the candidate even if
normalization has not run. An ambiguous native write is not compensated by
restoring the old key or anchor. If the selected slot cannot be authenticated,
the operation fails closed. This is not a claim of universal power-loss
acceptance or atomic transactions across a filesystem and credential service.

The existing 8 MiB state cap remains in force. Decrypted payloads have a 2 MiB
limit, at most 4096 accounts, bounded names/values, duplicate-account rejection,
and zeroizing plaintext buffers/maps. Prepared two-slot encoding must fit before
native anchor mutation. Oversized migrations fail rather than truncate.

## Explicit migration

Migration is a separately approved native action, never automatic on startup.
The native ticket binds the workspace's native identity and metadata generation;
both are rechecked under the state lock before credential reads.

Migration inventories **all** QuickSave accounts, including inactive and retained
work authority not reachable from current settings. It reads and revalidates the
complete inventory, then initializes encrypted state and the new anchor. It does
not inspect No Land's namespace, alter/delete old QuickSave items, connect
providers, upload, or change source-file permissions.

After migration, missing aggregate entries never read old accounts. Restoring an
old state without `encryptedSecrets` is also rejected while the native anchor
exists; otherwise preserved legacy items could resurrect obsolete permissions.
Removing the anchor is not a supported reset operation.

## Platform and prompt limits

- **macOS:** bounded attribute-only inventory targets QuickSave's service in the
  same user keychain used by `keyring`. Ordinary/background reads remain
  noninteractive. The separately approved migration uses a private backend that
  allows OS authorization only while holding the process-wide native-vault mutex.
  A drop guard restores noninteractive mode; failed restoration blocks further
  native access. No ACL bypass, password collection or Keychain unlock is used.
- **Linux:** bounded D-Bus metadata inventory targets QuickSave's exact service,
  including locked results and the backend's default/legacy collection rules.
  It does not start a secret session, activate/unlock a service, or read passwords
  during inventory. Actual Secret Service availability/authorization still matters.
- **Windows:** bounded service-confined legacy enumeration is unsupported.
  `CredEnumerateW`'s prefix-only filter cannot select the backend's
  `username.service` targets without broadly enumerating unrelated credentials.
  Migration must report unsupported rather than read unrelated entries or infer
  a falsely complete account list from current settings.

One active native item removes per-account native accesses **after migration**.
It does not guarantee that an OS will release that item, that existing items can
be migrated without authorization, or that development rebuilds preserve trust.
The main process permits Keychain dialogs only during separately approved
pre-worker migration operations. Old items may require several approvals; the
UI never promises a single password for the initial copy. Ordinary workers
remain noninteractive. Native authorization acceptance is not established merely
by testing the encrypted-state protocol and mocked interaction gate.

## Validation

Development tests use isolated temporary state and injected synthetic vaults.
They must never probe actual credential entries, real providers, or No Land
state. Unit tests and cross-compilation do not establish Windows/Linux native
credential-service or power-loss acceptance.
