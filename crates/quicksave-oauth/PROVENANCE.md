# OAuth protocol provenance and limitations

Reviewed **November 17, 2026**. All Rust in this crate is original
**GPL-3.0-only** implementation, not copied from No Land or an OAuth SDK. Existing
repositories/snapshots and remote lifecycle code were not modified or executed.
No production client registrations or credentials were used. Documentation is reference data, not
permission to operate an account.

## Primary protocol sources

1. [RFC 7636](https://www.rfc-editor.org/rfc/rfc7636):
   32 random bytes encoded as a 43-character base64url verifier; challenge
   `BASE64URL(SHA256(verifier))`; S256 only, never downgrade to plain. The
   Appendix B verifier/challenge pair is used only as a public test vector.
2. [RFC 8252](https://www.rfc-editor.org/rfc/rfc8252):
   native system browser, pre-bound IP-literal loopback listener, PKCE and no
   embedded authorization webview; listen only for the active flow. Google uses
   an ephemeral port. Microsoft/Dropbox use QuickSave's fixed registered URI
   below to match their registration rules; no arbitrary-port fallback occurs.
3. [RFC 6749](https://www.rfc-editor.org/rfc/rfc6749):
   authorization-code response, request/response state binding, form-encoded
   HTTPS token exchange, token lifetimes and scope semantics.
4. [reqwest 0.12.24 ClientBuilder](https://docs.rs/reqwest/0.12.24/reqwest/struct.ClientBuilder.html):
   `https_only`, rustls, disabled redirects, **explicit `retry::never()`**
   (default reqwest behavior can retry protocol NACKs), total request timeout,
   no proxy discovery, no verbose connection logging or decompression.

## Google Drive — `google_drive`

- [Desktop OAuth documentation](https://developers.google.com/identity/protocols/oauth2/native-app)
  verifies system-browser desktop loopback flow, S256, authorization endpoint
  **`https://accounts.google.com/o/oauth2/v2/auth`**, token endpoint
  **`https://oauth2.googleapis.com/token`**, `code_verifier`, optional desktop
  client secret, `expires_in`, refresh tokens and bearer response type.
- [Drive API scope reference](https://developers.google.com/workspace/drive/api/guides/api-specific-auth)
  defines **`https://www.googleapis.com/auth/drive`**. This is a **restricted,
  full-Drive scope**, not an app-folder-only grant. It is selected because the
  configured No Land-compatible storage prefix may already contain backup files
  not created by the newly registered OAuth client. `drive.file` would not grant
  general access to those preexisting files. The provider's own consent screen
  must disclose this permission; the client owner must satisfy Google's consent,
  test-user and verification rules.
- The crate requests `access_type=offline` and `prompt=consent`; a refresh token
  remains an optional actual server result, not a fabricated guarantee.
- Use a user-owned **Desktop app** client registration, not a mobile, SPA or
  confidential web registration. No Google production registration is embedded.
- The native listener binds `127.0.0.1:0` before opening the browser, using the
  assigned ephemeral port and an independently random callback path.

## Microsoft OneDrive — `microsoft_onedrive`

- [Authorization-code protocol](https://learn.microsoft.com/en-us/entra/identity-platform/v2-oauth2-auth-code-flow)
  documents S256, native/public clients, `response_mode=query`,
  `offline_access`, and these static common-tenant endpoints:
  **`https://login.microsoftonline.com/common/oauth2/v2.0/authorize`** and
  **`https://login.microsoftonline.com/common/oauth2/v2.0/token`**.
- [Graph permission reference](https://learn.microsoft.com/en-us/graph/permissions-reference#filesreadwrite)
  defines delegated **`Files.ReadWrite`**, permitting operations on the signed-in
  user's files. The requested string is
  **`offline_access https://graph.microsoft.com/Files.ReadWrite`**.
  No tenant-admin, Sites, all-users, identity/profile or application permissions
  are requested. Other users' shared/document-library roots may require separate
  permissions and must fail health checks rather than silently widen this scope.
- Microsoft's native/public flow must **not** use a client secret; supplying one
  for this kind is rejected. Use a user-owned Mobile and desktop application
  registration, not a SPA or confidential web registration.
- [Redirect registration restrictions](https://learn.microsoft.com/en-us/entra/identity-platform/reply-url#localhost-exceptions)
  permit ephemeral loopback ports and recommend `127.0.0.1`, whose HTTP URI may
  need manifest editing, but the **path must match the registered redirect URI**.
  QuickSave therefore selects the public, fixed registered URI
  **`http://127.0.0.1:53682/quicksave/oauth/callback`**. The client owner must add
  that URI to their public-client app registration, editing the manifest if the
  portal blocks HTTP IP-literal loopback redirects.
  The port is bound before browser opening; collision fails closed with no
  random port/path, wildcard, weakened matching or different OAuth flow.
  This URI is QuickSave's registration policy, **not a vendor-issued secret or
  claim that Microsoft has accepted a particular client registration**.

## Dropbox — `dropbox`

- [Dropbox authorization reference](https://docs.dropboxapi.com/dropbox-api/docs/get-started/authorization)
  verifies PKCE S256, the authorization endpoint
  **`https://www.dropbox.com/oauth2/authorize`**, token endpoint
  **`https://api.dropboxapi.com/oauth2/token`**, code/verifier/client-ID POST,
  `token_access_type=offline`, `expires_in`, optional refresh token and bearer
  type. The more general guide has a contradictory sentence about replacing the
  client ID; the concrete **PKCE token-request example** in the reference sends
  both `client_id` and `code_verifier`, which this crate follows.
- [Dropbox OAuth guide](https://developers.dropbox.com/oauth-guide) documents
  native PKCE, registered redirect URIs, and the App Folder / Full Dropbox
  registration choices. Prefer App Folder registrations when the configured
  backup prefix fits; Full Dropbox access is a separately consented registration
  choice for preexisting backup folders.
- Exact requested scopes:
  **`account_info.read files.metadata.read files.content.read files.content.write`**.
  This is the documented file backup/read/write set, not team/admin/sharing
  permissions. The user's registered app must enable these scopes and public
  clients. PKCE does not use a client secret for this provider.
- The reference requires the **exact registered redirect URI**, even localhost;
  QuickSave requests only
  **`http://127.0.0.1:53682/quicksave/oauth/callback`**. The client owner must add
  it exactly under the app's OAuth 2 Redirect URIs, enable public clients and the
  required scopes. The native listener binds that fixed IP/port before opening a
  browser and refuses collisions with no alternate URI/port/path.
  No assumption about Dropbox's ephemeral-port exceptions is now needed.
  No copy/paste code fallback, confidential-client fallback or less secure flow
  is implemented. Disposable registered-client acceptance remains unclaimed.

## Box — `box`: explicit user-configured confidential flow

- [Box public OAuth without SDKs](https://developer.box.com/guides/authentication/oauth2/without-sdk.md)
  documents **`https://account.box.com/api/oauth2/authorize`** and
  **`https://api.box.com/oauth2/token`**, with client-secret code exchange.
  It does **not** document a public-client S256 verifier/challenge contract.
- [Box app setup](https://developer.box.com/guides/authentication/oauth2/oauth2-setup.md)
  requires exact scheme/domain/path/query matching; loopback port may vary.
- [Box scopes](https://developer.box.com/guides/api-calls/permissions-and-errors/scopes.md)
  defines registration permissions. No undocumented scope or public-PKCE claim
  is fabricated here. The user explicitly chooses
  `authorize_box_confidential`, supplies their own client ID/secret, configures
  read/write permissions and registers QuickSave's exact loopback redirect.
  The normal PKCE entry point still rejects Box before opening a browser; there
  is **no automatic downgrade or embedded client secret**.
- Rechecked the official [without-SDK guide](https://developer.box.com/guides/authentication/oauth2/without-sdk/)
  and [app setup guide](https://developer.box.com/guides/authentication/oauth2/oauth2-setup/)
  on November 17, 2026. Their documented client-secret code exchange is used.

## Native OneDrive discovery and No Land code references

- [List drives](https://learn.microsoft.com/en-us/graph/api/drive-list?view=graph-rest-1.0):
  `/me/drives` supports delegated Files.ReadWrite and bounded paging.
- [Get drive](https://learn.microsoft.com/en-us/graph/api/drive-get?view=graph-rest-1.0):
  `/me/drive` may provision a missing drive; discovery deliberately does not use it.
- Read-only CODE references: `no_land/src-tauri/src/services/shared_storage/`
  `provider_profiles.rs`, `oauth_flow.rs`, and the proactive-refresh section of
  `shared_storage_manager.rs`. They establish the No Land credential/session
  shape, independent repository-key lifetime and concrete OneDrive fields.
  The new implementation does not copy their logging, stale-token fallback,
  secret serialization, remote execution, or default registrations.

## Acceptance and privacy boundaries

The service's assigned `src/oauth.rs` now uses the pure parsed/canonical origin
validator and explicit Box confidential selection. Its new Windows opener uses
the documented Win32 Shell/COM handoff, not a command interpreter or guessed
browser executable. ABI references, bounded-wait/unknown-outcome behavior and
unclaimed Windows acceptance are recorded in [`WINDOWS-OPENER.md`](WINDOWS-OPENER.md).

- Parent-directed provider policy resolves the registered-path mismatch while
  preserving strong per-attempt proofs: the fixed callback URI is public, not a
  secret. Fresh independent 32-byte state, constant-time state comparison and
  exact Host/path/loopback matching remain authoritative. PKCE providers use a
  separate verifier and S256; explicitly configured Box uses its documented
  confidential client without claiming PKCE. Google retains a random path;
  Microsoft/Dropbox/Box do not randomize their registered callback URI.
- `supports` includes Google Drive, Microsoft OneDrive, Dropbox and explicitly
  configured confidential Box. It does not replace checked native vault refresh
  handoff or service provider-health verification.
- An occupied fixed port, including a temporary OS socket reservation after a
  recent connection, is an explicit failure before browser launch. Address reuse
  is disabled; no automatic rebinding/fallback weakens collision behavior.
- Tests use injected opener/HTTP transport and synthetic tokens; they may open
  only their own loopback sockets. There are no provider-network tests.
- Callback response HTML says **“Authorization received. Return to QuickSave.”**
  It does not say connected, saved, verified, or granted write authority.
- Actual disposable-client authorization, native packaging, OS opener behavior,
  provider compatibility and Windows/Linux execution remain unaccepted.
- Zeroizing Drop covers crate-owned request/token strings, temporary callback
  buffers and form/response copies. It does **not** claim memory locking,
  elimination of allocator/HTTP/TLS-library copies, protection from process
  inspection, or control of a caller's logging/opener code.
- The native opener must return promptly, never panic/log private data, and not
  launch shell commands. Rust cannot forcibly stop an already-running blocking
  OS call; the authorization future still has a five-minute deadline and closes
  its listener on cancellation/timeout.
