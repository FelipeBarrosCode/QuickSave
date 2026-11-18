# Native OAuth, refresh and drive discovery

Original GPL-3.0-only code. Parent integration owns workspace membership, native
consent, trusted OS browser opening, credential-vault persistence and provider
health verification. No webview, subprocess, automatic account discovery, vault access,
production client IDs/secrets, remote provisioning, or frontend changes.

## Stable public integration API

```rust,ignore
use std::sync::Arc;
use anyhow::Result;
use quicksave_oauth::{authorize, OAuthRequest, OAuthTokens};

type Opener = Arc<dyn Fn(&str) -> Result<()> + Send + Sync>;

// Deliberately neither Debug nor Serialize nor Clone.
pub struct OAuthRequest {
    pub kind: String,
    pub client_id: String,
    pub client_secret: Option<String>,
}
pub struct OAuthTokens {
    pub access_token: String,
    pub refresh_token: Option<String>,
    pub expires_at: i64, // absolute Unix seconds
}

pub async fn authorize(
    request: OAuthRequest,
    open: Arc<dyn Fn(&str) -> Result<()> + Send + Sync>,
) -> Result<OAuthTokens>;

pub fn supports(kind: &str) -> bool;

pub async fn authorize_box_confidential(request: OAuthRequest, open: Opener) -> Result<OAuthTokens>;
pub async fn refresh(request: OAuthRequest, refresh_token: &str) -> Result<OAuthTokens>;
pub async fn discover_onedrive_drives(access_token: &str) -> Result<Vec<OneDriveChoice>>;
pub async fn discover_onedrive_drive(access_token: &str) -> Result<(String, String)>;
```

`supports` reports native **protocol support** for `google_drive`,
`microsoft_onedrive`, `dropbox`, and Box's **explicit confidential** flow.
Parent `ServiceOAuth.supports` can delegate here, select the correct explicit
entry point and perform checked vault persistence plus real provider health.
`authorize` never silently downgrades PKCE for Box: call
`authorize_box_confidential` after native consent with the user's own client
ID **and** secret. No production client registration is embedded or borrowed.

The browser opener runs **natively** with a generated, allowlisted HTTPS
authorization URL. It must use an OS-trusted URL opener, never an interpolated
shell command or a webview. It must return promptly; do not log its URL or errors.
This crate discards opener/HTTP/provider error details and never exposes codes,
tokens, verifiers, client secrets or callback contents in its errors.

After explicit native consent, call `authorize` with the user's own registered
desktop/public OAuth client. Persist returned tokens directly in the QuickSave
vault through `WorkspaceStore` using the No Land `o_auth2` type/value format.
Never serialize tokens into IPC responses or non-secret `state.json`. Token
receipt is **not** provider health verification or authority to bypass an imported
profile's read-only policy. Public structs zeroize their strings on Drop; move
fields using `std::mem::take` / `Option::take`, not destructuring a Drop type.

## Register the exact callback

- **Google Drive:** register a **Desktop app** client. The native listener binds
  `127.0.0.1:0` and uses the assigned ephemeral port plus a fresh random path.
  Google's desktop loopback policy is documented in its
  [native-app guide](https://developers.google.com/identity/protocols/oauth2/native-app).
- **Microsoft OneDrive:** use a public **Mobile and desktop application** client
  and register this exact URI, including spelling, fixed port and path:

  **`http://127.0.0.1:53682/quicksave/oauth/callback`**

  The Microsoft portal may require editing the application manifest to register
  the `http` IP-literal loopback URI; follow Microsoft's
  [redirect-URI rules](https://learn.microsoft.com/en-us/entra/identity-platform/reply-url#localhost-exceptions).
  Do not substitute `localhost`, another path/port, a SPA registration or a
  confidential web client.
- **Dropbox:** add the same exact URI above under the app's OAuth 2
  **Redirect URIs**, enable public clients and the required file scopes.
  Dropbox's [authorization reference](https://docs.dropboxapi.com/dropbox-api/docs/get-started/authorization)
  requires the requested URI to match a registered value.
- **Box:** register the exact URI above in a user-owned OAuth app and explicitly
  select its documented confidential authorization-code flow. A client secret
  is mandatory; no public-PKCE contract is claimed. Enable the necessary file
  read/write scopes on that registration; actual access is checked natively.

Port 53682 is bound **before** browser opening for Microsoft/Dropbox/Box. An occupied
or otherwise unavailable port fails closed before the opener; there is no
alternate port, random path, redirect, OOB flow or retry fallback. A recent
connection may leave the OS reserving this fixed port temporarily; start a fresh
sign-in only after it becomes available.

The registered callback URI is **public, not an authentication secret**.
Every attempt creates fresh 32-byte random state, compared in constant time.
Google/Microsoft/Dropbox additionally use S256 verifier/challenge binding; Box
uses its explicitly configured confidential client, without pretending it has
verified public PKCE support. Exact Host/path/loopback validation remains mandatory.

## Private refresh and OneDrive selection

`refresh` performs one allowlisted HTTPS POST, validates actual expiry and scope,
preserves an omitted refresh token and returns an actual rotation when issued.
There is no stale-token success fallback. Persist through
`WorkspaceStore::update_oauth_tokens_cas` before use; rclone's longer operations
use the checked storage handoff described in that crate.

OneDrive lists `/v1.0/me/drives`, with bounded, allowlisted pagination (8 pages,
256 drives, 256 KiB/page), no identity/account projection and no arbitrary URL.
This deliberately avoids `/me/drive`, which Microsoft documents may provision
a previously unprovisioned drive. Exactly one choice is automatic; multiple
choices stay native for a chooser. `OneDriveChoice` has no Debug/Serialize and
contains only native `drive_id`, `drive_type`, and name, never a bearer token.
The parent writes discovered IDs/types directly into the protected provider
fields; normal UI must not ask users to guess drive IDs.

## Bounds and tests

- Bind only `127.0.0.1`, before opening a browser; provider-specific ports above.
- Independent 32-byte OS-random state; PKCE providers use an independent S256
  verifier. Google's path is random; Microsoft/Dropbox/Box match registration.
- Exact GET request target/path and Host, loopback peer, no duplicate parameters,
  no request body/transfer encoding, 8 KiB headers, at most 16 rejected callbacks.
- Five-minute overall deadline, ten seconds per connection, thirty-second HTTPS
  token exchange. Static endpoints, rustls certificates, no redirects or retries,
  response body at most 256 KiB.
- Callback HTML is fixed, has no external resources and says only
  “Authorization received. Return to QuickSave.”
- Tests inject the HTTP transport and opener; only their own loopback sockets are
  allowed. No test calls public provider networks, launches a real browser,
  accesses accounts/vaults or reads No Land state.
- Fixed-port tests serialize owned listeners, verify the exact registered URI
  and fresh state/challenge on each attempt, and prove occupied-port failures
  never invoke the opener. Pure parser tests reject forged state/path/Host at the
  public fixed URI. They never connect to an existing local service.

Parent may run `cargo test -p quicksave-oauth` after adding workspace membership.
This agent does **not** run Cargo builds/tests. Protocol tests are not disposable
registered-client acceptance; no provider or cross-platform acceptance is claimed.

Official provider sources, supported kinds, exact endpoints/scopes, PKCE and
redirect-registration constraints are recorded in `PROVENANCE.md`.

The registered-path mismatch has been resolved by the provider-specific policy
above. Actual disposable-client/provider acceptance remains **unclaimed**.
