# Required native publication contract (service/tracker handoff)

Use:

```rust,ignore
engine.upload_captured_guarded(
    access, original_metadata_work,
    Arc::new(move || -> anyhow::Result<()> { /* fresh native authority */ }),
    original_native_controller,
).await
```

`upload` without a guard explicitly fails. Receipt-backed restart requires the
typed original-work recovery protocol, not `retry_guarded` plus a newly captured
tree. A missing native owner is not reconstructed from editable JSON.
Do not capture the whole service/engine in the closure (avoid an ownership cycle).

The synchronous `Send + Sync` callback is invoked at submission and by the actual
source backup worker after capture, immediately before manifest commit and again
immediately before catalog publication. It must revalidate the persisted provider
binding/write authority, software tracking grant, root identities/source scope,
and the exact autosave grant when automatic. Return Err on revoked/changed
authority. A post-commit monitor is not a publication guard.
The native source session also rechecks after ordinary metadata I/O immediately
before `COMMITTED` visibility markers and before `catalog/LATEST`. Session
operation IDs are privately bound to the exact source client operation ID.

The production `selection.captureSource` is metadata-only:

```json
{
  "stage": "awaiting_native_capture_receipt",
  "snapshotIdentity": "<the original frozen metadata identity>",
  "selectionKind": "full_scope",
  "nodeCount": 123
}
```

The Rust-only controller pages actual frozen files, directories and confined
links with complete native stamps. `full_scope` additionally requires the real
signed baseline/omission owner. `selected_files` is custom coverage and must not
advance a complete-application head. Empty/full scope is never inferred from an
empty file list.

Only real source capture can produce a `PreparedCaptureReceipt`. Tracker accepts
its actual hashes, immutable snapshot/proof and root stamps, then seals the exact
result. No pre-capture whole-tree hashing or predicted receipt is allowed.
Source submission/retry authentication binds original logical keys, instance,
metadata identity, mode and native scope; publication checks the actual prepared
manifest and the source-owned receipt.

Small revocation checks may run during progress monitoring. They carry native
grant envelopes, not a cloned 250k-node inventory. Exact source receipt validation
runs at actual publication barriers, not on every status poll.

Saved finalization also requires `verify_capture_completion` (or the batch's
equivalent authenticated committed-result verifier), after the real owner drains.
A prepared receipt and a terminal DB row alone do not prove `COMMITTED`.
Recovered Tracker receipts implement `verify_committed` using that original,
bound cryptographic completion proof. Newer changes remain dirty.

Native restore boot never replays path-only journals. Explicit local recovery
requires the original authenticated plan, destination identities and ownership
journals under fresh native consent. Unknown/replaced artifacts are retained.
Local recovery does not reconnect a provider, redownload or mark the original
failed restore completed.
