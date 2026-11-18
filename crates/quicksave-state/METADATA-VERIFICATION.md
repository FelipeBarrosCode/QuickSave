# Synchronous metadata verification frame

```rust,ignore
store.with_metadata_verification_snapshot(|| {
    native_tracking_adapter.call("software", arguments)
})?;
// Likewise ONLY the synchronous file_listing metadata projection.
```

The method is `with_metadata_verification_snapshot<T>(&self,
projection: impl FnOnce() -> anyhow::Result<T>) -> anyhow::Result<T>`.
It uses the existing fresh `read_snapshot()` once, routes existing
`WorkspaceStore::verify_grant`/`grant_verify` calls for `tracking`, `autosave`,
`app_tracking_policy`, and `bundle_discovery` through that document, and freshly
reads/compares the actual decoded document at the end. The closure runs once; on
change its result is discarded with an error. The adapter may retry the ENTIRE
metadata request at most a small fixed number of times (for example two).
That error downcasts to `quicksave_state::MetadataProjectionChanged`; do not
treat corrupt state, denied vault access or unrelated errors as retry signals.

An `Rc` thread-local frame is keyed by `Arc::ptr_eq` on the store's actual Inner.
It is not shared with other threads, separately opened stores, returned futures,
or later requests. A private non-Send RAII guard restores the previous frame on
success, error and unwind. Nesting is limited to eight frames. A native state
mutation invalidates matching frames; subsequent checks then read fresh state.

Every verification still performs the real HMAC and current persistent vault
nonce/revocation read. This is not a signature-result cache and cannot create a
device key or a grant. Provider operations, document reads, transactions and all
other grant kinds use their normal fresh path even inside the closure.

**Never wrap prepares, captures/receipts, autosave workers, upload/restore/delete,
publication guards, or write guards.** The four metadata kinds also have worker
uses, so the native call-site restriction is essential; no async block or awaited
work belongs inside this API. A returned future is polled after the frame has
already been removed and receives no optimization/authority.

Added synthetic tests for 4,096 existing generic verifications with the state
temporarily unavailable, real nonce revocation, fresh provider/mutation/publication
paths, exact store/thread separation, end-of-call changes, nesting and unwinding.
No Cargo build/test was run by this agent.
