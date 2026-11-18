<!-- SPDX-License-Identifier: GPL-3.0-only -->
# Native Shared Storage bridge provenance

This is original QuickSave integration code over the audited local library fork
in `shared-storage/`, derived from No Land commit
`e81238a7536aae201540956ce76981364fd36595`. The immutable reference remains
`upstream/no-land/`; it is not a runtime dependency or deployment directory.

- Capture, FastCDC/BLAKE3, CAS, compression, NLNE/NLZ1/NLPK, authenticated metadata,
  adaptive transfers and streaming restore come from the actual fork libraries.
- Native controllers bind canonical product IDs separately from installation
  instances, exact native roots/allowlists, frozen scopes, source-produced hashes,
  device grants and original operation IDs. Renderer JSON cannot instantiate
  a capture receipt, index owner, process proof or publication authority.
- Native process evidence enters the real source application/path graph as
  `VERIFY_REQUIRED`; it never turns watcher silence into saved/trusted state.
- Restore mappings ignore original absolute source hints. Authenticated native
  layouts can reconstruct real package directories, resources and confined
  links, but do not manufacture Runnable/signature/dependency acceptance.
- History is additive. Exact cloud deletion and local replacement/recovery have
  independent previews, native consent and ownership checks.
- Provider sessions, repository keys, device keys and credential refresh remain
  native-private. No remote provisioning, lifecycle service, SSH or production
  operation is executed by the bridge or its synthetic tests.

New code is GPL-3.0-only. Original source/package notices remain intact; the
upstream root GPLv3/engine-manifest MIT discrepancy still requires owner/license
review before distribution. See `shared-storage/SOURCE.json`,
`shared-storage/FORK-CHANGES.sha256.json` and `docs/REUSE-AND-LICENSE.md`.

Acceptance is recorded separately in
`docs/SHARED-STORAGE-INTEGRATION-STATUS.md`. Formatting, host tests and cross-target
compilation are not live-provider, native Windows/Linux or packaging acceptance.
