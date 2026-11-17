# Reuse, provenance and license review

## Pinned evidence

The only upstream input is the local snapshot at `upstream/no-land/`, recorded in
[`upstream/SOURCE.json`](../upstream/SOURCE.json):

- Source: `https://github.com/FelipeBarrosCode/no_land`
- Commit: `e81238a7536aae201540956ce76981364fd36595`
- Recorded source archive SHA-256:
  `157156c3812aba45fdbfcc97268eede85dd34c49c3df2db0628874c085247fa5`
- Scope: `state-agent/`, root `LICENSE`, and the four listed storage/secret docs.

The source archive itself is not retained, so hashing the unpacked directory does
**not** reproduce the archive digest. `scripts/verify_repository.py` checks the
source metadata and a separately pinned unpacked-tree digest in
`scripts/upstream-provenance.json`, checks each file against
`upstream/FILES.sha256.json`, and rejects runtime dependencies on the vendor tree.
This is an accidental-change guard, not a signed provenance attestation.
Do not rebuild the baseline to make an unexplained mismatch pass.

The copied upstream docs contain historical production details and test counts.
Those are reference evidence only: they authorize no access to those machines,
credentials or repositories and prove no QuickSave acceptance.

## Reuse matrix

Paths below are relative to `upstream/no-land/state-agent/crates/`.
“Candidate” means review/extract/adapt; it does not mean that crate is linked or
that its entire feature set is implemented in QuickSave.

The actual content excerpts/adaptations and their test fixtures are recorded in
[`crates/quicksave-content/PROVENANCE.md`](../crates/quicksave-content/PROVENANCE.md),
including chunking, compression policy and the deliberately new envelope.

| Upstream area | Decision | QuickSave boundary / evidence |
| --- | --- | --- |
| `noland-cas/src/lib.rs` | Extract portable algorithms | BLAKE3 and FastCDC 1/4/8 MiB; preserve deterministic boundary fixtures, stream through native-safe handles, bound accumulated metadata |
| `noland-crypto/src/lib.rs` | Adapt reviewed primitives | XChaCha20-Poly1305 and HKDF-SHA256 via libraries; new QuickSave context/envelope, zeroizing ownership, wrong-key/tamper tests; no No Land ciphertext compatibility |
| `noland-pack/src/lib.rs` | Compression policy extracted; pack container deferred | Level-1/never-expand policy informs the new content envelope; upstream pack parser/layout is not imported or claimed compatible |
| `noland-state-core/src/{manifest,logical_path}.rs` | Reuse design, replace schema | Logical roots, chunk/file references and explicit versions; replace Linux/instance assumptions with reviewed OS/path versions |
| `noland-state-db/` | Future candidate, new database | Observation epochs, transactional projections and operation records; do not copy production DB/state or claim schema migration compatibility |
| `noland-baseline/`, `noland-snapshot/` | Split portable policy/native code | Baseline validation concepts; Btrfs/reflink and filesystem identity need per-OS replacements and honest consistency labels |
| `noland-restore/` | Design/test reference first | Preflight, authenticate-before-publish, bounded assembly and journal recovery; first slice is empty-target only, not upstream overwrite rollback |
| `noland-storage/` | Selective future extraction | Commit-last and bounded transfer ideas; replace repository layout, remote-agent coupling and coordination assumptions |
| `noland-rclone-adapter/` | Future provider/config candidate | Provider kinds/options/tuning only after secret/subprocess review; standalone local application, no inherited user rclone config or production profile |
| `noland-discovery/` | Replace native integration | Linux desktop/Steam/Wine/Bottles/runtime evidence is not Windows/macOS discovery; explicit selected-root permission before capture |
| `noland-attribution/`, `noland-classifier/` | Review concepts/rules | Ownership/identity confidence and semantic roles; process evidence is OS-specific and uncertain classification cannot authorize more files |
| `noland-observer/` | Replace platform adapters | Linux process connector/eBPF, cgroups and `/proc` cannot stand in for Windows/macOS; gap handling and bounded queues remain requirements |
| `noland-rpc/` | Do not port service protocol | Desktop uses local typed Tauri commands/CLI; no remote socket/SSH control plane |
| `noland-state-agent/` | Do not transplant orchestration | Separate new engine; no provisioning, remote lifecycle, source removal or automatic upload from discovery |
| `noland-lifecycle-agent/` | Exclude | Cloud instance/process lifecycle is outside QuickSave's backup purpose |
| `noland-testkit/` and crate tests | Adapt isolated fixtures selectively | Useful corruption, confinement, recovery and resource-limit scenarios; upstream passing counts are not new-product test results |
| storage deletion/reclamation and history convergence | **Exclude** | Upstream one-current-bundle/full-deletion behavior conflicts with additive history and no automatic deletion |

Additional reference evidence:

- `docs/shared-storage-restore-pipeline.md`: authenticated bounded records,
  destination-side partial publication, journal/version recovery and rollback
  requirements. QuickSave must not claim this entire pipeline is already ported.
- `docs/shared-storage-dev-optimizations.md`: gap invalidation, concurrent mutation
  generations, bounded work and commit/finalization distinct from payload transfer.
- `docs/shared-storage-io-validation.md`: destructive/history-convergence behavior
  to deliberately exclude; live-provider evidence does not transfer to QuickSave.
- `docs/state-secret-storage.md`: references-only settings and fail-closed vault
  migration. Its implementation is not part of this snapshot's desktop client.

## License ambiguity: release blocker, not relicensing permission

The copied root `upstream/no-land/LICENSE` is GNU GPL version 3. In contrast,
`upstream/no-land/state-agent/Cargo.toml` declares `license = "MIT"` and its crate
manifests inherit that workspace value. These are conflicting source signals; a
Cargo metadata field alone does not settle the complete snapshot's license.

- Preserve original copyright/license notices and the unmodified snapshot.
- New QuickSave code is marked **GPL-3.0-only pending owner/license review**.
- Do not describe the snapshot or the resulting application as wholly MIT.
- This conservative development choice is not a legal determination about every
  upstream contribution or a grant to redistribute code under different terms.
- Before distribution, the owner must resolve intended scope with relevant rights
  holders, inventory third-party licenses/notices and native redistributables,
  review source-offer/distribution obligations, and approve the final SPDX/notices.
- Do not use this work as authorization for a public GitHub repo, binary release,
  code-signing identity, paid service or deployment.

## Derived-file review record

For each copied/adapted algorithm, retain a source comment and maintain a record
with:

1. QuickSave destination and upstream path/commit.
2. Algorithm/constants kept and code deliberately replaced.
3. Original notices plus the new-file license policy.
4. Equivalence fixture or the documented reason behavior/format diverges.
5. Remaining portability, parser, resource and security review.

Portable algorithm equivalence does not imply storage-format interoperability.
The verifier prevents vendor linkage; human review is still required for
provenance, semantics and licensing.
