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
`upstream/FILES.sha256.json`, and rejects dependencies on that reference tree.
The pinned unpacked tree remains **227 files**, tree SHA-256
`597d8cb35df99f5aa94ad509b5030160d5916dd56d2bc50fdc933ff257dcdd26`.
This is an accidental-change guard, not a signed provenance attestation.
Do not rebuild the baseline to make an unexplained mismatch pass.

The copied upstream docs contain historical production details and test counts.
Those are reference evidence only: they authorize no access to those machines,
credentials or repositories and prove no QuickSave acceptance.

## Two distinct implementation paths

The software/provider workspace revision is defined by
[`WORKSPACE-V2-CONTRACT.md`](WORKSPACE-V2-CONTRACT.md). Its native bridge uses the
separate active library fork at `shared-storage/`; **it does not link or modify
`upstream/no-land/`**. The fork retains No Land's existing format, encryption,
packs and provider/session representations rather than creating a second
"compatible" implementation.

The earlier `quicksave-engine` / `quicksave-content` / local CLI path is separate.
It has a deliberately different QuickSave envelope and local repository format.
Its tests, performance and restore limitations must not be presented as evidence
of No Land format interoperability or of workspace-v2 cloud acceptance. No
automatic conversion between these repositories is implemented or promised.

### Active native-library fork

`shared-storage/SOURCE.json` identifies the exact source commit above and the
local `../upstream/no-land/state-agent` reference. Its nonempty `adaptations`
list describes actual changes, not planned parity. The bridge owner must finish
that record after adaptations settle.

`shared-storage/FORK-CHANGES.sha256.json` records the complete delta from the
pinned `state-agent/` subtree:

- Keys are relative fork paths, without the `state-agent/` prefix.
- Added or modified files have their current lowercase SHA-256 as the value.
- Omitted upstream files have `null` as the value. This explicitly records the
  exclusion of deployment scripts, systemd/prebuilt artifacts and lifecycle code.
- Only `SOURCE.json` and `FORK-CHANGES.sha256.json` are excluded from this delta
  to avoid self-referential hashes. `Cargo.lock` and `LICENSE` are included.
- Review and record changes; never regenerate the immutable upstream baseline
  to hide them. This ledger detects drift, not whether a change is safe.

The verifier permits only the following 17 exact library packages at
`shared-storage/crates/<package>`:

```text
noland-attribution       noland-baseline       noland-cas
noland-classifier        noland-crypto         noland-discovery
noland-observer          noland-pack           noland-rclone-adapter
noland-restore           noland-rpc            noland-snapshot
noland-state-agent       noland-state-core     noland-state-db
noland-storage           noland-testkit
```

Every fork manifest is checked, including unused crates, workspace dependencies,
dev/build/target-specific dependencies, patches and replacements. Aliases must
resolve to the actual package name. Path components must remain within the
approved repository/fork boundary without symlinks or reparse points; absolute
and external paths, upstream-reference dependencies, registry No Land packages,
Git sources and binary-artifact dependencies are rejected. The active fork
remains a separate Cargo workspace, not a member of the QuickSave workspace.
Remote-agent executable targets are excluded; retained `src/main.rs` sources
must have automatic binary discovery disabled. No lifecycle package, deployment
scripts, systemd or prebuilt tree belongs in the active fork.

| Shared area | Workspace-v2 use and required boundary |
| --- | --- |
| Crypto, CAS, compression and packs | Reuse source implementations and authenticated formats; do not substitute the legacy QuickSave envelope |
| State core, database and storage | Use a private QuickSave instance/journal, never an existing No Land database or remote runtime |
| Capture, generation guards, admission and receipts | Retain source guards; explicit native roots and file selections replace inferred Linux ownership |
| Restore | Retain authenticated assembly and source safety protocols; confined native destinations and OS-specific behavior still need acceptance |
| Provider adapter | Reuse provider/session formats; QuickSave has its own vault namespace and transient native credential handling |
| `noland-state-agent` | In-process library only; no remote binary, provisioning, SSH, RPC listener or lifecycle process is authorized |
| Observer/discovery policy | Native approved-root tracking must not infer backup permission from process names or Linux runtime paths |
| Deletion/retry/cancellation | Reuse exact source protocols; deletion requires a fresh frozen preview, native confirmation and separate dependency acknowledgement |
| History convergence | **Disabled by QuickSave policy.** Version history is additive; no automatic cloud retirement or local source deletion |

The guard verifies local declarations, provenance hashes, the original license
copy and manifest license/authorship notices. It is not a transitive registry
SBOM, code-execution sandbox, proof that no forbidden runtime call exists, or
legal review. Human review must preserve any in-source notices too.

Current acceptance evidence and remaining gates are recorded separately in
[`WORKSPACE-V2-ACCEPTANCE.md`](WORKSPACE-V2-ACCEPTANCE.md). Library linkage is not
an assertion that every upstream feature works on every native platform.

### Earlier local CLI extraction matrix

Paths below are relative to `upstream/no-land/state-agent/crates/`.
“Candidate” means review/extract/adapt; it does not mean that crate is linked or
that its entire feature set is implemented in the earlier local engine. This
historical matrix does not describe the new active-fork linkage above.

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
- Preserve `shared-storage/LICENSE` byte-for-byte from
  `upstream/no-land/LICENSE`, and retain the original MIT workspace declaration
  and inherited manifest notices as evidence of the unresolved discrepancy.
- New QuickSave code is marked **GPL-3.0-only pending owner/license review**.
- New source files added to the fork must carry their GPL-3.0-only SPDX notice;
  retaining upstream MIT metadata does not relicense those additions.
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
The verifier prevents immutable-reference linkage and narrowly permits the
recorded active fork; human review remains necessary for semantics and licensing.
