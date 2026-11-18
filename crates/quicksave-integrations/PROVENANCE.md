# Provenance and license

New QuickSave integrations code is GPL-3.0-only pending owner/license review.
No upstream notices or licensing declarations have been removed.

`src/parsers/steam.rs` adapts the `parse_appmanifest`, `parse_acf` and
`parse_libraryfolders` structure and field semantics from the read-only snapshot:

- `upstream/no-land/state-agent/crates/noland-discovery/src/steam.rs`
- No Land commit `e81238a7536aae201540956ce76981364fd36595`

The upstream discovery manifest inherits an MIT declaration, while the source
root contains GPLv3; this is an unresolved conflict, not an assertion that the
snapshot is wholly MIT. The original snapshot remains unmodified.

The adaptation separates pure parsing from I/O, replaces line splitting with a
bounded structural parser, refuses ambiguous/unsafe installation paths, does not
fall back from missing `installdir` to a title, and never canonicalizes symlinked
Steam libraries. Upstream's whole-prefix and inferred userdata ownership are not
carried over as authority or save mappings.

The `.desktop` and plist readers and native bounded read-only handle layer are
new code. Parser fixtures in `fixtures/` are synthetic, not user app state.

`src/bundles/` adds a new native identity-based inventory/planning layer. It
reuses the adapted Steam parser above, including the upstream app-ID,
`installdir` and library-folder semantics. The standard XDG installation
directories also used by upstream
`state-agent/crates/noland-discovery/src/desktop.rs` are retained; the new
literal-absolute-executable parser does not carry over shell/env expansion,
generic-wrapper guesses, display-name filters or executable-parent ownership.
No upstream save-title heuristics, whole-prefix copies, user-home copying,
credential/account access or automatic tracking authority is reused.

The new macOS container/entitlement parsers, direct read-only Security and
CoreFoundation bindings, bounded planner, native handle identities, and explicit
Windows identity/Known Folder adapter contracts are new GPL-3.0-only code.
Security constants/signatures were checked against Apple's installed SDK
`SecCode.h` and `SecStaticCode.h`; no signing identity is used. Signature checking
omits network access and recursive bundle-resource validation. Fixtures inject
signed metadata inside temporary filesystems without calling native Security.
Portable Windows fixtures retain real Unix file IDs on Unix; they do not claim
Windows API or packaging acceptance. The upstream reference is unmodified.

`SourceAppIdentity` mirrors the public serialized field contract in
`shared-storage/crates/noland-state-core/src/identity.rs` (original upstream
`state-agent/crates/noland-state-core/src/identity.rs` at the commit above).
It adds no engine dependency, name-based aliases, title ownership, synthetic
executable paths or authority. Exact observed desktop IDs retain their case;
the upstream lossy desktop-name normalization is not reused as ownership proof.

`src/bundles/approved.rs` is new GPL-3.0-only code using QuickSave's original
`quicksave-platform::SafeRoot` native handle APIs. It retains policy-approved
roots and IDs without serde grant construction, reads bounded whitelisted
installation/container metadata relative to those same handles, rejects
unapproved external Steam libraries, and disables path-only signing probes in
approved mode. It does not reuse remote lifecycle or source state getters.
