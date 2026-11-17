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
