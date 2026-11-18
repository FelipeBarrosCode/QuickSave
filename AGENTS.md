# QuickSave implementation rules

- This is a NEW repository. Never modify, move, delete or reset any No Land repository or worktree.
- Do not use production cloud repositories, credentials, keys, remote machines or app state. Tests use isolated temporary directories only.
- `upstream/no-land/` is an unmodified snapshot of No Land commit e81238a7536aae201540956ce76981364fd36595. Do not edit it. Record derived-code provenance.
- `shared-storage/` is the separate audited native-library fork used for the user-requested No Land format/capability reuse. Adapt only this active fork; never execute its remote provisioning/lifecycle code or edit the upstream reference.
- The user requires the WHOLE optimized Shared Storage feature, not a reduced folder-copy product. Follow `docs/FULL-SHARED-STORAGE-CONTRACT.md`. Discovered apps must not become placeholder bundles; automatic No Land import searches the authoritative `com.noland.connect` application-data locations before offering an advanced manual fallback.
- No remote GitHub repository, merge, release, code-signing identity or paid resource is authorized by local implementation work.
- GPLv3 at the source root and MIT in engine manifests conflict. Preserve original notices. Use GPL-3.0-only for new code pending owner/license review; do not claim the entire snapshot is MIT.
- Unsupported capabilities must fail explicitly. Do not stub durability, authentication, path confinement, change detection or overwrite safety to success.
- No automatic cloud deletion or generation retirement. Version history is additive.
- Use real native filesystem handles. Reject symlinks/reparse points and invalid target paths unless a thoroughly tested feature explicitly supports them.
- Do not represent folder copies as app-consistent snapshots. Baseline is validated stable-file capture, not app-wide atomic consistency.
- Never log keys or add plaintext master keys to settings. Require an explicit external recovery-key file for CLI operations until native vault support exists.
- The user-directed workspace revision uses `state.json` for non-secret configuration and native vault references. Implement provider/No Land import flows with native consent, a QuickSave vault namespace, and read-only source import. Development/tests must still never access real provider accounts, live No Land state, or actual credential vault entries.
- Autosave is opt-in, bound to approved software/root identities/provider, and keeps local data. Watcher events are hints; overflow/restart/changes during upload cannot silently mark data saved.
- Keep memory, input/document sizes and subprocess output bounded. Preserve integrity checks.
- Do not claim Windows/Linux or native packaging acceptance based only on macOS builds.
- Agents must edit ONLY their assigned paths, coordinate shared APIs with the parent, and report exact commands/tests and limitations.
