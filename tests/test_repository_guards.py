# SPDX-License-Identifier: GPL-3.0-only
"""Verifier regression tests mutate isolated synthetic repositories only."""

import importlib.util
import hashlib
import json
import os
from pathlib import Path
import shutil
import tempfile
import unittest
from unittest import mock

SPEC = importlib.util.spec_from_file_location(
    "verify_repository", Path(__file__).resolve().parents[1] / "scripts/verify_repository.py"
)
guard = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(guard)


class RepositoryGuardTests(unittest.TestCase):
    def setUp(self):
        parent = Path(os.environ.get("QUICKSAVE_TEST_TMPDIR", tempfile.gettempdir())).resolve()
        self.temporary = tempfile.TemporaryDirectory(prefix="quicksave-guard-test-", dir=parent)
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.snapshot = self.root / "upstream/no-land"
        self.snapshot.mkdir(parents=True)
        (self.snapshot / "state-agent").mkdir()
        original_workspace = (
            "[workspace]\nmembers = "
            + json.dumps([f"crates/{name}" for name in sorted(guard.FORK_CRATES)])
            + '\n[workspace.package]\nlicense = "MIT"\nauthors = ["Synthetic original"]\n'
            + "[workspace.dependencies]\n"
            + "".join(
                f'{name} = {{ path = "crates/{name}" }}\n'
                for name in sorted(guard.FORK_CRATES)
            )
        )
        (self.snapshot / "state-agent/Cargo.toml").write_text(original_workspace, encoding="utf-8")
        for name in guard.FORK_CRATES:
            crate = self.snapshot / "state-agent/crates" / name
            (crate / "src").mkdir(parents=True)
            (crate / "Cargo.toml").write_text(
                f'[package]\nname = "{name}"\nversion = "0.1.0"\nlicense.workspace = true\n',
                encoding="utf-8",
            )
            (crate / "src/lib.rs").write_text("// Synthetic source only.\n", encoding="utf-8")
        (self.snapshot / "state-agent/crates/noland-cas/fixture.txt").write_text(
            "Synthetic removable fixture.\n", encoding="utf-8"
        )
        (self.snapshot / "docs").mkdir()
        for path in guard.EXPECTED_PATHS - {"state-agent"}:
            (self.snapshot / path).write_text("Synthetic reference, not upstream code.\n", encoding="utf-8")
        source = {
            "source_repository": guard.EXPECTED_REPOSITORY,
            "commit": guard.EXPECTED_COMMIT,
            "archive_sha256": guard.EXPECTED_ARCHIVE,
            "paths": sorted(guard.EXPECTED_PATHS),
        }
        (self.root / "upstream/SOURCE.json").write_text(json.dumps(source), encoding="utf-8")
        self.file_hashes = {
            path.relative_to(self.snapshot).as_posix(): hashlib.sha256(path.read_bytes()).hexdigest()
            for path in self.snapshot.rglob("*")
            if path.is_file()
        }
        (self.root / "upstream/FILES.sha256.json").write_text(
            json.dumps(self.file_hashes), encoding="utf-8"
        )
        (self.root / "scripts").mkdir()
        pinned = {
            "format_version": 1,
            "source_commit": guard.EXPECTED_COMMIT,
            "archive_sha256": guard.EXPECTED_ARCHIVE,
            "algorithm": guard.ALGORITHM,
            **guard.tree_fingerprint(self.snapshot),
        }
        (self.root / "scripts/upstream-provenance.json").write_text(json.dumps(pinned), encoding="utf-8")
        (self.root / "Cargo.toml").write_text(
            '[workspace]\nmembers = ["crates/example"]\n'
            '[workspace.package]\nlicense = "GPL-3.0-only"\n',
            encoding="utf-8",
        )
        self.manifest = self.root / "crates/example/Cargo.toml"
        self.manifest.parent.mkdir(parents=True)
        self.manifest.write_text(
            '[package]\nname = "quicksave-example"\nversion = "0.1.0"\n'
            'license = "GPL-3.0-only"\n',
            encoding="utf-8",
        )
        # Clone only the synthetic reference just constructed, never live source,
        # credentials, a pre-existing repository, or an actual No Land directory.
        self.fork = self.root / "shared-storage"
        shutil.copytree(self.snapshot / "state-agent", self.fork)
        shutil.copyfile(self.snapshot / "LICENSE", self.fork / "LICENSE")
        (self.fork / "SOURCE.json").write_text(
            json.dumps({
                "commit": guard.EXPECTED_COMMIT,
                "upstream": "../upstream/no-land/state-agent",
                "adaptations": ["Synthetic native library fixture; no deployment."],
            }),
            encoding="utf-8",
        )
        self.record_fork_changes()

    def assert_refused(self, message=None):
        with self.assertRaisesRegex(guard.VerificationError, message or "."):
            guard.verify(self.root)

    def record_fork_changes(self):
        baseline = {
            path.removeprefix("state-agent/"): digest
            for path, digest in self.file_hashes.items()
            if path.startswith("state-agent/")
        }
        current = {
            path.relative_to(self.fork).as_posix(): hashlib.sha256(path.read_bytes()).hexdigest()
            for path in self.fork.rglob("*")
            if path.is_file() and path.name not in guard.FORK_RECORDS
        }
        changes = {
            path: current.get(path)
            for path in baseline.keys() | current.keys()
            if baseline.get(path) != current.get(path)
        }
        (self.fork / "FORK-CHANGES.sha256.json").write_text(
            json.dumps(changes, sort_keys=True), encoding="utf-8"
        )

    def fork_manifest(self, name="noland-state-core"):
        return self.fork / "crates" / name / "Cargo.toml"

    def append_dependency(self, text):
        with self.manifest.open("a", encoding="utf-8") as stream:
            stream.write(text)

    def test_pristine_reference_and_new_workspace_pass(self):
        self.assertEqual(guard.verify(self.root)["status"], "verified")

    def add_native_platform(self):
        platform = self.root / "crates/quicksave-platform"
        (platform / "src").mkdir(parents=True)
        (platform / "Cargo.toml").write_text(
            '[package]\nname = "quicksave-platform"\nversion = "0.1.0"\n'
            'license = "GPL-3.0-only"\n', encoding="utf-8")
        (platform / "src/lib.rs").write_text("// Synthetic native handle boundary.\n", encoding="utf-8")

    def test_exact_windows_sqlite_native_platform_edge_is_confined_to_repository(self):
        self.add_native_platform()
        with self.fork_manifest("noland-state-db").open("a") as stream:
            stream.write('\n[target.\'cfg(windows)\'.dependencies]\n'
                'quicksave-platform = { path = "../../../crates/quicksave-platform" }\n')
        self.record_fork_changes()
        self.assertEqual(guard.verify(self.root)["status"], "verified")

    def test_reverse_platform_edge_cannot_be_borrowed_by_another_fork_crate(self):
        self.add_native_platform()
        with self.fork_manifest("noland-cas").open("a") as stream:
            stream.write('\n[target.\'cfg(windows)\'.dependencies]\n'
                'quicksave-platform = { path = "../../../crates/quicksave-platform" }\n')
        self.record_fork_changes()
        self.assert_refused("escapes")

    def test_reverse_platform_edge_cannot_change_target_or_alias(self):
        self.add_native_platform()
        with self.fork_manifest("noland-state-db").open("a") as stream:
            stream.write('\n[target.\'cfg(unix)\'.dependencies]\n'
                'quicksave-platform = { path = "../../../crates/quicksave-platform" }\n')
        self.record_fork_changes()
        self.assert_refused("escapes")

    def test_reverse_platform_edge_rejects_an_alias_even_with_the_same_package(self):
        self.add_native_platform()
        with self.fork_manifest("noland-state-db").open("a") as stream:
            stream.write('\n[target.\'cfg(windows)\'.dependencies]\n'
                'native-platform = { package = "quicksave-platform", '
                'path = "../../../crates/quicksave-platform" }\n')
        self.record_fork_changes()
        self.assert_refused("escapes")

    def test_reverse_platform_edge_does_not_authorize_a_build_dependency(self):
        self.add_native_platform()
        with self.fork_manifest("noland-state-db").open("a") as stream:
            stream.write('\n[target.\'cfg(windows)\'.build-dependencies]\n'
                'quicksave-platform = { path = "../../../crates/quicksave-platform" }\n')
        self.record_fork_changes()
        self.assert_refused("escapes")

    def test_changed_bytes_refused(self):
        (self.snapshot / "LICENSE").write_text("changed", encoding="utf-8")
        self.assert_refused()

    def test_unexpected_file_refused(self):
        (self.snapshot / "unexpected").write_text("extra", encoding="utf-8")
        self.assert_refused()

    def test_missing_file_refused(self):
        (self.snapshot / "LICENSE").unlink()
        self.assert_refused()

    def test_moved_file_refused(self):
        (self.snapshot / "LICENSE").rename(self.snapshot / "LICENSE.moved")
        self.assert_refused()

    @unittest.skipUnless(os.name == "posix", "Fixture link creation requires POSIX")
    def test_file_symlink_refused(self):
        (self.snapshot / "alias").symlink_to("LICENSE")
        self.assert_refused()

    @unittest.skipUnless(os.name == "posix", "Fixture link creation requires POSIX")
    def test_directory_symlink_refused(self):
        (self.snapshot / "alias").symlink_to("docs", target_is_directory=True)
        self.assert_refused()

    def test_archive_metadata_mismatch_refused(self):
        path = self.root / "upstream/SOURCE.json"
        document = json.loads(path.read_text(encoding="utf-8"))
        document["archive_sha256"] = "0" * 64
        path.write_text(json.dumps(document), encoding="utf-8")
        self.assert_refused()

    def test_file_manifest_mismatch_refused(self):
        path = self.root / "upstream/FILES.sha256.json"
        document = json.loads(path.read_text(encoding="utf-8"))
        document["LICENSE"] = "0" * 64
        path.write_text(json.dumps(document), encoding="utf-8")
        self.assert_refused()

    def test_edited_file_manifest_cannot_override_tree_baseline(self):
        (self.snapshot / "LICENSE").write_text("changed", encoding="utf-8")
        path = self.root / "upstream/FILES.sha256.json"
        document = json.loads(path.read_text(encoding="utf-8"))
        document["LICENSE"] = hashlib.sha256(b"changed").hexdigest()
        path.write_text(json.dumps(document), encoding="utf-8")
        self.assert_refused()

    def test_vendor_path_dependency_refused(self):
        self.append_dependency(
            '[dependencies]\ninnocent = { path = "../../upstream/no-land/state-agent" }\n'
        )
        self.assert_refused()

    def test_renamed_noland_dependency_refused(self):
        self.append_dependency(
            '[dependencies]\ninnocent = { package = "noland-state-core", version = "1" }\n'
        )
        self.assert_refused()

    def test_target_specific_dependency_refused(self):
        self.append_dependency(
            '[target.\'cfg(windows)\'.dependencies]\nnoland-observer = "1"\n'
        )
        self.assert_refused()

    def test_workspace_inherited_dependency_refused(self):
        with (self.root / "Cargo.toml").open("a", encoding="utf-8") as stream:
            stream.write(
                '[workspace.dependencies]\nengine = { path = "upstream/no-land/state-agent" }\n'
            )
        self.append_dependency("[dependencies]\nengine.workspace = true\n")
        self.assert_refused()

    def test_vendor_member_refused(self):
        (self.root / "Cargo.toml").write_text(
            '[workspace]\nmembers = ["upstream/no-land/state-agent"]\n'
            '[workspace.package]\nlicense = "GPL-3.0-only"\n', encoding="utf-8"
        )
        self.assert_refused()

    def test_outside_path_dependency_refused(self):
        self.append_dependency('[dependencies]\nexternal = { path = "../../../outside" }\n')
        self.assert_refused()

    def test_patch_dependency_refused(self):
        with (self.root / "Cargo.toml").open("a", encoding="utf-8") as stream:
            stream.write(
                '[patch.crates-io]\nengine = { path = "upstream/no-land/state-agent" }\n'
            )
        self.assert_refused()

    def test_frontend_vendor_dependency_refused(self):
        (self.root / "package.json").write_text(
            json.dumps({"dependencies": {"engine": "file:upstream/no-land"}}), encoding="utf-8"
        )
        self.assert_refused()

    def test_oversized_file_guard(self):
        with mock.patch.object(guard, "MAX_FILE_BYTES", 1):
            self.assert_refused()

    def test_oversized_document_guard(self):
        with mock.patch.object(guard, "MAX_DOCUMENT_BYTES", 1):
            self.assert_refused()

    def test_exact_active_fork_dependency_passes(self):
        self.append_dependency(
            '[dependencies]\nnoland-state-core = { path = "../../shared-storage/crates/noland-state-core" }\n'
        )
        self.assertEqual(guard.verify(self.root)["status"], "verified")

    def test_renamed_exact_active_fork_dependency_passes(self):
        self.append_dependency(
            '[dependencies]\nengine = { package = "noland-state-core", path = "../../shared-storage/crates/noland-state-core" }\n'
        )
        self.assertEqual(guard.verify(self.root)["status"], "verified")

    def test_target_specific_exact_active_fork_dependency_passes(self):
        self.append_dependency(
            '[target.\'cfg(unix)\'.dependencies]\nnoland-state-core = { path = "../../shared-storage/crates/noland-state-core" }\n'
        )
        self.assertEqual(guard.verify(self.root)["status"], "verified")

    def test_workspace_inherited_exact_fork_path_uses_workspace_base(self):
        with (self.root / "Cargo.toml").open("a", encoding="utf-8") as stream:
            stream.write(
                '[workspace.dependencies]\nengine = { package = "noland-state-core", path = "shared-storage/crates/noland-state-core" }\n'
            )
        self.append_dependency("[dependencies]\nengine.workspace = true\n")
        self.assertEqual(guard.verify(self.root)["status"], "verified")

    def test_fork_workspace_inheritance_uses_fork_base(self):
        with self.fork_manifest("noland-cas").open("a", encoding="utf-8") as stream:
            stream.write("[dependencies]\nnoland-state-core.workspace = true\n")
        self.record_fork_changes()
        self.assertEqual(guard.verify(self.root)["status"], "verified")

    def test_remote_git_dependency_under_innocent_alias_refused(self):
        self.append_dependency(
            '[dependencies]\nengine = { git = "https://example.invalid/innocent" }\n'
        )
        self.assert_refused("Git/binary dependency")

    def test_named_noland_git_dependency_refused(self):
        self.append_dependency(
            '[dependencies]\nengine = { package = "noland-storage", git = "https://example.invalid/engine" }\n'
        )
        self.assert_refused()

    def test_local_path_package_alias_must_match_actual_package(self):
        self.append_dependency(
            '[dependencies]\ninnocent = { path = "../../shared-storage/crates/noland-state-core" }\n'
        )
        self.assert_refused("package mismatch")

    def test_noland_name_cannot_be_replaced_by_quicksave_path(self):
        self.append_dependency('[dependencies]\nnoland-state-core = { path = "." }\n')
        self.assert_refused()

    def test_unapproved_noland_alias_cannot_hide_lifecycle_dependency(self):
        self.append_dependency(
            '[dependencies]\nnoland-lifecycle-agent = { package = "noland-state-core", path = "../../shared-storage/crates/noland-state-core" }\n'
        )
        self.assert_refused("exact active-fork")

    def test_fork_cannot_join_main_workspace(self):
        path = self.root / "Cargo.toml"
        path.write_text(
            path.read_text(encoding="utf-8").replace(
                '"crates/example"', '"crates/example", "shared-storage/crates/noland-state-core"'
            ),
            encoding="utf-8",
        )
        self.assert_refused("separate library workspace")

    def test_noland_package_outside_active_fork_refused(self):
        path = self.root / "crates/disguised"
        path.mkdir()
        (path / "Cargo.toml").write_text(
            '[package]\nname = "noland-state-core"\nlicense = "GPL-3.0-only"\n',
            encoding="utf-8",
        )
        self.append_dependency(
            '[dependencies]\ninnocent = { package = "noland-state-core", path = "../disguised" }\n'
        )
        self.assert_refused()

    def test_unused_fork_workspace_path_to_upstream_refused(self):
        path = self.fork / "Cargo.toml"
        with path.open("a", encoding="utf-8") as stream:
            stream.write('innocent = { path = "../upstream/no-land/state-agent" }\n')
        self.record_fork_changes()
        self.assert_refused("escapes")

    def test_unused_fork_target_specific_path_to_new_workspace_refused(self):
        with self.fork_manifest().open("a", encoding="utf-8") as stream:
            stream.write(
                '[target.\'cfg(windows)\'.dev-dependencies]\n'
                'innocent = { path = "../../../crates/example" }\n'
            )
        self.record_fork_changes()
        self.assert_refused()

    def test_unused_fork_patch_path_refused(self):
        with (self.fork / "Cargo.toml").open("a", encoding="utf-8") as stream:
            stream.write('[patch.crates-io]\ninnocent = { path = "../crates/example" }\n')
        self.record_fork_changes()
        self.assert_refused()

    def test_unused_fork_lifecycle_registry_dependency_refused(self):
        with self.fork_manifest().open("a", encoding="utf-8") as stream:
            stream.write(
                '[build-dependencies]\ninnocent = { package = "noland-lifecycle-agent", version = "1" }\n'
            )
        self.record_fork_changes()
        self.assert_refused("exact active-fork")

    def test_unused_fork_git_dependency_refused(self):
        with self.fork_manifest().open("a", encoding="utf-8") as stream:
            stream.write('[dev-dependencies]\ninnocent = { git = "https://example.invalid/engine" }\n')
        self.record_fork_changes()
        self.assert_refused("Git/binary dependency")

    def test_unexpected_fork_manifest_refused_even_when_not_a_member(self):
        path = self.fork / "unused/Cargo.toml"
        path.parent.mkdir()
        path.write_text('[package]\nname = "innocent"\n', encoding="utf-8")
        self.record_fork_changes()
        self.assert_refused("exact approved library manifests")

    def test_renamed_active_fork_manifest_refused(self):
        path = self.fork_manifest()
        path.write_text(
            path.read_text(encoding="utf-8").replace('"noland-state-core"', '"innocent"'),
            encoding="utf-8",
        )
        self.record_fork_changes()
        self.assert_refused("package mismatch|Unexpected No Land package")

    def test_fork_commit_must_equal_pinned_upstream(self):
        path = self.fork / "SOURCE.json"
        source = json.loads(path.read_text(encoding="utf-8"))
        source["commit"] = "0" * 40
        path.write_text(json.dumps(source), encoding="utf-8")
        self.assert_refused("exact pinned source")

    def test_fork_source_must_identify_local_immutable_reference(self):
        path = self.fork / "SOURCE.json"
        source = json.loads(path.read_text(encoding="utf-8"))
        source["upstream"] = "https://example.invalid/engine"
        path.write_text(json.dumps(source), encoding="utf-8")
        self.assert_refused("exact pinned source")

    def test_fork_adaptations_cannot_be_empty(self):
        path = self.fork / "SOURCE.json"
        source = json.loads(path.read_text(encoding="utf-8"))
        source["adaptations"] = []
        path.write_text(json.dumps(source), encoding="utf-8")
        self.assert_refused("actual active-fork adaptations")

    def test_fork_license_copy_required(self):
        (self.fork / "LICENSE").unlink()
        self.record_fork_changes()
        self.assert_refused("LICENSE verbatim")

    def test_fork_license_cannot_be_replaced_with_mit(self):
        (self.fork / "LICENSE").write_text("MIT", encoding="utf-8")
        self.record_fork_changes()
        self.assert_refused("LICENSE verbatim")

    def test_original_fork_manifest_license_notice_preserved(self):
        path = self.fork / "Cargo.toml"
        path.write_text(
            path.read_text(encoding="utf-8").replace('license = "MIT"', 'license = "GPL-3.0-only"'),
            encoding="utf-8",
        )
        self.record_fork_changes()
        self.assert_refused("Original license notice")

    def test_original_fork_authorship_notice_preserved(self):
        path = self.fork / "Cargo.toml"
        path.write_text(
            path.read_text(encoding="utf-8").replace("Synthetic original", "Replacement author"),
            encoding="utf-8",
        )
        self.record_fork_changes()
        self.assert_refused("Original authors notice")

    def test_changed_fork_bytes_require_reviewed_hash_record(self):
        (self.fork / "crates/noland-cas/src/lib.rs").write_text("changed", encoding="utf-8")
        self.assert_refused("change hashes")

    def test_added_fork_file_requires_reviewed_hash_record(self):
        (self.fork / "crates/noland-cas/src/new.rs").write_text("new", encoding="utf-8")
        self.assert_refused("change hashes")

    def test_removed_fork_file_requires_explicit_null_hash_record(self):
        (self.fork / "crates/noland-cas/fixture.txt").unlink()
        self.assert_refused("change hashes")
        self.record_fork_changes()
        changes = json.loads((self.fork / "FORK-CHANGES.sha256.json").read_text(encoding="utf-8"))
        self.assertIsNone(changes["crates/noland-cas/fixture.txt"])
        self.assertEqual(guard.verify(self.root)["status"], "verified")

    def test_fork_remote_agent_explicit_binary_refused(self):
        with self.fork_manifest("noland-state-agent").open("a", encoding="utf-8") as stream:
            stream.write('[[bin]]\nname = "remote"\npath = "src/lib.rs"\n')
        self.record_fork_changes()
        self.assert_refused("executable targets")

    def test_fork_remote_agent_implicit_binary_requires_autobins_false(self):
        (self.fork / "crates/noland-state-agent/src/main.rs").write_text(
            "// SPDX-License-Identifier: GPL-3.0-only\nfn main() {}", encoding="utf-8"
        )
        self.record_fork_changes()
        self.assert_refused("automatic remote-agent binaries")
        with self.fork_manifest("noland-state-agent").open("a", encoding="utf-8") as stream:
            stream.write("autobins = false\n")
        self.record_fork_changes()
        self.assertEqual(guard.verify(self.root)["status"], "verified")

    def test_fork_provisioning_content_excluded(self):
        path = self.fork / "scripts/provision.sh"
        path.parent.mkdir()
        path.write_text("# Synthetic; never executed.\n", encoding="utf-8")
        self.record_fork_changes()
        self.assert_refused("Provisioning/lifecycle")

    def test_fork_library_source_path_cannot_escape(self):
        with self.fork_manifest().open("a", encoding="utf-8") as stream:
            stream.write('[lib]\npath = "../../../../crates/example/Cargo.toml"\n')
        self.record_fork_changes()
        self.assert_refused("escapes")

    def test_fork_build_script_path_cannot_escape(self):
        with self.fork_manifest().open("a", encoding="utf-8") as stream:
            stream.write('build = "../../../../crates/example/Cargo.toml"\n')
        self.record_fork_changes()
        self.assert_refused("escapes")

    def test_fork_workspace_redirect_cannot_escape(self):
        with self.fork_manifest().open("a", encoding="utf-8") as stream:
            stream.write('workspace = "../../../.."\n')
        self.record_fork_changes()
        self.assert_refused("escapes")

    def test_absolute_native_and_windows_dependency_paths_refused(self):
        for text in [str(self.fork / "crates/noland-state-core"), r"C:\external\crate"]:
            with self.subTest(path=text):
                original = self.manifest.read_text(encoding="utf-8")
                self.append_dependency(
                    f"[dependencies]\nengine = {{ path = {json.dumps(text)} }}\n"
                )
                self.assert_refused("Invalid/absolute")
                self.manifest.write_text(original, encoding="utf-8")

    @unittest.skipUnless(os.name == "posix", "Fixture link creation requires POSIX")
    def test_active_fork_directory_symlink_refused(self):
        real = self.root / "kept-fork"
        self.fork.rename(real)
        self.fork.symlink_to(real, target_is_directory=True)
        self.assert_refused("Link/reparse point")

    @unittest.skipUnless(os.name == "posix", "Fixture link creation requires POSIX")
    def test_fork_manifest_parent_symlink_refused(self):
        path = self.fork / "crates/noland-state-core"
        kept = self.root / "kept-core"
        path.rename(kept)
        path.symlink_to(kept, target_is_directory=True)
        self.assert_refused("Link/reparse point")

    @unittest.skipUnless(os.name == "posix", "Fixture link creation requires POSIX")
    def test_dependency_symlink_even_to_valid_fork_refused(self):
        (self.root / "alias").symlink_to(self.fork, target_is_directory=True)
        self.append_dependency(
            '[dependencies]\nengine = { package = "noland-state-core", path = "../../alias/crates/noland-state-core" }\n'
        )
        self.assert_refused("Link/reparse point")

    @unittest.skipUnless(os.name == "posix", "Fixture link creation requires POSIX")
    def test_symlink_before_dotdot_cannot_be_normalized_away(self):
        (self.root / "alias").symlink_to(self.fork, target_is_directory=True)
        self.append_dependency(
            '[dependencies]\nengine = { package = "noland-state-core", path = "../../alias/../shared-storage/crates/noland-state-core" }\n'
        )
        self.assert_refused("Link/reparse point")

    @unittest.skipUnless(os.name == "posix", "Fixture link creation requires POSIX")
    def test_unused_fork_source_symlink_refused(self):
        (self.fork / "crates/noland-cas/src/alias.rs").symlink_to("lib.rs")
        self.assert_refused("Link/reparse point")

    def test_frontend_active_fork_dependency_refused(self):
        (self.root / "package.json").write_text(
            json.dumps({"dependencies": {"engine": "file:shared-storage"}}), encoding="utf-8"
        )
        self.assert_refused("frontend dependency")

    def test_invalid_workspace_inheritance_refused(self):
        self.append_dependency('[dependencies]\nengine = { workspace = true, path = "." }\n')
        self.assert_refused("workspace dependency override")

    def test_missing_workspace_inheritance_refused(self):
        self.append_dependency("[dependencies]\nengine.workspace = true\n")
        self.assert_refused("Missing/recursive workspace dependency")

    def test_binary_artifact_dependency_refused(self):
        self.append_dependency(
            '[dependencies]\nengine = { package = "noland-state-agent", path = "../../shared-storage/crates/noland-state-agent", artifact = "bin" }\n'
        )
        self.assert_refused("Git/binary dependency")

    def test_new_quicksave_code_cannot_claim_mit(self):
        self.manifest.write_text(
            self.manifest.read_text(encoding="utf-8").replace('"GPL-3.0-only"', '"MIT"'),
            encoding="utf-8",
        )
        self.assert_refused("GPL-3.0-only")

    def test_fork_crate_must_remain_an_actual_library(self):
        (self.fork / "crates/noland-cas/src/lib.rs").unlink()
        self.record_fork_changes()
        self.assert_refused("library target")

    def test_new_fork_source_must_identify_new_code_license(self):
        (self.fork / "crates/noland-cas/src/new.rs").write_text("// no notice\n", encoding="utf-8")
        self.record_fork_changes()
        self.assert_refused("New fork source must identify GPL-3.0-only")

    def test_unknown_fork_cargo_configuration_refused(self):
        path = self.fork / ".cargo/config.toml"
        path.parent.mkdir()
        path.write_text('[build]\ntarget-dir = "../outside"\n', encoding="utf-8")
        self.record_fork_changes()
        self.assert_refused("Provisioning/lifecycle")

    def test_malformed_manifest_table_refused_without_traceback(self):
        for text in ['workspace = "outside"\n', "[workspace]\ndependencies = []\n"]:
            with self.subTest(manifest=text):
                original = self.manifest.read_text(encoding="utf-8")
                with self.manifest.open("a", encoding="utf-8") as stream:
                    stream.write(text)
                self.assert_refused()
                self.manifest.write_text(original, encoding="utf-8")

    def test_deep_manifest_metadata_refused(self):
        with self.manifest.open("a", encoding="utf-8") as stream:
            stream.write("[" + ".".join(["package", "metadata"] + ["nested"] * 40) + ']\nvalue = "x"\n')
        self.assert_refused("nesting guard")

    def test_workspace_default_member_path_cannot_escape(self):
        path = self.fork / "Cargo.toml"
        path.write_text(
            path.read_text(encoding="utf-8").replace(
                "[workspace]\n", '[workspace]\ndefault-members = ["../crates/example"]\n'
            ),
            encoding="utf-8",
        )
        self.record_fork_changes()
        self.assert_refused("Escaping workspace")

    def test_bounded_final_component_workspace_glob_passes(self):
        path = self.root / "Cargo.toml"
        path.write_text(
            path.read_text(encoding="utf-8").replace('"crates/example"', '"crates/*"'),
            encoding="utf-8",
        )
        self.assertEqual(guard.verify(self.root)["status"], "verified")

    def test_workspace_glob_cannot_traverse_unvalidated_directories(self):
        path = self.root / "Cargo.toml"
        path.write_text(
            path.read_text(encoding="utf-8").replace('"crates/example"', '"*/example"'),
            encoding="utf-8",
        )
        self.assert_refused("final directory name")

    @unittest.skipUnless(os.name == "posix", "Fixture link creation requires POSIX")
    def test_workspace_glob_parent_symlink_refused_before_enumeration(self):
        (self.root / "alias").symlink_to("crates", target_is_directory=True)
        path = self.root / "Cargo.toml"
        path.write_text(
            path.read_text(encoding="utf-8").replace('"crates/example"', '"alias/*"'),
            encoding="utf-8",
        )
        self.assert_refused("Link/reparse point")


if __name__ == "__main__":
    unittest.main()
