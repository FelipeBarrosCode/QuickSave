# SPDX-License-Identifier: GPL-3.0-only
"""Verifier regression tests mutate isolated synthetic repositories only."""

import importlib.util
import hashlib
import json
import os
from pathlib import Path
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
        (self.snapshot / "state-agent/Cargo.toml").write_text("[workspace]\n", encoding="utf-8")
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
        file_hashes = {
            path.relative_to(self.snapshot).as_posix(): hashlib.sha256(path.read_bytes()).hexdigest()
            for path in self.snapshot.rglob("*")
            if path.is_file()
        }
        (self.root / "upstream/FILES.sha256.json").write_text(
            json.dumps(file_hashes), encoding="utf-8"
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
            '[workspace]\nmembers = ["crates/example"]\n', encoding="utf-8"
        )
        self.manifest = self.root / "crates/example/Cargo.toml"
        self.manifest.parent.mkdir(parents=True)
        self.manifest.write_text(
            '[package]\nname = "quicksave-example"\nversion = "0.1.0"\n', encoding="utf-8"
        )

    def assert_refused(self):
        with self.assertRaises(guard.VerificationError):
            guard.verify(self.root)

    def append_dependency(self, text):
        with self.manifest.open("a", encoding="utf-8") as stream:
            stream.write(text)

    def test_pristine_reference_and_new_workspace_pass(self):
        self.assertEqual(guard.verify(self.root)["status"], "verified")

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
            '[workspace]\nmembers = ["upstream/no-land/state-agent"]\n', encoding="utf-8"
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


if __name__ == "__main__":
    unittest.main()
