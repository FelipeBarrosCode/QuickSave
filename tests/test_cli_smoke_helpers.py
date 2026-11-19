# SPDX-License-Identifier: GPL-3.0-only
"""CLI test harness checks; these do not substitute for running the built CLI."""

import importlib.util
import json
import os
from pathlib import Path
import sys
import tempfile
import unittest
from unittest import mock
import uuid

SPEC = importlib.util.spec_from_file_location(
    "cli_smoke", Path(__file__).resolve().parents[1] / "scripts/cli_smoke.py"
)
smoke = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(smoke)


class SmokeHarnessTests(unittest.TestCase):
    def test_native_durability_does_not_claim_legacy_cli_format_support(self):
        capabilities = {
            "platform": {"platform": "windows", "filesystem": {"durable_create_new": True}},
            "localRepositorySupported": False,
        }
        with mock.patch.object(smoke, "run_command", side_effect=[
            (0, b"backup --key-file", b""),
            (0, json.dumps(capabilities).encode(), b""),
            (1, b"", b"legacy local repository initialization is unsupported"),
        ]):
            result = smoke.smoke(Path(sys.executable), None)
        self.assertEqual(result["status"], "unsupported-refusal-verified")
        self.assertFalse(result["round_trip"])
        self.assertEqual(result["commands"], 3)

    def test_unsupported_cli_cannot_report_initialization_success(self):
        with mock.patch.object(smoke, "run_command", side_effect=[
            (0, b"backup --key-file", b""),
            (0, b'{"platform":{"filesystem":{"durable_create_new":true}},'
                b'"localRepositorySupported":false}', b""),
            (0, b"{}", b""),
        ]):
            with self.assertRaisesRegex(smoke.SmokeError, "Unexpected CLI exit status"):
                smoke.smoke(Path(sys.executable), None)

    def test_unsupported_refusal_cannot_leave_key_or_repository_mutations(self):
        for mutation, message in (
            ("key", "published a key"),
            ("repository", "modified repository"),
        ):
            with self.subTest(mutation=mutation):
                def run(command, cwd, env):
                    if command[1] == "--help":
                        return 0, b"backup --key-file", b""
                    if command[1] == "capabilities":
                        return (
                            0,
                            b'{"platform":{"filesystem":{"durable_create_new":true}},'
                            b'"localRepositorySupported":false}',
                            b"",
                        )
                    self.assertEqual(command[1], "init")
                    if mutation == "key":
                        Path(command[command.index("--key-file") + 1]).write_bytes(b"x" * 32)
                    else:
                        repository = Path(command[command.index("--repository") + 1])
                        (repository / "unexpected").write_bytes(b"mutation")
                    return 1, b"", b"unsupported"

                with mock.patch.object(smoke, "run_command", side_effect=run):
                    with self.assertRaisesRegex(smoke.SmokeError, message):
                        smoke.smoke(Path(sys.executable), None)

    def test_snapshot_array_ids(self):
        identifier = str(uuid.uuid4())
        self.assertEqual(smoke.snapshot_ids([{"snapshotId": identifier}]), {identifier})

    def test_snapshot_wrapper_ids(self):
        identifier = str(uuid.uuid4())
        self.assertEqual(smoke.snapshot_ids({"snapshots": [{"id": identifier}]}), {identifier})

    def test_invalid_snapshot_id_refused(self):
        with self.assertRaises(smoke.SmokeError):
            smoke.snapshot_ids([{"id": "../../escape"}])

    def test_duplicate_snapshot_id_refused(self):
        identifier = str(uuid.uuid4())
        with self.assertRaises(smoke.SmokeError):
            smoke.snapshot_ids([{"id": identifier}, {"id": identifier}])

    def test_unrecognized_result_shape_refused(self):
        with self.assertRaises(smoke.SmokeError):
            smoke.snapshot_ids({"operationId": str(uuid.uuid4())})

    def test_subprocess_streams_are_captured(self):
        parent = Path(os.environ.get("QUICKSAVE_TEST_TMPDIR", tempfile.gettempdir())).resolve()
        with tempfile.TemporaryDirectory(prefix="quicksave-output-test-", dir=parent) as root:
            status, stdout, stderr = smoke.run_command(
                [sys.executable, "-c", "import sys; print('out'); print('err', file=sys.stderr)"],
                Path(root), os.environ.copy(),
            )
            self.assertEqual((status, stdout.strip(), stderr.strip()), (0, b"out", b"err"))

    def test_subprocess_output_is_bounded(self):
        parent = Path(os.environ.get("QUICKSAVE_TEST_TMPDIR", tempfile.gettempdir())).resolve()
        with tempfile.TemporaryDirectory(prefix="quicksave-bound-test-", dir=parent) as root:
            with mock.patch.object(smoke, "OUTPUT_LIMIT", 1024):
                with self.assertRaisesRegex(smoke.SmokeError, "bounded output"):
                    smoke.run_command(
                        [sys.executable, "-c", "print('x' * 65536)"],
                        Path(root), os.environ.copy(),
                    )

    def test_subprocess_stderr_is_bounded(self):
        parent = Path(os.environ.get("QUICKSAVE_TEST_TMPDIR", tempfile.gettempdir())).resolve()
        with tempfile.TemporaryDirectory(prefix="quicksave-stderr-test-", dir=parent) as root:
            with mock.patch.object(smoke, "OUTPUT_LIMIT", 1024):
                with self.assertRaisesRegex(smoke.SmokeError, "bounded output"):
                    smoke.run_command(
                        [sys.executable, "-c", "import sys; print('x' * 65536, file=sys.stderr)"],
                        Path(root), os.environ.copy(),
                    )


if __name__ == "__main__":
    unittest.main()
