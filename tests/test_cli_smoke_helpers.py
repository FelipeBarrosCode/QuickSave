# SPDX-License-Identifier: GPL-3.0-only
"""CLI test harness checks; these do not substitute for running the built CLI."""

import importlib.util
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
