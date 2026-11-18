# SPDX-License-Identifier: GPL-3.0-only
# Fixture/API provenance: No Land e81238a7536aae201540956ce76981364fd36595.
"""Unit tests for benchmark containment/parsing; NOT native benchmark measurements."""

import copy
import importlib.util
import json
import os
from pathlib import Path
import sys
import tempfile
import unittest
from unittest import mock

SPEC = importlib.util.spec_from_file_location(
    "bench_native_shared_storage",
    Path(__file__).resolve().parents[1] / "scripts/bench_native_shared_storage.py",
)
bench = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(bench)


def unit_report():
    """Deliberately synthetic schema fixture, never emitted as engine evidence."""
    size = 64 * 1024 * 1024
    phases = {}
    for name in ("first_capture", "unchanged_capture", "changed_capture", "subset_capture"):
        phases[name] = {
            "elapsedSeconds": 0.1, "durableCompletion": True, "bytesRead": 0,
            "fullScans": 1, "remoteBytes": {"uploaded": 0, "downloaded": 0, "packUploaded": 0, "streamDownloaded": 0},
            "newPacks": 0, "chunksReused": 4, "sharedChunkHashes": 2, "selectedFiles": 1,
            "sourceFilesReused": 1000, "filesRehashed": 0,
            "captureAuthority": "actual_source_metadata_scope_receipt",
            "captureMetadataCounters": {
                "acceptedReceipts": 1, "sourceProofsRecorded": 1,
                "frozenPages": 1, "metadataFileOpens": 1,
            },
            "peakBuffers": {
                "codecs": 1, "codecCeiling": 2, "uploads": 1, "uploadCeiling": 2,
                "reservedBytes": 1024, "reservedByteCeiling": 4096, "reservedCount": 1, "reservedCountCeiling": 2,
            },
        }
    phases["first_capture"].update(bytesRead=size, newPacks=1)
    phases["changed_capture"].update(bytesRead=size // 4, newPacks=1)
    for name in ("first_restore", "unchanged_restore", "selective_restore"):
        phases[name] = {
            "elapsedSeconds": 0.1, "durableCompletion": True, "bytesRead": size,
            "fullScans": 0, "remoteBytes": {"uploaded": 0, "downloaded": 0, "packUploaded": 0, "streamDownloaded": 0},
            "packsDownloaded": 0, "readback": 0, "assembledBytes": size,
            "requiredPacks": 0, "availablePacks": 2,
            "peakBuffers": {
                "assemblyHandles": 1, "activeHashers": 1, "unpublishedFiles": 1,
                "decodeWorkers": 1, "decoderCeiling": 1, "verificationWorkers": 1, "verifierCeiling": 1,
            },
        }
    phases["selective_restore"].update(packsDownloaded=1, requiredPacks=1)
    return {
        "schemaVersion": 1, "sourceCommit": bench.SOURCE_COMMIT,
        "pipeline": "source-native-local-storage", "provider": "isolated_filesystem_fixture",
        "liveProviderBenchmark": False,
        "fixture": {"logicalBytes": size, "files": 1000, "generationBufferBytes": 65536},
        "phases": phases,
        "checks": {key: True for key in ("zstdNoExpansion", "zstdUsed", "crossFileDedup", "markerLast", "failedMarkerInvisible", "noEventCleanRefused", "statusPollBounded")},
        "opaquePlans": {"storedEntries": 250_000, "maxPollBytes": 512, "fullScans": 0},
        "adaptiveConcurrency": {"simulation": True, "peakActive": 4, "maximum": 4, "beforeRateLimit": 4, "afterRateLimit": 2, "finalActive": 0},
    }


class NativeBenchHelperTests(unittest.TestCase):
    def temporary_parent(self):
        return bench.APPROVED_TMP if bench.APPROVED_TMP.is_dir() else Path(tempfile.gettempdir())

    def test_limits_reject_disk_flood_and_nondecimal_input(self):
        self.assertEqual(bench.bounded_int("256", 64, 256, "mib"), 256)
        for value in ("0", "63", "257", "34000", "-1", "1e3", "１２８", "128 ", "9" * 10_000):
            with self.subTest(value=value), self.assertRaises(bench.BenchError):
                bench.bounded_int(value, 64, 256, "mib")

    def test_environment_never_inherits_provider_or_vault_configuration(self):
        with tempfile.TemporaryDirectory(dir=self.temporary_parent()) as temporary:
            root = Path(temporary).resolve()
            with mock.patch.dict(os.environ, {"RCLONE_CONFIG": "/real/config", "RCLONE_CONFIG_REMOTE_TOKEN": "secret", "AWS_SECRET_ACCESS_KEY": "secret", "HOME": "/real/home"}):
                env = bench.isolated_environment(root, 64, 1000)
            self.assertNotIn("AWS_SECRET_ACCESS_KEY", env)
            self.assertNotIn("RCLONE_CONFIG_REMOTE_TOKEN", env)
            self.assertEqual(env["HOME"], str(root / "home"))
            self.assertEqual(env["RCLONE_CONFIG"], str(root / "never-use-rclone.conf"))
            self.assertFalse(Path(env["RCLONE_CONFIG"]).exists())

    def test_report_must_come_from_explicit_single_sentinel(self):
        payload = json.dumps(unit_report()).encode()
        report = bench.parse_report(b"test native ... " + bench.PREFIX + payload + b"\nok\n")
        self.assertEqual(report["schemaVersion"], 1)
        for text in (payload, bench.PREFIX + payload + b"\n" + bench.PREFIX + payload):
            with self.assertRaises(bench.BenchError):
                bench.parse_report(text)

    def test_duplicate_keys_nan_oversized_and_malformed_json_refused(self):
        for payload in (b'{"schemaVersion":1,"schemaVersion":1}', b'{"elapsed":NaN}', b'{"missing":', b'[]'):
            with self.subTest(payload=payload), self.assertRaises(bench.BenchError):
                bench.parse_report(bench.PREFIX + payload)
        with mock.patch.object(bench, "REPORT_LIMIT", 32), self.assertRaises(bench.BenchError):
            bench.parse_report(bench.PREFIX + json.dumps(unit_report()).encode())

    def test_unknown_counter_is_not_silently_zero(self):
        report = unit_report()
        del report["phases"]["unchanged_capture"]["bytesRead"]
        with self.assertRaisesRegex(bench.BenchError, "measured counter"):
            bench.validate_report(report, 64, 1000)
        with self.assertRaises(bench.BenchError):
            bench.integer({"value": False}, "value")

    def test_counter_gates_are_independent_of_elapsed_speed(self):
        report = unit_report()
        for phase in report["phases"].values():
            phase["elapsedSeconds"] = 12000.0
        self.assertEqual(bench.validate_report(report, 64, 1000), [])
        report["phases"]["first_restore"]["elapsedSeconds"] = float("inf")
        with self.assertRaises(bench.BenchError):
            bench.validate_report(report, 64, 1000)

    def test_guarded_revalidation_baseline_cannot_claim_optimized_parity(self):
        report = unit_report()
        report["phases"]["unchanged_capture"]["bytesRead"] = report["fixture"]["logicalBytes"]
        report["phases"]["changed_capture"]["bytesRead"] = report["fixture"]["logicalBytes"]
        with self.assertRaisesRegex(bench.BenchError, "NOT optimized parity"):
            bench.validate_report(report, 64, 1000)
        gaps = bench.validate_report(report, 64, 1000, allow_revalidation_baseline=True)
        self.assertEqual(len(gaps), 1)

    def test_resource_integrity_and_selectivity_regressions_fail(self):
        changes = (
            ("first_restore", "readback", 1),
            ("unchanged_restore", "packsDownloaded", 1),
            ("selective_restore", "packsDownloaded", 2),
            ("subset_capture", "selectedFiles", 2),
            ("changed_capture", "sharedChunkHashes", 0),
            ("first_capture", "durableCompletion", False),
        )
        for name, key, value in changes:
            with self.subTest(phase=name, counter=key):
                report = copy.deepcopy(unit_report())
                report["phases"][name][key] = value
                with self.assertRaises(bench.BenchError):
                    bench.validate_report(report, 64, 1000)
        report = unit_report()
        report["phases"]["first_restore"]["peakBuffers"]["assemblyHandles"] = 33
        with self.assertRaises(bench.BenchError):
            bench.validate_report(report, 64, 1000)
        report = unit_report()
        report["phases"]["first_capture"]["peakBuffers"]["codecs"] = 3
        with self.assertRaises(bench.BenchError):
            bench.validate_report(report, 64, 1000)

    def test_zero_reads_without_actual_source_reuse_is_not_optimized_proof(self):
        report = unit_report()
        report["phases"]["unchanged_capture"]["sourceFilesReused"] = 0
        with self.assertRaisesRegex(bench.BenchError, "NOT optimized parity"):
            bench.validate_report(report, 64, 1000)

    def test_fixture_is_not_a_live_provider_or_non_native_pipeline(self):
        for key, value in (("liveProviderBenchmark", True), ("pipeline", "quicksave-local-format")):
            report = unit_report()
            report[key] = value
            with self.assertRaises(bench.BenchError):
                bench.validate_report(report, 64, 1000)

    def test_bounded_subprocess_captures_both_streams_and_real_elapsed(self):
        with tempfile.TemporaryDirectory(dir=self.temporary_parent()) as temporary:
            root = Path(temporary).resolve()
            status, stdout, stderr, elapsed = bench.run_bounded(
                [sys.executable, "-c", "import sys; print('out'); print('err', file=sys.stderr)"],
                root, {"PATH": "/usr/bin:/bin", "LANG": "C"},
            )
        self.assertEqual((status, stdout.strip(), stderr.strip()), (0, b"out", b"err"))
        self.assertGreater(elapsed, 0)

    def test_stdout_and_stderr_floods_are_killed(self):
        for stream in ("sys.stdout", "sys.stderr"):
            with self.subTest(stream=stream), tempfile.TemporaryDirectory(dir=self.temporary_parent()) as temporary:
                with mock.patch.object(bench, "OUTPUT_LIMIT", 1024), self.assertRaisesRegex(bench.BenchError, "bounded subprocess output"):
                    bench.run_bounded(
                        [sys.executable, "-c", f"import sys; {stream}.write('x' * 65536)"],
                        Path(temporary), {"PATH": "/usr/bin:/bin"},
                    )


if __name__ == "__main__":
    unittest.main()
