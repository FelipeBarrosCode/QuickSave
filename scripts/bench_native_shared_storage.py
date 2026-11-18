#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-only
# Fixture/API provenance: No Land e81238a7536aae201540956ce76981364fd36595,
# state-agent backup/{scale,optimizations}.rs and shared-storage-dev-optimizations.md.
"""Run an already-built, isolated source-engine benchmark; never build or use cloud auth.

The binary is noland-testkit's native_optimized_pipeline integration-test executable,
not quicksave-cli (whose local format is a different pipeline). See the parity doc.
"""

from __future__ import annotations

import argparse
import json
import math
import os
from pathlib import Path
import stat
import subprocess
import sys
import tempfile
import threading
import time

PREFIX = b"NATIVE_SHARED_STORAGE_BENCH "
SOURCE_COMMIT = "e81238a7536aae201540956ce76981364fd36595"
DEFAULT_MIB = 64
MAX_MIB = 256
DEFAULT_FILES = 1000
MAX_FILES = 4096
OUTPUT_LIMIT = 2 * 1024 * 1024  # Per stream, including Rust's test harness output.
REPORT_LIMIT = 256 * 1024
HANG_TIMEOUT = 1800  # Runaway-process protection, never a performance threshold.
APPROVED_TMP = Path("/private/var/folders/bm/fyg39kl11r5crgrby4bqs4lr0000gn/T/opencode")
TEST_NAME = "native_optimized_pipeline_benchmark"


class BenchError(RuntimeError):
    pass


def require(condition: bool, message: str) -> None:
    if not condition:
        raise BenchError(message)


def bounded_int(value: str, minimum: int, maximum: int, name: str) -> int:
    require(len(value) <= 10 and value.isascii() and value.isdecimal(), f"{name} must be a bounded decimal integer")
    number = int(value)
    require(minimum <= number <= maximum, f"{name} must be {minimum}–{maximum}")
    return number


def isolated_environment(root: Path, mib: int, files: int) -> dict[str, str]:
    """Allowlist, rather than inherit, process configuration and provider secrets."""
    root = root.resolve(strict=True)
    require(root.is_dir(), "Benchmark sandbox is not a directory")
    for leaf in ("home", "config", "data", "state", "cache", "run", "tmp"):
        (root / leaf).mkdir(mode=0o700, exist_ok=False)
    return {
        "PATH": "/usr/bin:/bin",
        "LANG": "C",
        "LC_ALL": "C",
        "HOME": str(root / "home"),
        "USERPROFILE": str(root / "home"),
        "XDG_CONFIG_HOME": str(root / "config"),
        "XDG_DATA_HOME": str(root / "data"),
        "XDG_STATE_HOME": str(root / "state"),
        "XDG_CACHE_HOME": str(root / "cache"),
        "XDG_RUNTIME_DIR": str(root / "run"),
        "APPDATA": str(root / "config"),
        "LOCALAPPDATA": str(root / "data"),
        "TMPDIR": str(root / "tmp"),
        "TMP": str(root / "tmp"),
        "TEMP": str(root / "tmp"),
        "NOLAND_STATE_ROOT": str(root / "state"),
        "NOLAND_RUN_ROOT": str(root / "run"),
        "NOLAND_HOME": str(root / "home"),
        # Neither the test nor this script executes rclone. This is defense in
        # depth against an accidental future fallback to an inherited config.
        "RCLONE_CONFIG": str(root / "never-use-rclone.conf"),
        "QUICKSAVE_NATIVE_BENCH_SANDBOX": str(root),
        "QUICKSAVE_NATIVE_BENCH_MIB": str(mib),
        "QUICKSAVE_NATIVE_BENCH_FILES": str(files),
        "RUST_BACKTRACE": "0",
    }


def run_bounded(command: list[str], cwd: Path, env: dict[str, str]) -> tuple[int, bytes, bytes, float]:
    """Drain both pipes concurrently, with hard bounds and joined workers."""
    started = time.monotonic()
    process = subprocess.Popen(
        command, cwd=cwd, env=env, stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE, stderr=subprocess.PIPE,
    )
    outputs = [bytearray(), bytearray()]
    exceeded = threading.Event()
    errors: list[OSError] = []

    def kill() -> None:
        try:
            process.kill()
        except ProcessLookupError:
            pass

    def drain(stream, destination: bytearray) -> None:
        try:
            while block := stream.read(4096):
                if len(destination) + len(block) > OUTPUT_LIMIT:
                    exceeded.set()
                    kill()
                    return
                destination.extend(block)
        except OSError as error:
            errors.append(error)
            kill()
        finally:
            stream.close()

    workers = [
        threading.Thread(target=drain, args=(process.stdout, outputs[0]), daemon=True),
        threading.Thread(target=drain, args=(process.stderr, outputs[1]), daemon=True),
    ]
    for worker in workers:
        worker.start()
    timed_out = False
    try:
        process.wait(timeout=HANG_TIMEOUT)
    except subprocess.TimeoutExpired:
        timed_out = True
        kill()
        process.wait(timeout=10)
    finally:
        for worker in workers:
            worker.join(timeout=10)
    require(not any(worker.is_alive() for worker in workers), "Benchmark pipe worker did not drain")
    require(not timed_out, "Benchmark exceeded the runaway-process guard")
    require(not exceeded.is_set(), "Benchmark exceeded bounded subprocess output")
    require(not errors, "Benchmark subprocess output could not be read")
    return process.returncode, bytes(outputs[0]), bytes(outputs[1]), time.monotonic() - started


def _unique_object(pairs):
    result = {}
    for key, value in pairs:
        require(key not in result, "Benchmark report contains duplicate JSON keys")
        result[key] = value
    return result


def parse_report(stdout: bytes) -> dict:
    require(len(stdout) <= OUTPUT_LIMIT, "Benchmark stdout exceeds its bound")
    # Rust's harness can prefix a line with `test name ... `. Match the explicit
    # sentinel anywhere on that line, but never accept multiple reports.
    candidates = [
        line.split(PREFIX, 1)[1]
        for line in stdout.splitlines()
        if PREFIX in line
    ]
    require(len(candidates) == 1, "Expected exactly one source-engine benchmark report")
    require(len(candidates[0]) <= REPORT_LIMIT, "Benchmark JSON exceeds its bound")
    try:
        report = json.loads(
            candidates[0], object_pairs_hook=_unique_object,
            parse_constant=lambda _: (_ for _ in ()).throw(BenchError("Non-finite JSON number")),
        )
    except (ValueError, UnicodeError, RecursionError) as error:
        raise BenchError("Benchmark returned invalid JSON") from error
    require(isinstance(report, dict), "Benchmark report must be an object")
    return report


def integer(document: dict, key: str) -> int:
    require(isinstance(document, dict), f"Missing counter document: {key}")
    value = document.get(key)
    require(type(value) is int and value >= 0, f"Missing or invalid measured counter: {key}")
    return value


def validate_report(report: dict, mib: int, files: int, allow_revalidation_baseline: bool = False) -> list[str]:
    """Counter/ratio gates only: elapsed time is recorded, never pass/fail speed."""
    require(report.get("schemaVersion") == 1, "Unsupported benchmark report schema")
    require(report.get("sourceCommit") == SOURCE_COMMIT, "Unexpected source provenance")
    require(report.get("pipeline") == "source-native-local-storage", "Wrong storage pipeline")
    require(report.get("provider") == "isolated_filesystem_fixture", "Not an isolated provider fixture")
    require(report.get("liveProviderBenchmark") is False, "A fixture cannot claim live-provider results")
    fixture = report.get("fixture")
    require(isinstance(fixture, dict), "Missing fixture counters")
    require(integer(fixture, "logicalBytes") == mib * 1024 * 1024, "Fixture payload differs from requested bytes")
    require(integer(fixture, "files") == files, "Fixture file count differs from request")
    require(integer(fixture, "generationBufferBytes") <= 128 * 1024, "Unbounded fixture generation buffer")
    phases = report.get("phases")
    require(isinstance(phases, dict), "Missing native pipeline phases")
    captures = ("first_capture", "unchanged_capture", "changed_capture", "subset_capture")
    restores = ("first_restore", "unchanged_restore", "selective_restore")
    for name in captures + restores:
        phase = phases.get(name)
        require(isinstance(phase, dict), f"Missing benchmark phase: {name}")
        elapsed = phase.get("elapsedSeconds")
        require(
            type(elapsed) in (int, float) and math.isfinite(elapsed) and elapsed >= 0,
            f"Missing real-clock elapsed time: {name}",
        )
        require(phase.get("durableCompletion") is True, f"Not durably completed: {name}")
        integer(phase, "bytesRead")
        integer(phase, "fullScans")
        require(isinstance(phase.get("remoteBytes"), dict), f"Missing provider counters: {name}")
        for key in ("uploaded", "downloaded", "packUploaded", "streamDownloaded"):
            integer(phase["remoteBytes"], key)
    for name in captures:
        require(
            phases[name].get("captureAuthority") == "actual_source_metadata_scope_receipt",
            f"Benchmark did not use actual metadata-frozen source capture authority: {name}",
        )
        counters = phases[name].get("captureMetadataCounters")
        require(isinstance(counters, dict), f"Missing actual native capture-coordinator counters: {name}")
        selected = integer(phases[name], "selectedFiles")
        require(integer(counters, "acceptedReceipts") == 1, f"Actual source receipt was not accepted once: {name}")
        require(integer(counters, "sourceProofsRecorded") == selected, f"Source captured/reused proofs omitted selected files: {name}")
        require(integer(counters, "frozenPages") == (selected + 499) // 500, f"Native metadata pages were not consumed once: {name}")
        require(integer(counters, "metadataFileOpens") >= selected, f"Native metadata stamps were not validated: {name}")
    first, unchanged, changed, subset = (phases[name] for name in captures)
    logical = fixture["logicalBytes"]
    for name in ("first_capture", "changed_capture"):
        resources = phases[name].get("peakBuffers")
        require(isinstance(resources, dict), f"Missing actual capture resource counters: {name}")
        for peak, ceiling in (
            ("codecs", "codecCeiling"), ("uploads", "uploadCeiling"),
            ("reservedBytes", "reservedByteCeiling"), ("reservedCount", "reservedCountCeiling"),
        ):
            require(integer(resources, peak) <= integer(resources, ceiling), f"Capture resource ceiling exceeded: {peak}")
    require(integer(first, "bytesRead") == logical, "First capture did not hash the complete fixture")
    require(integer(first, "newPacks") > 0, "First capture produced no real packs")
    require(integer(unchanged, "newPacks") == 0, "Unchanged capture produced new payload packs")
    require(unchanged["remoteBytes"]["packUploaded"] == 0, "Unchanged capture transferred payload")
    require(integer(unchanged, "chunksReused") > 0, "Unchanged capture lost source chunk reuse")
    require(integer(changed, "sharedChunkHashes") > 0, "Changed-file FastCDC chunks were not reused")
    require(integer(changed, "newPacks") > 0, "Changed capture produced no changed payload")
    require(integer(subset, "selectedFiles") == 1, "Subset capture widened its exact selection")
    require(integer(subset, "newPacks") == 0, "Unchanged subset duplicated existing chunks")
    require(integer(subset, "bytesRead") <= logical // 4, "Subset capture rehashed unrelated content")
    for name in restores:
        phase = phases[name]
        resources = phase.get("peakBuffers")
        require(isinstance(resources, dict), f"Missing restore resource counters: {name}")
        require(integer(resources, "assemblyHandles") <= 32, "Assembly handle ceiling exceeded")
        require(integer(resources, "activeHashers") <= 128, "Inline hasher ceiling exceeded")
        require(integer(resources, "unpublishedFiles") <= 256, "Unpublished file ceiling exceeded")
        require(integer(resources, "decodeWorkers") <= integer(resources, "decoderCeiling"), "Decoder ceiling exceeded")
        require(integer(resources, "verificationWorkers") <= integer(resources, "verifierCeiling"), "Verifier ceiling exceeded")
        require(integer(phase, "readback") <= integer(phase, "assembledBytes"), "Restore readback amplification exceeded one pass")
    require(integer(phases["first_restore"], "readback") == 0, "Ordered restore lost inline hash/readback avoidance")
    require(integer(phases["unchanged_restore"], "packsDownloaded") == 0, "Identical restore fetched packs")
    require(phases["unchanged_restore"]["remoteBytes"]["streamDownloaded"] == 0, "Identical restore read pack bytes")
    selective = phases["selective_restore"]
    require(integer(selective, "packsDownloaded") == integer(selective, "requiredPacks"), "Selective restore fetched unrelated/repeated packs")
    require(integer(selective, "requiredPacks") < integer(selective, "availablePacks"), "Selective fixture did not distinguish pack selection")
    checks = report.get("checks", {})
    require(isinstance(checks, dict), "Missing native regression checks")
    for key in ("zstdNoExpansion", "zstdUsed", "crossFileDedup", "markerLast", "failedMarkerInvisible", "noEventCleanRefused", "statusPollBounded"):
        require(checks.get(key) is True, f"Native regression gate not satisfied: {key}")
    polling = report.get("opaquePlans", {})
    require(integer(polling, "storedEntries") == 250_000, "Opaque-plan stress fixture was reduced")
    require(integer(polling, "maxPollBytes") <= 4096, "Status poll serialized its server-only plan")
    require(integer(polling, "fullScans") == 0, "Status polling walked source trees")
    simulation = report.get("adaptiveConcurrency", {})
    require(simulation.get("simulation") is True, "Limiter faults must be labeled simulation")
    require(1 < integer(simulation, "peakActive") <= integer(simulation, "maximum"), "Limiter did not exercise bounded concurrency")
    require(integer(simulation, "afterRateLimit") < integer(simulation, "beforeRateLimit"), "Rate-limit feedback did not reduce admission")
    require(integer(simulation, "finalActive") == 0, "Limiter workers/permits did not drain")
    gaps = []
    if (
        unchanged["bytesRead"] != 0
        or integer(unchanged, "sourceFilesReused") != files
        or changed["bytesRead"] > logical // 4
        or integer(changed, "filesRehashed") > 1
    ):
        gaps.append(
            "Native capture receipts are not wired: unchanged/one-file captures still "
            "rehash unrelated files. No-event safety was retained; this is NOT optimized parity."
        )
    require(not gaps or allow_revalidation_baseline, "\n".join(gaps))
    return gaps


def benchmark(binary: Path, parent: Path, mib: int, files: int, baseline: bool) -> dict:
    require(not binary.is_symlink(), "Pass the actual built test executable, not a symlink")
    binary = binary.resolve(strict=True)
    metadata = binary.stat()
    require(stat.S_ISREG(metadata.st_mode) and os.access(binary, os.X_OK), "Test binary is not an executable regular file")
    parent = parent.resolve(strict=True)
    with tempfile.TemporaryDirectory(prefix="quicksave-native-bench-", dir=parent) as temporary:
        root = Path(temporary).resolve(strict=True)
        env = isolated_environment(root, mib, files)
        status, stdout, _stderr, elapsed = run_bounded(
            [str(binary), "--exact", TEST_NAME, "--ignored", "--nocapture", "--test-threads=1"],
            root, env,
        )
        # Private subprocess output is never copied to the report or an error.
        require(status == 0, "Native source regression failed (subprocess output withheld)")
        report = parse_report(stdout)
        gaps = validate_report(report, mib, files, baseline)
        report["runnerElapsedSeconds"] = elapsed
        report["optimizedParity"] = not gaps
        report["parityGaps"] = gaps
        return report


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--binary", required=True, type=Path, help="Already-built native_optimized_pipeline test executable; never invokes Cargo")
    parser.add_argument("--temporary-parent", type=Path, default=APPROVED_TMP if APPROVED_TMP.is_dir() else Path(tempfile.gettempdir()))
    parser.add_argument("--mib", default=str(DEFAULT_MIB), help="64 by default; explicit maximum 256 MiB")
    parser.add_argument("--files", default=str(DEFAULT_FILES), help="1000 by default; maximum 4096")
    parser.add_argument("--allow-revalidation-baseline", action="store_true", help="Record the current guarded full-rehash baseline; never claim optimization parity")
    args = parser.parse_args()
    try:
        mib = bounded_int(args.mib, 64, MAX_MIB, "mib")
        files = bounded_int(args.files, 32, MAX_FILES, "files")
        report = benchmark(args.binary, args.temporary_parent, mib, files, args.allow_revalidation_baseline)
        print(json.dumps(report, sort_keys=True, allow_nan=False, separators=(",", ":")))
        return 0
    except (BenchError, OSError) as error:
        # No subprocess text, paths to application data, or credential material.
        print(f"Native benchmark refused/failed: {error if isinstance(error, BenchError) else 'local I/O failure'}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
