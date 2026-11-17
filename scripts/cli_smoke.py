#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-only
"""Exercise a built QuickSave CLI using synthetic, disjoint temporary roots only."""

from __future__ import annotations

import argparse
import base64
import json
import os
from pathlib import Path
import secrets
import stat
import subprocess
import sys
import tempfile
import threading
import uuid

OUTPUT_LIMIT = 256 * 1024  # Per stream; kill rather than retain excessive output.
COMMAND_TIMEOUT = 90


class SmokeError(RuntimeError):
    pass


def require(condition: bool, message: str) -> None:
    if not condition:
        raise SmokeError(message)


def run_command(command: list[str], cwd: Path, env: dict[str, str]) -> tuple[int, bytes, bytes]:
    process = subprocess.Popen(
        command, cwd=cwd, env=env, stdout=subprocess.PIPE, stderr=subprocess.PIPE
    )
    outputs = [bytearray(), bytearray()]
    exceeded = threading.Event()
    read_errors: list[Exception] = []

    def drain(stream, output: bytearray) -> None:
        try:
            while block := stream.read(4096):
                if len(output) + len(block) > OUTPUT_LIMIT:
                    exceeded.set()
                    try:
                        process.kill()
                    except ProcessLookupError:
                        pass
                    return
                output.extend(block)
        except OSError as error:
            read_errors.append(error)
        finally:
            stream.close()

    workers = [
        threading.Thread(target=drain, args=(process.stdout, outputs[0])),
        threading.Thread(target=drain, args=(process.stderr, outputs[1])),
    ]
    for worker in workers:
        worker.start()
    timed_out = False
    try:
        process.wait(timeout=COMMAND_TIMEOUT)
    except subprocess.TimeoutExpired:
        timed_out = True
        process.kill()
        process.wait(timeout=10)
    finally:
        for worker in workers:
            worker.join(timeout=10)
        require(not any(worker.is_alive() for worker in workers), "CLI output worker did not stop")
    require(not timed_out, "CLI command timed out")
    require(not exceeded.is_set(), "CLI command exceeded bounded output")
    require(not read_errors, "CLI output could not be read")
    return process.returncode, bytes(outputs[0]), bytes(outputs[1])


def snapshot_ids(document) -> set[str]:
    if isinstance(document, dict):
        for key in ("snapshots", "result"):
            if key in document:
                return snapshot_ids(document[key])
    require(isinstance(document, list), "Snapshot list must be an array or documented wrapper")
    result: set[str] = set()
    for entry in document:
        require(isinstance(entry, dict), "Snapshot entry must be an object")
        identifier = next(
            (entry[key] for key in ("snapshotId", "snapshot_id", "id") if key in entry),
            None,
        )
        require(isinstance(identifier, str), "Snapshot entry has no identifier")
        try:
            uuid.UUID(identifier)
        except ValueError as error:
            raise SmokeError("Snapshot identifier is not a UUID") from error
        require(identifier not in result, "Snapshot list contains duplicate identifiers")
        result.add(identifier)
    return result


def tree_contents(root: Path) -> tuple[dict[str, bytes], set[str]]:
    files: dict[str, bytes] = {}
    directories: set[str] = set()
    pending = [root]
    total_bytes = 0
    while pending:
        with os.scandir(pending.pop()) as entries:
            for entry in entries:
                require(
                    len(files) + len(directories) < 256,
                    "Smoke output exceeds the tree-entry guard",
                )
                require(not entry.is_symlink(), "Smoke output unexpectedly contains a symlink")
                path = Path(entry.path)
                relative = path.relative_to(root).as_posix()
                metadata = entry.stat(follow_symlinks=False)
                if stat.S_ISDIR(metadata.st_mode):
                    directories.add(relative)
                    pending.append(path)
                else:
                    require(stat.S_ISREG(metadata.st_mode), "Smoke output contains a special file")
                    with path.open("rb") as stream:
                        value = stream.read(4 * 1024 * 1024 + 1)
                    require(len(value) <= 4 * 1024 * 1024, "Smoke output file exceeds guard")
                    total_bytes += len(value)
                    require(total_bytes <= 8 * 1024 * 1024, "Smoke output exceeds byte guard")
                    files[relative] = value
    return files, directories


def private_key(path: Path, value: bytes) -> None:
    with os.fdopen(os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600), "wb") as stream:
        stream.write(value)


def smoke(binary: Path, temporary_parent: Path | None) -> dict:
    binary = binary.resolve(strict=True)
    parent = temporary_parent.resolve(strict=True) if temporary_parent else Path(
        tempfile.gettempdir()
    ).resolve(strict=True)
    # Resolve the temporary parent to avoid macOS /var or /tmp alias ancestors.
    with tempfile.TemporaryDirectory(prefix="quicksave-cli-smoke-", dir=parent) as temporary:
        root = Path(temporary).resolve(strict=True)
        source = root / "source"
        repository = root / "repository"
        key = root / "recovery.key"
        restore_first = root / "restore-first"
        restore_second = root / "restore-second"
        occupied = root / "occupied"
        wrong_target = root / "wrong-target"
        for directory in (
            source, repository, restore_first, restore_second, occupied, wrong_target,
            root / "home", root / "config", root / "data", root / "state",
        ):
            directory.mkdir(mode=0o700)
        env = os.environ.copy()
        env.update(
            HOME=str(root / "home"),
            USERPROFILE=str(root / "home"),
            XDG_CONFIG_HOME=str(root / "config"),
            XDG_DATA_HOME=str(root / "data"),
            XDG_STATE_HOME=str(root / "state"),
            APPDATA=str(root / "config"),
            LOCALAPPDATA=str(root / "data"),
            RCLONE_CONFIG=str(root / "unused-rclone.conf"),
        )
        known_keys: list[bytes] = []
        transcripts: list[tuple[bytes, bytes]] = []
        command_count = 0

        def check_secret_output(secret: bytes, stdout: bytes, stderr: bytes):
            for representation in (secret, secret.hex().encode(), base64.b64encode(secret)):
                require(
                    representation not in stdout and representation not in stderr,
                    "CLI exposed recovery-key material",
                )

        def remember_key(path: Path):
            value = path.read_bytes()
            require(len(value) == 32, "Smoke key has an unexpected length")
            known_keys.append(value)
            # Include initialization's output, emitted before its key was readable.
            for stdout, stderr in transcripts:
                check_secret_output(value, stdout, stderr)

        def invoke(*arguments: str, success: bool = True, structured: bool = True):
            nonlocal command_count
            command_count += 1
            require(command_count <= 32, "Smoke command/transcript budget exceeded")
            status, stdout, stderr = run_command([str(binary), *arguments], root, env)
            transcripts.append((stdout, stderr))
            for secret in known_keys:
                check_secret_output(secret, stdout, stderr)
            require(
                (status == 0) == success,
                f"Unexpected CLI exit status for {arguments[0]} (output withheld)",
            )
            if not success:
                require(bool(stderr.strip()), "Failed CLI command did not explain the failure")
                return stderr
            if not structured:
                return stdout
            try:
                return json.loads(stdout)
            except (ValueError, UnicodeError) as error:
                raise SmokeError("Successful CLI command did not return JSON") from error

        help_text = invoke("--help", structured=False)
        require(b"--key-file" in help_text or b"backup" in help_text, "CLI help is missing")
        capabilities = invoke("capabilities")
        platform = capabilities.get("platform", capabilities)
        filesystem = platform.get("filesystem", {})
        writable = filesystem.get("durable_create_new")
        require(isinstance(writable, bool), "CLI has no explicit durable-write capability")
        init_arguments = (
            "init", "--repository", str(repository), "--key-file", str(key),
        )
        if not writable:
            error = invoke(*init_arguments, success=False)
            require(b"unsupported" in error.lower(), "Unavailable writes must fail explicitly")
            require(not key.exists(), "Unsupported initialization unexpectedly published a key")
            require(not list(repository.iterdir()), "Unsupported initialization modified repository")
            return {
                "status": "unsupported-refusal-verified",
                "platform": platform.get("platform"),
                "round_trip": False,
                "reason": filesystem.get("windows_durable_write_status", "durable writes unavailable"),
                "commands": command_count,
            }

        (source / "nested").mkdir()
        (source / "empty-directory").mkdir()
        (source / "notes.txt").write_bytes(b"Synthetic first revision.\n")
        (source / "empty.txt").write_bytes(b"")
        (source / "nested/state.bin").write_bytes(bytes(range(256)) * 8193)
        expected_first = tree_contents(source)
        invoke(*init_arguments)
        require(key.stat().st_size == 32, "CLI did not create the expected external raw key")
        if os.name == "posix":
            require(stat.S_IMODE(key.stat().st_mode) == 0o600, "Recovery-key mode is not 0600")
        remember_key(key)
        common = ("--repository", str(repository), "--key-file", str(key))
        require(not snapshot_ids(invoke("list", *common)), "New repository has snapshots")
        invoke("backup", *common, "--source", str(source))
        first_ids = snapshot_ids(invoke("list", *common))
        require(len(first_ids) == 1, "First backup did not publish exactly one snapshot")
        require(tree_contents(source) == expected_first, "Backup changed the source")
        first_id = next(iter(first_ids))

        (source / "notes.txt").write_bytes(b"Synthetic second revision.\n")
        (source / "empty.txt").unlink()
        (source / "added.txt").write_bytes(b"Only in the second revision.\n")
        expected_second = tree_contents(source)
        invoke("backup", *common, "--source", str(source))
        all_ids = snapshot_ids(invoke("list", *common))
        require(len(all_ids) == 2 and first_ids < all_ids, "Snapshot history is not additive")
        second_id = next(iter(all_ids - first_ids))
        require(tree_contents(source) == expected_second, "Second backup changed the source")

        for identifier, destination, expected in (
            (first_id, restore_first, expected_first),
            (second_id, restore_second, expected_second),
        ):
            invoke(
                "restore", *common, "--snapshot", identifier,
                "--destination", str(destination),
            )
            require(tree_contents(destination) == expected, "Restored tree differs from captured bytes")

        (occupied / "sentinel.txt").write_bytes(b"Existing user data must survive.\n")
        before_occupied = tree_contents(occupied)
        invoke(
            "restore", *common, "--snapshot", first_id,
            "--destination", str(occupied), success=False,
        )
        require(tree_contents(occupied) == before_occupied, "Nonempty-target refusal changed data")

        wrong = root / "wrong.key"
        private_key(wrong, secrets.token_bytes(32))
        remember_key(wrong)
        wrong_common = ("--repository", str(repository), "--key-file", str(wrong))
        invoke("list", *wrong_common, success=False)
        invoke(
            "restore", *wrong_common, "--snapshot", first_id,
            "--destination", str(wrong_target), success=False,
        )
        require(not list(wrong_target.iterdir()), "Wrong-key restore published output")
        original_key = key.read_bytes()
        invoke(*init_arguments, success=False)
        require(key.read_bytes() == original_key, "Initialization overwrote an existing key")
        require(snapshot_ids(invoke("list", *common)) == all_ids, "Failure modified snapshot history")
        return {
            "status": "passed",
            "round_trip": True,
            "snapshots_preserved": 2,
            "wrong_key_refused": True,
            "nonempty_target_preserved": True,
            "commands": command_count,
        }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--binary", type=Path, required=True, help="Already built quicksave executable")
    parser.add_argument(
        "--temp-dir", type=Path,
        default=Path(os.environ["QUICKSAVE_TEST_TMPDIR"]) if "QUICKSAVE_TEST_TMPDIR" in os.environ else None,
    )
    arguments = parser.parse_args()
    try:
        print(json.dumps(smoke(arguments.binary, arguments.temp_dir), sort_keys=True))
        return 0
    except (SmokeError, OSError, ValueError, KeyError, AttributeError) as error:
        print(f"CLI smoke failed: {error}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
