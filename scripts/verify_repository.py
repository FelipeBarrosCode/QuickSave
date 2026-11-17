#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-only
"""Read-only guard for pinned upstream bytes and QuickSave dependency boundaries."""

from __future__ import annotations

import argparse
import hashlib
import itertools
import json
import os
from pathlib import Path
import stat
import sys
import tomllib

EXPECTED_COMMIT = "e81238a7536aae201540956ce76981364fd36595"
EXPECTED_ARCHIVE = "157156c3812aba45fdbfcc97268eede85dd34c49c3df2db0628874c085247fa5"
EXPECTED_REPOSITORY = "https://github.com/FelipeBarrosCode/no_land"
EXPECTED_PATHS = {
    "state-agent",
    "LICENSE",
    "docs/shared-storage-restore-pipeline.md",
    "docs/shared-storage-io-validation.md",
    "docs/shared-storage-dev-optimizations.md",
    "docs/state-secret-storage.md",
}
ALGORITHM = "sha256(sorted UTF-8 relative-path NUL decimal-size NUL file-sha256 LF)"
MAX_DOCUMENT_BYTES = 256 * 1024
MAX_FILE_BYTES = 16 * 1024 * 1024
MAX_TREE_BYTES = 128 * 1024 * 1024
MAX_TREE_ENTRIES = 10_000
MAX_MANIFESTS = 128


class VerificationError(RuntimeError):
    pass


def require(condition: bool, message: str) -> None:
    if not condition:
        raise VerificationError(message)


def read_document(path: Path, *, toml: bool = False) -> dict:
    require(path.is_file() and not path.is_symlink(), f"Missing/unsafe document: {path}")
    with path.open("rb") as stream:
        data = stream.read(MAX_DOCUMENT_BYTES + 1)
    require(len(data) <= MAX_DOCUMENT_BYTES, f"Document exceeds guard: {path}")
    try:
        parsed = tomllib.loads(data.decode("utf-8")) if toml else json.loads(data)
    except (UnicodeError, ValueError) as error:
        raise VerificationError(f"Invalid document: {path}") from error
    require(isinstance(parsed, dict), f"Expected a document object: {path}")
    return parsed


def tree_fingerprint(snapshot: Path, expected_files: dict | None = None) -> dict:
    """Hash regular-file paths, lengths and bytes; reject links and special files."""
    require(
        snapshot.is_dir() and not snapshot.is_symlink(),
        "The upstream snapshot must be a real directory",
    )
    files: list[tuple[str, int, str]] = []
    entry_count = 0
    total_bytes = 0

    def walk_error(error: OSError) -> None:
        raise VerificationError("Cannot enumerate the upstream snapshot") from error

    for directory, directories, filenames in os.walk(
        snapshot, followlinks=False, onerror=walk_error
    ):
        entry_count += len(directories) + len(filenames)
        require(entry_count <= MAX_TREE_ENTRIES, "Upstream tree exceeds entry guard")
        for name in directories:
            mode = (Path(directory) / name).lstat().st_mode
            require(stat.S_ISDIR(mode), "Upstream contains a link/special directory")
        for name in filenames:
            path = Path(directory) / name
            before = path.lstat()
            require(stat.S_ISREG(before.st_mode), "Upstream contains a link/special file")
            require(before.st_size <= MAX_FILE_BYTES, "Upstream file exceeds size guard")
            relative = path.relative_to(snapshot).as_posix()
            require(len(relative.encode("utf-8")) <= 4096, "Upstream path exceeds guard")
            total_bytes += before.st_size
            require(total_bytes <= MAX_TREE_BYTES, "Upstream tree exceeds byte guard")
            digest = hashlib.sha256()
            count = 0
            with path.open("rb") as stream:
                while block := stream.read(64 * 1024):
                    count += len(block)
                    require(count <= MAX_FILE_BYTES, "Upstream file grew beyond guard")
                    digest.update(block)
            after = path.lstat()
            require(
                (before.st_ino, before.st_size, before.st_mtime_ns, before.st_ctime_ns)
                == (after.st_ino, after.st_size, after.st_mtime_ns, after.st_ctime_ns)
                and count == before.st_size,
                "Upstream changed during verification",
            )
            files.append((relative, count, digest.hexdigest()))

    if expected_files is not None:
        require(
            {path: digest for path, _length, digest in files} == expected_files,
            "Upstream file manifest does not match the exact snapshot files/hashes",
        )
    tree = hashlib.sha256()
    for relative, length, digest in sorted(files):
        tree.update(
            relative.encode("utf-8")
            + b"\0"
            + str(length).encode("ascii")
            + b"\0"
            + digest.encode("ascii")
            + b"\n"
        )
    return {"file_count": len(files), "tree_sha256": tree.hexdigest()}


def within(path: Path, root: Path) -> bool:
    return path.is_relative_to(root)


def forbidden_name(name: str) -> bool:
    normalized = name.lower().replace("_", "-")
    return normalized == "noland" or normalized.startswith(("noland-", "no-land"))


def dependency_tables(document: dict):
    for key, value in document.items():
        if not isinstance(value, dict):
            continue
        if key in {"dependencies", "dev-dependencies", "build-dependencies", "replace"}:
            yield value
        if key == "patch":
            for overrides in value.values():
                if isinstance(overrides, dict):
                    yield overrides
        yield from dependency_tables(value)


def check_dependencies(root: Path) -> dict:
    workspace = read_document(root / "Cargo.toml", toml=True)
    members = workspace.get("workspace", {}).get("members")
    require(isinstance(members, list) and members, "Missing explicit workspace members")
    manifests = {root / "Cargo.toml"}
    for pattern in members:
        require(isinstance(pattern, str), "Invalid workspace member")
        require(
            not Path(pattern).is_absolute() and ".." not in Path(pattern).parts,
            "Workspace member escapes the new repository",
        )
        matches = list(itertools.islice(root.glob(pattern), MAX_MANIFESTS + 1))
        require(0 < len(matches) <= MAX_MANIFESTS, f"Missing/unbounded member: {pattern}")
        for member in matches:
            resolved = member.resolve()
            require(
                within(resolved, root) and not within(resolved, root / "upstream"),
                "Vendor/outside code must not be a QuickSave workspace member",
            )
            manifests.add(resolved / "Cargo.toml")
    manifests.update(root.glob("crates/*/Cargo.toml"))
    desktop = root / "apps/desktop/src-tauri/Cargo.toml"
    if desktop.exists():
        manifests.add(desktop)
    require(len(manifests) <= MAX_MANIFESTS, "Too many new Rust manifests")

    for manifest in sorted(manifests):
        document = read_document(manifest, toml=True)
        package = document.get("package", {})
        require(
            not forbidden_name(str(package.get("name", ""))),
            f"No Land package in QuickSave graph: {manifest}",
        )
        for table in dependency_tables(document):
            for alias, dependency in table.items():
                package_name = dependency.get("package", alias) if isinstance(
                    dependency, dict
                ) else alias
                require(
                    not forbidden_name(str(alias))
                    and not forbidden_name(str(package_name)),
                    f"No Land runtime dependency in {manifest}: {alias}",
                )
                if not isinstance(dependency, dict):
                    continue
                git = str(dependency.get("git", "")).lower().replace("-", "_")
                require("no_land" not in git, f"No Land Git dependency in {manifest}")
                if "path" in dependency:
                    path = dependency["path"]
                    require(isinstance(path, str), f"Invalid dependency path: {manifest}")
                    target = (manifest.parent / path).resolve()
                    require(
                        within(target, root) and not within(target, root / "upstream"),
                        f"Vendor/outside path dependency in {manifest}: {alias}",
                    )

    # This is a declaration guard, not a transitive SBOM or executable-code audit.
    for manifest in [root / "package.json", root / "apps/desktop/package.json"]:
        if not manifest.exists():
            continue
        document = read_document(manifest)
        for table_name in ("dependencies", "devDependencies", "optionalDependencies"):
            for name, value in document.get(table_name, {}).items():
                specifier = str(value).lower().replace("\\", "/")
                require(
                    not forbidden_name(name)
                    and "upstream/" not in specifier
                    and "no_land" not in specifier
                    and "no-land" not in specifier,
                    f"Vendor/No Land frontend dependency in {manifest}: {name}",
                )
    return {"workspace_members": len(members), "rust_manifests_checked": len(manifests)}


def verify(root: Path) -> dict:
    root = root.resolve()
    require(not (root / "upstream").is_symlink(), "Upstream parent must not be a link")
    source = read_document(root / "upstream/SOURCE.json")
    require(source.get("commit") == EXPECTED_COMMIT, "Upstream commit metadata changed")
    require(
        source.get("source_repository") == EXPECTED_REPOSITORY,
        "Upstream source repository metadata changed",
    )
    require(
        source.get("archive_sha256") == EXPECTED_ARCHIVE,
        "Recorded upstream archive digest changed",
    )
    require(set(source.get("paths", [])) == EXPECTED_PATHS, "Upstream path scope changed")
    pinned = read_document(root / "scripts/upstream-provenance.json")
    require(
        pinned.get("format_version") == 1
        and pinned.get("algorithm") == ALGORITHM
        and pinned.get("source_commit") == EXPECTED_COMMIT
        and pinned.get("archive_sha256") == EXPECTED_ARCHIVE,
        "Invalid unpacked-tree provenance baseline",
    )
    expected_files = read_document(root / "upstream/FILES.sha256.json")
    require(
        len(expected_files) <= MAX_TREE_ENTRIES
        and all(
            isinstance(path, str)
            and isinstance(digest, str)
            and len(digest) == 64
            and all(character in "0123456789abcdef" for character in digest)
            for path, digest in expected_files.items()
        ),
        "Invalid upstream file-hash manifest",
    )
    actual = tree_fingerprint(root / "upstream/no-land", expected_files)
    require(
        all(pinned.get(key) == value for key, value in actual.items()),
        "Unpacked upstream bytes/paths changed; do not regenerate the baseline",
    )
    return {"status": "verified", **actual, **check_dependencies(root)}


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=Path, default=Path(__file__).resolve().parents[1])
    arguments = parser.parse_args()
    try:
        print(json.dumps(verify(arguments.root), sort_keys=True))
        return 0
    except (VerificationError, OSError, TypeError, UnicodeError) as error:
        print(f"Repository verification failed: {error}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
