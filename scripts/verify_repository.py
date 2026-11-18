#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-only
"""Read-only guard for pinned upstream bytes and QuickSave dependency boundaries."""

from __future__ import annotations

import argparse
import hashlib
import itertools
import json
import os
from pathlib import Path, PureWindowsPath
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
FORK_CRATES = frozenset(
    {
        "noland-attribution",
        "noland-baseline",
        "noland-cas",
        "noland-classifier",
        "noland-crypto",
        "noland-discovery",
        "noland-observer",
        "noland-pack",
        "noland-rclone-adapter",
        "noland-restore",
        "noland-rpc",
        "noland-snapshot",
        "noland-state-agent",
        "noland-state-core",
        "noland-state-db",
        "noland-storage",
        "noland-testkit",
    }
)
FORK_RECORDS = {"SOURCE.json", "FORK-CHANGES.sha256.json"}


class VerificationError(RuntimeError):
    pass


def require(condition: bool, message: str) -> None:
    if not condition:
        raise VerificationError(message)


def table(document: dict, key: str) -> dict:
    value = document.get(key, {})
    require(isinstance(value, dict), f"Expected a table/object: {key}")
    return value


def read_document(path: Path, *, toml: bool = False) -> dict:
    require(path.is_file() and not path.is_symlink(), f"Missing/unsafe document: {path}")
    with path.open("rb") as stream:
        data = stream.read(MAX_DOCUMENT_BYTES + 1)
    require(len(data) <= MAX_DOCUMENT_BYTES, f"Document exceeds guard: {path}")
    try:
        parsed = tomllib.loads(data.decode("utf-8")) if toml else json.loads(data)
    except (UnicodeError, ValueError, RecursionError) as error:
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


def literal_relative(text: str, label: str) -> Path:
    require(
        isinstance(text, str)
        and 0 < len(text.encode("utf-8")) <= 4096
        and "\\" not in text
        and "\0" not in text
        and not Path(text).is_absolute()
        and not PureWindowsPath(text).drive,
        f"Invalid/absolute {label}",
    )
    return Path(text)


def confined_path(base: Path, text: str, boundary: Path, label: str) -> Path:
    """Inspect every component, including before '..'; never follow a link out."""
    relative = literal_relative(text, label)
    require(within(base, boundary), f"Invalid base for {label}")
    current = base
    for component in relative.parts:
        current = current.parent if component == ".." else current / component
        require(within(current, boundary), f"{label} escapes its allowed root")
        require(
            not within(current, boundary / "upstream"),
            f"{label} enters the immutable upstream reference",
        )
        try:
            info = current.lstat()
        except OSError as error:
            raise VerificationError(f"Missing/unreadable {label}: {current}") from error
        require(
            not stat.S_ISLNK(info.st_mode)
            and not getattr(info, "st_file_attributes", 0)
            & getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x400),
            f"Link/reparse point in {label}: {current}",
        )
    return current


def fork_hashes(fork: Path) -> dict[str, str]:
    """Bounded read-only inventory; also rejects links in unused fork sources."""
    require(fork.is_dir() and not fork.is_symlink(), "Active fork must be a real directory")
    hashes = {}
    entries = 0
    total = 0

    def walk_error(error: OSError) -> None:
        raise VerificationError("Cannot enumerate the active fork") from error

    for directory, directories, filenames in os.walk(
        fork, followlinks=False, onerror=walk_error
    ):
        entries += len(directories) + len(filenames)
        require(entries <= MAX_TREE_ENTRIES, "Active fork exceeds entry guard")
        for name in directories + filenames:
            path = confined_path(
                fork,
                (Path(directory) / name).relative_to(fork).as_posix(),
                fork,
                "fork path",
            )
            before = path.lstat()
            if name in directories:
                require(stat.S_ISDIR(before.st_mode), "Special directory in active fork")
                continue
            require(stat.S_ISREG(before.st_mode), "Special file in active fork")
            require(before.st_size <= MAX_FILE_BYTES, "Active fork file exceeds size guard")
            total += before.st_size
            require(total <= MAX_TREE_BYTES, "Active fork exceeds byte guard")
            digest = hashlib.sha256()
            count = 0
            with path.open("rb") as stream:
                while block := stream.read(64 * 1024):
                    count += len(block)
                    require(count <= MAX_FILE_BYTES, "Active fork file grew beyond guard")
                    digest.update(block)
            after = path.lstat()
            require(
                (before.st_ino, before.st_size, before.st_mtime_ns, before.st_ctime_ns)
                == (after.st_ino, after.st_size, after.st_mtime_ns, after.st_ctime_ns)
                and count == before.st_size,
                "Active fork changed during verification",
            )
            hashes[path.relative_to(fork).as_posix()] = digest.hexdigest()
    return hashes


def check_fork(root: Path, upstream_files: dict) -> dict:
    fork = confined_path(root, "shared-storage", root, "active fork")
    source = read_document(fork / "SOURCE.json")
    require(
        source.get("commit") == EXPECTED_COMMIT
        and source.get("upstream") == "../upstream/no-land/state-agent",
        "Active fork provenance must identify the exact pinned source",
    )
    adaptations = source.get("adaptations")
    require(
        isinstance(adaptations, list)
        and 0 < len(adaptations) <= MAX_MANIFESTS
        and all(isinstance(item, str) and 0 < len(item) <= 4096 for item in adaptations),
        "Record the actual active-fork adaptations in SOURCE.json",
    )
    hashes = fork_hashes(fork)
    require(
        hashes.get("LICENSE") == upstream_files.get("LICENSE"),
        "Active fork must preserve the original upstream LICENSE verbatim",
    )
    baseline = {
        path.removeprefix("state-agent/"): digest
        for path, digest in upstream_files.items()
        if path.startswith("state-agent/")
    }
    changes = {
        path: hashes.get(path)
        for path in sorted(baseline.keys() | hashes.keys())
        if path not in FORK_RECORDS and baseline.get(path) != hashes.get(path)
    }
    require(
        read_document(fork / "FORK-CHANGES.sha256.json") == changes,
        "Active-fork change hashes are missing/stale (review changes before recording them)",
    )
    expected = {"Cargo.toml"} | {
        f"crates/{name}/Cargo.toml" for name in FORK_CRATES
    }
    require(
        {path for path in hashes if Path(path).name == "Cargo.toml"} == expected,
        "Active fork must contain only the exact approved library manifests",
    )
    for path in hashes:
        parts = Path(path).parts
        require(
            (
                parts[0] == "crates"
                and len(parts) >= 3 and parts[1] in FORK_CRATES
                or len(parts) == 1
                and parts[0] in FORK_RECORDS | {
                    "Cargo.toml", "Cargo.lock", "LICENSE", "README.md", "NOTICE", "NOTICES"
                }
            ),
            "Provisioning/lifecycle or unknown crate content in the active fork",
        )
        if path not in baseline and path.endswith(".rs"):
            with (fork / path).open("rb") as stream:
                require(
                    b"SPDX-License-Identifier: GPL-3.0-only" in stream.read(4096),
                    f"New fork source must identify GPL-3.0-only: {path}",
                )
    return {"fork_files_checked": len(hashes), "fork_changes_recorded": len(changes)}


def dependency_tables(document: dict, depth: int = 0):
    require(depth <= 32, "Manifest tables exceed nesting guard")
    for key, value in document.items():
        if key in {"dependencies", "dev-dependencies", "build-dependencies", "replace"}:
            require(isinstance(value, dict), f"Invalid dependency table: {key}")
            yield value
        if key == "patch":
            require(isinstance(value, dict), "Invalid patch table")
            for overrides in value.values():
                require(isinstance(overrides, dict), "Invalid patch source table")
                yield overrides
        if isinstance(value, dict):
            yield from dependency_tables(value, depth + 1)


def native_platform_edge(document: dict, manifest: Path, root: Path, alias: str, dependencies: dict) -> bool:
    """One reviewed reverse edge, not a general permission to escape the fork."""
    return (
        manifest == root / "shared-storage/crates/noland-state-db/Cargo.toml"
        and alias == "quicksave-platform"
        and dependencies is document.get("target", {}).get("cfg(windows)", {}).get("dependencies")
        and dependencies.get(alias) == {"path": "../../../crates/quicksave-platform"}
    )


def check_manifest_paths(document: dict, manifest: Path, boundary: Path, root: Path | None = None) -> None:
    """Check Cargo source/target paths as well as dependency paths."""
    def paths(value: dict, depth: int = 0, trail: tuple = ()) -> None:
        require(depth <= 32, "Manifest paths exceed nesting guard")
        for key, item in value.items():
            if key == "path":
                # Windows SQLite admission delegates actual handle/ACL/durability
                # operations to the audited local platform crate. No other fork
                # path, target, alias or declaration may use this reverse edge.
                approved = (
                    root is not None
                    and trail == ("target", "cfg(windows)", "dependencies", "quicksave-platform")
                    and native_platform_edge(document, manifest, root, "quicksave-platform",
                        document["target"]["cfg(windows)"]["dependencies"])
                )
                confined_path(manifest.parent, item, root if approved else boundary,
                    f"manifest path in {manifest}")
            elif isinstance(item, dict):
                paths(item, depth + 1, trail + (key,))
            elif isinstance(item, list):
                for entry in item:
                    if isinstance(entry, dict):
                        paths(entry, depth + 1, trail + (key,))

    paths(document)
    package = document.get("package", {})
    for key in ("workspace", "build", "readme", "license-file"):
        value = package.get(key)
        if isinstance(value, str):
            target = confined_path(manifest.parent, value, boundary, f"package {key}")
            if key == "workspace":
                require(target == boundary, "Package redirects its owning workspace")
        elif value is not None:
            require(key in {"build", "readme"} and isinstance(value, bool), f"Invalid package {key}")
    for key in ("include", "exclude"):
        if key in package:
            require(isinstance(package[key], list), f"Invalid package {key}")
            for pattern in package[key]:
                require(
                    ".." not in literal_relative(pattern, f"package {key}").parts,
                    f"Escaping package {key}",
                )
    for key in ("default-members", "exclude"):
        values = table(document, "workspace").get(key, [])
        require(isinstance(values, list) and len(values) <= MAX_MANIFESTS, f"Invalid workspace {key}")
        for pattern in values:
            require(
                ".." not in literal_relative(pattern, f"workspace {key}").parts,
                f"Escaping workspace {key}",
            )


def check_dependencies(root: Path) -> dict:
    workspace = read_document(root / "Cargo.toml", toml=True)
    workspace_table = table(workspace, "workspace")
    members = workspace_table.get("members")
    require(
        isinstance(members, list) and 0 < len(members) <= MAX_MANIFESTS,
        "Missing/unbounded explicit workspace members",
    )
    fork = root / "shared-storage"
    fork_workspace = read_document(fork / "Cargo.toml", toml=True)
    fork_members = table(fork_workspace, "workspace").get("members")
    require(
        isinstance(fork_members, list)
        and all(isinstance(member, str) for member in fork_members)
        and len(fork_members) == len(FORK_CRATES)
        and set(fork_members) == {f"crates/{name}" for name in FORK_CRATES},
        "Active-fork workspace must include exactly the approved libraries",
    )
    require(
        table(workspace_table, "package").get("license") == "GPL-3.0-only",
        "New QuickSave workspace must use GPL-3.0-only",
    )
    manifests = {root / "Cargo.toml"}
    for pattern in members:
        relative = literal_relative(pattern, "workspace member")
        require(
            ".." not in relative.parts and "**" not in pattern,
            "Workspace member escapes the new repository",
        )
        # Glob only a final name component, after checking its real parent.
        # Otherwise glob itself could enumerate an external linked directory
        # before the matched manifest reaches the path validator.
        require(
            not any(
                character in component
                for component in relative.parts[:-1]
                for character in "*?[]"
            ),
            "Workspace member globs may only match a final directory name",
        )
        confined_path(root, relative.parent.as_posix(), root, "workspace member parent")
        matches = list(itertools.islice(root.glob(pattern), MAX_MANIFESTS + 1))
        require(0 < len(matches) <= MAX_MANIFESTS, f"Missing/unbounded member: {pattern}")
        for member in matches:
            resolved = confined_path(root, member.relative_to(root).as_posix(), root, "workspace member")
            require(
                not within(resolved, fork),
                "The active fork must remain a separate library workspace",
            )
            manifests.add(resolved / "Cargo.toml")
    confined_path(root, "crates", root, "QuickSave crates directory")
    manifests.update(itertools.islice(root.glob("crates/*/Cargo.toml"), MAX_MANIFESTS + 1))
    desktop = root / "apps/desktop/src-tauri/Cargo.toml"
    if desktop.exists():
        manifests.add(desktop)
    manifests.add(fork / "Cargo.toml")
    manifests.update(fork / "crates" / name / "Cargo.toml" for name in FORK_CRATES)
    checked = set()
    while manifests - checked:
        require(len(manifests) <= MAX_MANIFESTS, "Too many Rust manifests")
        manifest = min(manifests - checked)
        confined_path(root, manifest.relative_to(root).as_posix(), root, "Rust manifest")
        document = read_document(manifest, toml=True)
        in_fork = within(manifest, fork)
        owner = fork_workspace if in_fork else workspace
        boundary = fork if in_fork else root
        package = table(document, "package")
        check_manifest_paths(document, manifest, boundary, root)
        package_name = package.get("name", "")
        require(
            isinstance(package_name, str)
            and (package_name in FORK_CRATES if in_fork and package else not forbidden_name(package_name)),
            f"Unexpected No Land package in QuickSave graph: {manifest}",
        )
        if in_fork:
            require(
                (manifest == fork / "Cargo.toml" and not package)
                or (package and manifest.parent == fork / "crates" / package_name),
                f"Renamed/unapproved active-fork package: {manifest}",
            )
            original = root / "upstream/no-land/state-agent" / manifest.relative_to(fork)
            original_document = read_document(original, toml=True)
            for field in ("package", "workspace"):
                current_notice = table(document, field)
                original_notice = table(original_document, field)
                if field == "workspace":
                    current_notice = table(current_notice, "package")
                    original_notice = table(original_notice, "package")
                for key in ("license", "license-file", "authors"):
                    require(
                        current_notice.get(key) == original_notice.get(key),
                        f"Original {key} notice changed in {manifest}",
                    )
            require(
                not any(document.get(key) for key in ("bin", "example", "bench"))
                and "default-run" not in package,
                f"Active fork must not expose remote-agent executable targets: {manifest}",
            )
            if package:
                library = confined_path(
                    manifest.parent,
                    table(document, "lib").get("path", "src/lib.rs"),
                    fork,
                    "active-fork library target",
                )
                require(library.is_file(), f"Missing active-fork library target: {manifest}")
            if package and ((manifest.parent / "src/main.rs").exists() or (manifest.parent / "src/bin").exists()):
                require(
                    package.get("autobins") is False,
                    f"Disable automatic remote-agent binaries in {manifest}",
                )
        elif package:
            license_value = package.get("license")
            if license_value == {"workspace": True}:
                license_value = table(workspace_table, "package").get("license")
            require(
                license_value == "GPL-3.0-only",
                f"New code must declare GPL-3.0-only: {manifest}",
            )
        for dependencies in dependency_tables(document):
            for alias, dependency in dependencies.items():
                require(isinstance(dependency, (dict, str)), f"Invalid dependency: {manifest}: {alias}")
                dependency_base = manifest.parent
                if isinstance(dependency, dict) and "workspace" in dependency:
                    require(
                        dependency["workspace"] is True
                        and set(dependency) <= {"workspace", "features", "optional", "default-features"},
                        f"Invalid workspace dependency override in {manifest}: {alias}",
                    )
                    dependency = table(table(owner, "workspace"), "dependencies").get(alias)
                    require(
                        isinstance(dependency, (dict, str))
                        and (not isinstance(dependency, dict) or "workspace" not in dependency),
                        f"Missing/recursive workspace dependency in {manifest}: {alias}",
                    )
                    dependency_base = boundary
                declared_name = dependency.get("package", alias) if isinstance(dependency, dict) else alias
                require(
                    isinstance(declared_name, str),
                    f"Invalid dependency package in {manifest}: {alias}",
                )
                target = None
                actual_name = None
                if isinstance(dependency, dict):
                    require(
                        not {"git", "branch", "tag", "rev", "artifact"} & dependency.keys(),
                        f"Git/binary dependency is outside the audited local graph: {manifest}: {alias}",
                    )
                    if "path" in dependency:
                        edge_boundary = root if native_platform_edge(
                            document, manifest, root, alias, dependencies) else boundary
                        target = confined_path(
                            dependency_base, dependency["path"], edge_boundary, "dependency path"
                        )
                        target_manifest = target / "Cargo.toml"
                        confined_path(root, target_manifest.relative_to(root).as_posix(), root, "dependency manifest")
                        actual_name = table(read_document(target_manifest, toml=True), "package").get("name")
                        require(actual_name == declared_name, f"Renamed/aliased path package mismatch: {manifest}: {alias}")
                        manifests.add(target_manifest)
                if (
                    forbidden_name(alias)
                    or forbidden_name(declared_name)
                    or target is not None and within(target, fork)
                ):
                    require(
                        actual_name in FORK_CRATES
                        and target == fork / "crates" / actual_name
                        and (not forbidden_name(alias) or alias in FORK_CRATES),
                        f"No Land dependencies must name exact active-fork libraries: {manifest}: {alias}",
                    )
        checked.add(manifest)

    # This is a local declaration guard, not a registry SBOM or executable-code audit.
    for manifest in [root / "package.json", root / "apps/desktop/package.json"]:
        if not manifest.exists():
            continue
        confined_path(root, manifest.relative_to(root).as_posix(), root, "frontend manifest")
        document = read_document(manifest)
        for table_name in ("dependencies", "devDependencies", "optionalDependencies"):
            for name, value in table(document, table_name).items():
                specifier = str(value).lower().replace("\\", "/")
                require(
                    not forbidden_name(name)
                    and "upstream/" not in specifier
                    and "no_land" not in specifier
                    and "no-land" not in specifier
                    and "shared-storage" not in specifier,
                    f"Vendor/No Land frontend dependency in {manifest}: {name}",
                )
    return {"workspace_members": len(members), "rust_manifests_checked": len(checked)}


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
    return {
        "status": "verified",
        **actual,
        **check_fork(root, expected_files),
        **check_dependencies(root),
    }


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
