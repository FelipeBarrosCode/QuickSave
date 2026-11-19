# SPDX-License-Identifier: GPL-3.0-only
"""Pure CI-contract tests. No registry, vault, user data or network access."""
import importlib.util
import json
from pathlib import Path
import unittest

ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location("ci_native_host", ROOT / "scripts/check_ci_native_host.py")
HOST = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(HOST)


class DesktopMatrixTests(unittest.TestCase):
    def test_all_desktop_targets_are_present_exactly_once(self):
        rows = json.loads((ROOT / ".github/desktop-targets.json").read_text())
        expected = {
            "windows-x86": ("windows-2025", "i686-pc-windows-msvc", "x64", "nsis"),
            "windows-x64": ("windows-2025", "x86_64-pc-windows-msvc", "x64", "nsis"),
            "windows-arm64": ("windows-11-arm", "aarch64-pc-windows-msvc", "arm64", "nsis"),
            "macos-x64": ("macos-15-intel", "x86_64-apple-darwin", "x64", "app,dmg"),
            "macos-arm64": ("macos-15", "aarch64-apple-darwin", "arm64", "app,dmg"),
            "linux-x64": ("ubuntu-24.04", "x86_64-unknown-linux-gnu", "x64", "deb,rpm"),
            "linux-arm64": ("ubuntu-24.04-arm", "aarch64-unknown-linux-gnu", "arm64", "deb,rpm"),
        }
        self.assertEqual(len(rows), len(expected))
        self.assertEqual({row["name"] for row in rows}, set(expected))
        for row in rows:
            self.assertEqual(
                tuple(row[key] for key in ("runner", "target", "python_arch", "bundles")),
                expected[row["name"]],
            )
            fields = {"name", "runner", "target", "python_arch", "bundles"}
            if row["name"] == "windows-x86":
                fields.add("execution")
                self.assertEqual(row["execution"], "wow64")
            self.assertEqual(set(row), fields)

    def test_wow64_is_explicit_and_cannot_impersonate_native_x86_or_arm(self):
        HOST.verify_native_host("i686-pc-windows-msvc", "Windows", "AMD64",
            "x86_64-pc-windows-msvc", "wow64")
        for args in [
            ("i686-pc-windows-msvc", "Windows", "AMD64", "x86_64-pc-windows-msvc", "native"),
            ("aarch64-pc-windows-msvc", "Windows", "AMD64", "x86_64-pc-windows-msvc", "wow64"),
            ("i686-pc-windows-msvc", "Linux", "AMD64", "x86_64-pc-windows-msvc", "wow64"),
        ]:
            with self.assertRaises(ValueError):
                HOST.verify_native_host(*args)

    def test_native_architecture_guard_accepts_all_six_targets(self):
        for system, machine, target in [
            ("Windows", "AMD64", "x86_64-pc-windows-msvc"),
            ("Windows", "ARM64", "aarch64-pc-windows-msvc"),
            ("Darwin", "x86_64", "x86_64-apple-darwin"),
            ("Darwin", "arm64", "aarch64-apple-darwin"),
            ("Linux", "x86_64", "x86_64-unknown-linux-gnu"),
            ("Linux", "aarch64", "aarch64-unknown-linux-gnu"),
        ]:
            HOST.verify_native_host(target, system, machine, target)

    def test_cross_compilation_emulated_python_wrong_os_and_unknown_targets_fail(self):
        for args in [
            ("aarch64-pc-windows-msvc", "Windows", "AMD64", "aarch64-pc-windows-msvc"),
            ("aarch64-apple-darwin", "Darwin", "arm64", "x86_64-apple-darwin"),
            ("x86_64-unknown-linux-gnu", "Darwin", "x86_64", "x86_64-unknown-linux-gnu"),
            ("riscv64gc-unknown-linux-gnu", "Linux", "riscv64", "riscv64gc-unknown-linux-gnu"),
        ]:
            with self.assertRaises(ValueError):
                HOST.verify_native_host(*args)


if __name__ == "__main__":
    unittest.main()
