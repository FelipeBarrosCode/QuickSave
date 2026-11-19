#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-only
"""Verify CI test binaries will execute on the claimed native OS/architecture."""
from __future__ import annotations

import platform
import subprocess
import sys


def verify_native_host(target: str, system: str, machine: str, rust_host: str, execution: str = "native") -> None:
    if execution == "wow64":
        if (target, system, machine.lower(), rust_host) != (
            "i686-pc-windows-msvc", "Windows", "amd64", "x86_64-pc-windows-msvc"
        ):
            raise ValueError("WOW64 requires Windows x64 and the explicit i686 target")
        return
    if execution != "native":
        raise ValueError("Unknown execution mode")
    architectures = {"x86_64": "x64", "amd64": "x64", "aarch64": "arm64", "arm64": "arm64"}
    expected_arch = {"x86_64": "x64", "aarch64": "arm64"}.get(target.split("-")[0])
    expected_system = (
        "Windows" if target.endswith("windows-msvc") else
        "Darwin" if target.endswith("apple-darwin") else
        "Linux" if target.endswith("unknown-linux-gnu") else None
    )
    if expected_arch is None or expected_system is None:
        raise ValueError("Unsupported CI target")
    if system != expected_system or architectures.get(machine.lower()) != expected_arch:
        raise ValueError("Runner OS/architecture does not match the native target")
    if rust_host != target:
        raise ValueError("Rust toolchain host does not match the native target")


def main() -> int:
    if len(sys.argv) not in (2, 3):
        raise ValueError("Supply a target triple and optional execution mode")
    execution = sys.argv[2] if len(sys.argv) == 3 else "native"
    result = subprocess.run(
        ["rustc", "-vV"], check=True, capture_output=True, timeout=15,
    )
    if len(result.stdout) > 16384 or len(result.stderr) > 16384:
        raise ValueError("Rust version output exceeds bounds")
    host = next((line[6:] for line in result.stdout.decode().splitlines() if line.startswith("host: ")), "")
    verify_native_host(sys.argv[1], platform.system(), platform.machine(), host, execution)
    print(f"CI execution mode verified: {execution}, target={sys.argv[1]}, host={host}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
