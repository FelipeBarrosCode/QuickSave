#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-only
"""Type-check Linux inventory against actual libdbus Rust FFI declarations.

No C build, linking, credential service, bus connection, or native calls occur.
This is deliberately NOT a substitute for native Linux runtime acceptance.
"""
import argparse
import glob
import json
import os
from pathlib import Path
import subprocess
import tempfile


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--anyhow", type=Path, required=True,
                        help="Existing x86_64-unknown-linux-gnu anyhow .rmeta")
    args = parser.parse_args()
    root = Path(__file__).resolve().parent.parent
    matches = glob.glob(str(Path.home() / ".cargo/registry/src/*/libdbus-sys-0.2.7/src/lib.rs"))
    if len(matches) != 1:
        raise SystemExit("Expected exactly one cached pinned libdbus-sys source; no downloads attempted")
    if not args.anyhow.is_file():
        raise SystemExit("Compile Linux anyhow metadata first; no native toolchain installation attempted")
    base = Path(os.environ.get("TMPDIR", tempfile.gettempdir())).resolve()
    target = "x86_64-unknown-linux-gnu"
    with tempfile.TemporaryDirectory(prefix="linux-vault-typecheck-", dir=base) as directory:
        directory = Path(directory)
        bindings = directory / "libdbus_sys.rmeta"
        common = ["rustc", "--edition=2021", "--crate-type=rlib", "--emit=metadata", "--target", target]
        subprocess.run(common + ["--crate-name", "libdbus_sys", matches[0], "-o", str(bindings)],
                       check=True)
        source = directory / "inventory.rs"
        source.write_text(
            'const QUICKSAVE_VAULT_SERVICE: &str = "quicksave.desktop-secrets.v1";\n'
            f'#[path = {json.dumps(str(root / "crates/quicksave-state/src/vault_inventory_linux.rs"))}]\n'
            'mod inventory;\n'
        )
        subprocess.run(common + ["--crate-name", "quicksave_linux_inventory_check",
            str(source), "--extern", f"anyhow={args.anyhow.resolve()}",
            "--extern", f"libdbus_sys={bindings}", "-L", f"dependency={args.anyhow.resolve().parent}",
            "-o", str(directory / "inventory.rmeta")], check=True)
    print(json.dumps({"target": target, "rust_typecheck": "passed",
                      "native_link_or_execution": False, "credential_service_access": False}))


if __name__ == "__main__":
    main()
