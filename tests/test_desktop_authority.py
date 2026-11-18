# SPDX-License-Identifier: GPL-3.0-only
"""The desktop must not retain the old unconsented/local-format IPC fallback."""

import json
from pathlib import Path
import re
import unittest


ROOT = Path(__file__).resolve().parents[1]
EXPECTED = {"workspace_query", "workspace_prepare", "workspace_execute"}


def bounded_text(relative):
    with (ROOT / relative).open("rb") as stream:
        data = stream.read(128 * 1024 + 1)
    if len(data) > 128 * 1024:
        raise AssertionError("Desktop authority declaration exceeded its bound")
    return data.decode("utf-8")


class DesktopAuthorityTests(unittest.TestCase):
    def test_only_exact_workspace_commands_are_registered(self):
        source = bounded_text("apps/desktop/src-tauri/src/main.rs")
        block = re.search(r"\.invoke_handler\(tauri::generate_handler!\[(.*?)\]\)", source, re.S)
        self.assertIsNotNone(block)
        without_comments = re.sub(r"//[^\n]*", "", block.group(1))
        self.assertEqual(set(re.findall(r"\b[a-z_]+\b", without_comments)), EXPECTED)

    def test_generated_command_permissions_match_the_same_boundary(self):
        source = bounded_text("apps/desktop/src-tauri/build.rs")
        declaration = re.search(r"\.commands\(&\[(.*?)\]\)", source, re.S)
        self.assertIsNotNone(declaration)
        self.assertEqual(set(re.findall(r'"([a-z_]+)"', declaration.group(1))), EXPECTED)

    def test_main_capability_has_no_legacy_discovery_or_transfer_permissions(self):
        capability = json.loads(bounded_text("apps/desktop/src-tauri/capabilities/main.json"))
        allowed = {"core:default", "dialog:allow-open", "dialog:allow-save"}
        allowed.update("allow-" + name.replace("_", "-") for name in EXPECTED)
        self.assertEqual(set(capability["permissions"]), allowed)
        self.assertTrue(capability["local"])


if __name__ == "__main__":
    unittest.main()
