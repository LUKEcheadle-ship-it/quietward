from __future__ import annotations

import importlib.util
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
MODULE_PATH = ROOT / "src" / "quietward" / "windows_restart.py"
SPEC = importlib.util.spec_from_file_location("quietward_windows_restart_scope_test", MODULE_PATH)
assert SPEC is not None and SPEC.loader is not None
WINDOWS_RESTART = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(WINDOWS_RESTART)


class WindowsRestartScopeTests(unittest.TestCase):
    PROTECTED = (
        r"C:\Users\tester\quietward",
        r"C:\Users\tester\AppData\Local\QuietWard",
        r"C:\Users\tester\.config\quietward",
    )

    def test_external_active_operation_is_warning_not_product_blocker(self) -> None:
        result = WINDOWS_RESTART.assess_windows_restart_state(
            pending_values=[r"\??\C:\Program Files\Vendor\update.tmp", ""],
            component_servicing_pending=False,
            windows_update_pending=False,
            system_root=r"C:\Windows",
            boot_token="boot-1",
            path_exists=lambda _: True,
            protected_roots=self.PROTECTED,
        )
        self.assertEqual("PASS_EXTERNAL", result["decision"], result)
        self.assertEqual(0, result["counts"]["active_protected"])
        self.assertEqual(1, result["counts"]["active_external"])
        self.assertFalse(result["safety"]["external_software_modified"])

    def test_active_operation_under_install_root_blocks(self) -> None:
        result = WINDOWS_RESTART.assess_windows_restart_state(
            pending_values=[r"\??\C:\Users\tester\AppData\Local\QuietWard\venv\file.tmp", ""],
            component_servicing_pending=False,
            windows_update_pending=False,
            system_root=r"C:\Windows",
            boot_token="boot-1",
            path_exists=lambda _: True,
            protected_roots=self.PROTECTED,
        )
        self.assertEqual("BLOCK", result["decision"], result)
        self.assertEqual(1, result["counts"]["active_protected"])
        self.assertEqual(0, result["counts"]["active_external"])

    def test_protected_root_match_is_case_insensitive(self) -> None:
        pending = "\\??\\" + self.PROTECTED[1].upper() + r"\state\file.tmp"
        result = WINDOWS_RESTART.assess_windows_restart_state(
            pending_values=[pending, ""],
            component_servicing_pending=False,
            windows_update_pending=False,
            system_root=r"C:\Windows",
            boot_token="boot-1",
            path_exists=lambda _: True,
            protected_roots=self.PROTECTED,
        )
        self.assertEqual("BLOCK", result["decision"], result)
        self.assertEqual("protected", result["operations"][0]["scope"])

    def test_path_prefix_without_directory_boundary_is_external(self) -> None:
        result = WINDOWS_RESTART.assess_windows_restart_state(
            pending_values=[r"\??\C:\Users\tester\AppData\Local\QuietWardBackup\file.tmp", ""],
            component_servicing_pending=False,
            windows_update_pending=False,
            system_root=r"C:\Windows",
            boot_token="boot-1",
            path_exists=lambda _: True,
            protected_roots=self.PROTECTED,
        )
        self.assertEqual("PASS_EXTERNAL", result["decision"])
        self.assertEqual("external", result["operations"][0]["scope"])

    def test_external_active_and_absent_operations_can_start_with_warning(self) -> None:
        existing = r"C:\Program Files\Vendor\active.tmp"
        result = WINDOWS_RESTART.assess_windows_restart_state(
            pending_values=[r"\??\C:\Program Files\Vendor\active.tmp", "", r"\??\C:\Program Files\Vendor\gone.tmp", ""],
            component_servicing_pending=False,
            windows_update_pending=False,
            system_root=r"C:\Windows",
            boot_token="boot-1",
            path_exists=lambda path: path.lower() == existing.lower(),
            protected_roots=self.PROTECTED,
        )
        self.assertEqual("PASS_EXTERNAL", result["decision"], result)
        self.assertEqual(1, result["counts"]["active_external"])
        self.assertEqual(1, result["counts"]["stale_candidates"])

    def test_windows_servicing_flag_still_blocks_external_queue(self) -> None:
        result = WINDOWS_RESTART.assess_windows_restart_state(
            pending_values=[r"\??\C:\Program Files\Vendor\update.tmp", ""],
            component_servicing_pending=True,
            windows_update_pending=False,
            system_root=r"C:\Windows",
            boot_token="boot-1",
            path_exists=lambda _: True,
            protected_roots=self.PROTECTED,
        )
        self.assertEqual("BLOCK", result["decision"])

    def test_start_script_passes_all_sentinel_roots_and_accepts_external_warning(self) -> None:
        text = (ROOT / "scripts" / "start_beta_soak.ps1").read_text(encoding="utf-8")
        self.assertIn('"--protected-root", $Root', text)
        self.assertIn('"--protected-root", $ProductRoot', text)
        self.assertIn('"--protected-root", $ConfigRoot', text)
        self.assertIn('"PASS_EXTERNAL"', text)
        self.assertIn("active_protected", text)

    def test_inspector_does_not_expose_paths_without_explicit_flag(self) -> None:
        text = (ROOT / "scripts" / "inspect_windows_restart_state.py").read_text(encoding="utf-8")
        self.assertIn("--show-paths", text)
        self.assertIn('"scope": item.get("scope")', text)
        self.assertIn("PASS_EXTERNAL", text)
        self.assertNotIn("SetValue", text)
        self.assertNotIn("DeleteValue", text)


if __name__ == "__main__":
    unittest.main()
