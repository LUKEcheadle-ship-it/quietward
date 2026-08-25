from __future__ import annotations
import unittest
from pathlib import Path
from scripts.audit_v05_safety import audit
class V05SafetyAuditTests(unittest.TestCase):
    def test_current_private_candidate_preserves_observation_only_invariants(self) -> None:
        root = Path(__file__).resolve().parents[1]; result = audit(root); self.assertEqual(result["decision"], "PASS", result["blockers"]); self.assertEqual(result["blockers"], []); self.assertTrue(result["invariants"]["observation_only"]); self.assertEqual(result["invariants"]["actions_executed"], 0); self.assertFalse(result["invariants"]["arbitrary_shell_execution"]); self.assertFalse(result["invariants"]["automatic_remediation"]); self.assertFalse(result["invariants"]["github_actions_used"])
if __name__ == "__main__": unittest.main()
