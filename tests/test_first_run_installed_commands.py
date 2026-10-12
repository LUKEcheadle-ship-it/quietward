"""Keep Windows onboarding aligned with the actual private-venv installer."""
from pathlib import Path
import unittest

ROOT = Path(__file__).resolve().parents[1]

class InstalledCommandsTest(unittest.TestCase):
    def test_windows_guide_uses_installed_module_without_global_path(self):
        guide = (ROOT / "docs/FIRST_RUN.md").read_text(encoding="utf-8")
        command = '& "$env:LOCALAPPDATA\\QuietWard\\venv\\Scripts\\python.exe" -m quietward'
        self.assertIn(command + ' doctor --pretty', guide)
        self.assertIn(command + ' open-dashboard --pretty', guide)
        self.assertNotIn('\nquietward doctor', guide)
        self.assertNotIn('\nquietward open-dashboard', guide)
        installer = (ROOT / "scripts/install_windows_preview.ps1").read_text(encoding="utf-8")
        self.assertIn('$VenvDir = Join-Path $ProductRoot "venv"', installer)
        self.assertIn('$VenvPython = Join-Path $VenvDir "Scripts\\python.exe"', installer)

if __name__ == "__main__":
    unittest.main()
