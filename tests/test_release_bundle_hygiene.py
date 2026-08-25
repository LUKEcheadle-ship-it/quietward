from __future__ import annotations

import importlib.util
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts" / "build_release_bundle.py"
SPEC = importlib.util.spec_from_file_location("build_release_bundle_hygiene", SCRIPT)
assert SPEC is not None and SPEC.loader is not None
BUNDLE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(BUNDLE)


class ReleaseBundleHygieneTests(unittest.TestCase):
    def test_transient_test_cache_and_sensitive_state_are_excluded(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            (root / "pyproject.toml").write_text(
                '[project]\nname="quietward"\nversion="0.5.0a1"\n',
                encoding="utf-8",
            )
            (root / "README.md").write_text("safe\n", encoding="utf-8")
            cache = root / ".pytest_cache" / "v" / "cache"
            cache.mkdir(parents=True)
            (cache / "nodeids").write_text("[]\n", encoding="utf-8")
            state = root / "state"
            state.mkdir()
            (state / "runtime.sqlite3").write_bytes(b"database")
            (state / "privacy.key").write_bytes(b"secret")
            (root / "module.pyc").write_bytes(b"compiled")

            included = {path.as_posix() for path in BUNDLE.included_files(root)}
            self.assertIn("README.md", included)
            self.assertIn("pyproject.toml", included)
            self.assertNotIn(".pytest_cache/v/cache/nodeids", included)
            self.assertNotIn("state/runtime.sqlite3", included)
            self.assertNotIn("state/privacy.key", included)
            self.assertNotIn("module.pyc", included)


if __name__ == "__main__":
    unittest.main()
