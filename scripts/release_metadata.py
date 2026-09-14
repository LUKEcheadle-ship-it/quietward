"""Read and cross-check current release metadata without importing runtime code."""
from pathlib import Path
import re
import tomllib


def release_metadata(root: Path) -> tuple[str, str]:
    project = tomllib.loads((root / "pyproject.toml").read_text(encoding="utf-8"))["project"]
    version = str(project["version"])
    source = (root / "src/quietward/__init__.py").read_text(encoding="utf-8")
    match = re.search(r'__version__\s*=\s*"([^"]+)"', source)
    if project["name"] != "quietward" or match is None or match.group(1) != version:
        raise ValueError("QuietWard source and package release metadata disagree")
    if not re.fullmatch(r"\d+\.\d+\.\d+(?:a\d+)?", version):
        raise ValueError("unsupported release version format")
    return version, re.sub(r"a(\d+)$", r"-alpha.\1", version)
