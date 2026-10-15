#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
temporary="$(mktemp -d)"
trap 'rm -rf "${temporary}"' EXIT

cd "${repo_root}"

# Run the complete public v0.5 release gate: repository tests, compilation,
# observation-only safety audit, strict public audit, deterministic double build,
# and independent verification of both archives.
python3 scripts/validate_migrated_release.py --root "${repo_root}" --pretty

# Derive the publication candidate name from the authoritative current source
# and package metadata; reject mismatched versions before staging any archive.
release_version="$(python3 - "${repo_root}" <<'PY'
import sys
from pathlib import Path
root = Path(sys.argv[1]).resolve()
sys.path.insert(0, str(root / "scripts"))
from release_metadata import release_metadata
_, display_version = release_metadata(root)
print(display_version)
PY
)"
archive="${temporary}/quietward-v${release_version}-source.zip"

# Independently verify the same versioned release archive as the gate above.
python3 scripts/build_release_bundle.py "${archive}" --root "${repo_root}"
python3 scripts/verify_release_bundle.py "${archive}"

sha="$(sha256sum "${archive}" | awk '{print $1}')"
printf 'QuietWard v%s source validation passed.\nSource bundle SHA-256: %s\n' "${release_version}" "${sha}"
printf 'Target-host Windows 11 and Debian 12 qualification and public prerelease publication are separate remaining gates.\n'
