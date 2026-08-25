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

# Build once more as the publication candidate and independently verify it.
python3 scripts/build_release_bundle.py "${temporary}/quietward-v0.5.0-alpha.1-source.zip" --root "${repo_root}"
python3 scripts/verify_release_bundle.py "${temporary}/quietward-v0.5.0-alpha.1-source.zip"

sha="$(sha256sum "${temporary}/quietward-v0.5.0-alpha.1-source.zip" | awk '{print $1}')"
printf 'QuietWard v0.5 release validation passed.\nSource bundle SHA-256: %s\n' "${sha}"
