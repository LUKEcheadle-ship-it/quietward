#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
temporary="$(mktemp -d)"
trap 'rm -rf "${temporary}"' EXIT

cd "${repo_root}"

# Run the exact v0.5 hardening gate first. It sets its own PYTHONPATH, executes the
# full pytest suite with warnings-as-errors, verifies product separation and runs
# the public-release audit.
python3 scripts/verify_v05_detection.py

python3 scripts/build_release_bundle.py "${temporary}/first.zip"
python3 scripts/build_release_bundle.py "${temporary}/second.zip"

first_sha="$(sha256sum "${temporary}/first.zip" | awk '{print $1}')"
second_sha="$(sha256sum "${temporary}/second.zip" | awk '{print $1}')"
if [[ "${first_sha}" != "${second_sha}" ]]; then
  echo "Deterministic release bundle check failed." >&2
  exit 1
fi

python3 scripts/verify_release_bundle.py "${temporary}/first.zip"

printf 'QuietWard v0.5 release validation passed.\nSource bundle SHA-256: %s\n' "${first_sha}"
