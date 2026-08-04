#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
temporary="$(mktemp -d)"
trap 'rm -rf "${temporary}"' EXIT

cd "${repo_root}"

PYTHONPATH=src python3 -m unittest discover -s tests -v
python3 -m compileall -q src tests scripts
python3 scripts/public_release_audit.py
python3 scripts/build_release_bundle.py "${temporary}/first.zip"
python3 scripts/build_release_bundle.py "${temporary}/second.zip"

first_sha="$(sha256sum "${temporary}/first.zip" | awk '{print $1}')"
second_sha="$(sha256sum "${temporary}/second.zip" | awk '{print $1}')"
if [[ "${first_sha}" != "${second_sha}" ]]; then
  echo "Deterministic release bundle check failed." >&2
  exit 1
fi

printf 'QuietWard release validation passed.\nSource bundle SHA-256: %s\n' "${first_sha}"
