#!/usr/bin/env bash
set -euo pipefail

start_service=true
migrate_pre_rename=false
if [[ ${1:-} == "--no-start" ]]; then
  start_service=false
elif [[ ${1:-} == "--migrate-pre-rename" ]]; then
  migrate_pre_rename=true
elif [[ $# -gt 0 ]]; then
  echo "Usage: $0 [--no-start|--migrate-pre-rename]" >&2
  exit 2
fi

if [[ ${EUID} -eq 0 && ${QUIETWARD_ALLOW_ROOT_TEST_INSTALL:-0} != 1 ]]; then
  echo "Run this installer as the normal service user, not root." >&2
  exit 2
fi

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
install_root="${HOME}/.local/share/quietward"
app_root="${install_root}/app"
bin_root="${install_root}/bin"
config_dir="${HOME}/.config/quietward"
state_dir="${HOME}/.local/state/quietward"
unit_dir="${HOME}/.config/systemd/user"

migration_prepared=false
migration_finalized=false
legacy_service_stop_attempted=false
rollback_migration() {
  status="${1:-$?}"
  trap - ERR
  set +e
  if ${migration_prepared} && ! ${migration_finalized}; then
    systemctl --user disable --now quietward.service >/dev/null 2>&1
    python3 "${repo_root}/scripts/migrate_pre_rename_user_install.py" rollback
    systemctl --user daemon-reload
  fi
  if ${legacy_service_stop_attempted} && ! ${migration_finalized}; then
    systemctl --user start forge-sentinel.service
  fi
  exit "${status}"
}
trap 'rollback_migration $?' ERR

if ${migrate_pre_rename}; then
  legacy_service_stop_attempted=true
  systemctl --user stop forge-sentinel.service
  if systemctl --user is-active --quiet forge-sentinel.service; then
    echo "forge-sentinel.service did not stop cleanly" >&2
    rollback_migration 2
  fi
  python3 "${repo_root}/scripts/migrate_pre_rename_user_install.py" prepare
  migration_prepared=true
fi

mkdir -p "${app_root}" "${bin_root}" "${config_dir}" "${state_dir}" "${unit_dir}"
chmod 700 "${install_root}" "${app_root}" "${bin_root}" "${config_dir}" "${state_dir}"
privacy_key="${config_dir}/privacy-identity.key"
if [[ -L "${privacy_key}" ]]; then
  echo "Refusing symlinked privacy identity key: ${privacy_key}" >&2
  exit 2
fi
if [[ ! -e "${privacy_key}" ]]; then
  umask 077
  python3 - "${privacy_key}" <<'PY'
import os
import secrets
import sys

path = sys.argv[1]
descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
try:
    os.write(descriptor, secrets.token_bytes(32))
finally:
    os.close(descriptor)
PY
fi
chmod 600 "${privacy_key}"
rm -rf "${app_root}/quietward"
cp -a "${repo_root}/src/quietward" "${app_root}/quietward"
find "${app_root}" -type d -name __pycache__ -prune -exec rm -rf {} +
find "${app_root}" -type f -name '*.pyc' -delete

cat > "${bin_root}/quietward" <<'LAUNCHER'
#!/usr/bin/env bash
set -euo pipefail
install_root="${HOME}/.local/share/quietward"
export PYTHONPATH="${install_root}/app${PYTHONPATH:+:${PYTHONPATH}}"
exec python3 -m quietward.console "$@"
LAUNCHER
chmod 700 "${bin_root}/quietward"

if [[ ! -e "${config_dir}/config.json" ]]; then
  cp "${repo_root}/config/quietward.example.json" "${config_dir}/config.json"
  chmod 600 "${config_dir}/config.json"
fi
cp "${repo_root}/deploy/quietward.service" "${unit_dir}/quietward.service"
chmod 600 "${unit_dir}/quietward.service"

"${bin_root}/quietward" model-info --config "${config_dir}/config.json" >/dev/null
"${bin_root}/quietward" doctor --config "${config_dir}/config.json" --pretty || true

if ${start_service}; then
  systemctl --user daemon-reload
  systemctl --user enable --now quietward.service
  systemctl --user --no-pager status quietward.service || true
fi

if ${migrate_pre_rename}; then
  if ! systemctl --user is-active --quiet quietward.service; then
    echo "quietward.service did not become active; rolling back" >&2
    rollback_migration 2
  fi
  python3 "${repo_root}/scripts/migrate_pre_rename_user_install.py" finalize
  migration_finalized=true
fi

trap - ERR

echo "QuietWard installed without network downloads or Python package dependencies."
echo "Launcher: ${bin_root}/quietward"
echo "Configuration: ${config_dir}/config.json"
echo "State: ${state_dir}"
echo "Redacted export: ${bin_root}/quietward export FINDING_ID OUTPUT"
