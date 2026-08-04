#!/usr/bin/env bash
set -euo pipefail

delete_data=false
if [[ ${1:-} == "--delete-data" ]]; then
  delete_data=true
elif [[ $# -gt 0 ]]; then
  echo "Usage: $0 [--delete-data]" >&2
  exit 2
fi

systemctl --user disable --now quietward.service 2>/dev/null || true
rm -f "${HOME}/.config/systemd/user/quietward.service"
systemctl --user daemon-reload
rm -rf "${HOME}/.local/share/quietward"

if ${delete_data}; then
  rm -rf "${HOME}/.local/state/quietward" "${HOME}/.config/quietward"
  echo "QuietWard and its local data were removed."
else
  echo "QuietWard was removed; configuration and local evidence were preserved."
fi
