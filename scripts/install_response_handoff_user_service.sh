#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
SCRIPT="$ROOT/scripts/run_response_handoff_outbox.py"
CONFIG="${1:-$HOME/.config/quietward/config.json}"
OUTBOX="${2:-$HOME/.local/state/quietward/response-handoff-outbox}"
UNIT_DIR="$HOME/.config/systemd/user"
UNIT="$UNIT_DIR/quietward-response-handoff.service"

if [[ "$CONFIG" != /* || "$OUTBOX" != /* ]]; then
  echo "Config and outbox paths must be absolute." >&2
  exit 2
fi
if [[ ! -f "$CONFIG" ]]; then
  echo "QuietWard config not found: $CONFIG" >&2
  exit 2
fi
if [[ ! -f "$SCRIPT" ]]; then
  echo "QuietWard handoff exporter not found: $SCRIPT" >&2
  exit 2
fi

if [[ -x "$ROOT/.venv/bin/python" ]]; then
  PYTHON="$ROOT/.venv/bin/python"
elif command -v python3 >/dev/null 2>&1; then
  PYTHON="$(command -v python3)"
else
  echo "python3 was not found." >&2
  exit 2
fi

mkdir -p "$UNIT_DIR" "$OUTBOX"
chmod 700 "$OUTBOX" || true

cat >"$UNIT" <<EOF
[Unit]
Description=QuietWard local Response handoff outbox
After=default.target

[Service]
Type=simple
ExecStart="$PYTHON" "$SCRIPT" --config "$CONFIG" --outbox "$OUTBOX" --interval 5
Restart=on-failure
RestartSec=5
NoNewPrivileges=true
PrivateTmp=true
UMask=0077

[Install]
WantedBy=default.target
EOF
chmod 600 "$UNIT"

systemctl --user daemon-reload
systemctl --user enable --now quietward-response-handoff.service

echo "QuietWard Response handoff outbox service installed."
echo "Unit: $UNIT"
echo "Outbox: $OUTBOX"
echo "Status: systemctl --user status quietward-response-handoff.service"
