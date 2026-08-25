#!/usr/bin/env bash
set -euo pipefail
if [[ ${EUID} -ne 0 ]]; then echo "run as root" >&2; exit 2; fi
if [[ $# -ne 1 ]]; then echo "Usage: $0 SERVICE_GROUP" >&2; exit 2; fi
group="$1"; getent group "$group" >/dev/null
repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
install_root=/usr/local/lib/quietward-telemetry
install -d -o root -g root -m 0755 "$install_root"
install -d -o root -g root -m 0755 /usr/local/libexec
install -o root -g root -m 0644 "$repo_root/src/quietward/telemetry_helper.py" "$install_root/telemetry_helper.py"
cat >/usr/local/libexec/quietward-telemetry-helper <<'EOF'
#!/usr/bin/env bash
exec /usr/bin/python3 /usr/local/lib/quietward-telemetry/telemetry_helper.py "$@"
EOF
chmod 0755 /usr/local/libexec/quietward-telemetry-helper
sed "s/%G/$group/g" "$repo_root/deploy/quietward-telemetry.service" >/etc/systemd/system/quietward-telemetry.service
chmod 0644 /etc/systemd/system/quietward-telemetry.service
systemctl daemon-reload
systemctl enable --now quietward-telemetry.service
