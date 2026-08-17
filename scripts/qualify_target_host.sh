#!/usr/bin/env bash
set -euo pipefail
config="${1:-${HOME}/.config/quietward/config.json}"
quietward doctor --config "${config}" --pretty
quietward qualify --config "${config}" --cycles 10 --interval-seconds 5 --pretty
quietward run --config "${config}" --cycles 10 --no-dashboard
quietward status --config "${config}" --pretty
