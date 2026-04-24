#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/../.." && pwd)"

HOST="${HOST:-127.0.0.1}"
PORT="${PORT:-8765}"

cd "${REPO_ROOT}"
sudo -v

exec sudo -E env \
  PYTHONPATH="./python${PYTHONPATH:+:${PYTHONPATH}}" \
  DEMO_REAL_USER="${SUDO_USER:-$USER}" \
  DEMO_REAL_GROUP="$(id -gn "${SUDO_USER:-$USER}")" \
  DEMO_DISPLAY="${DISPLAY:-}" \
  DEMO_XAUTHORITY="${XAUTHORITY:-}" \
  DEMO_XDG_RUNTIME_DIR="${XDG_RUNTIME_DIR:-}" \
  DEMO_DBUS_SESSION_BUS_ADDRESS="${DBUS_SESSION_BUS_ADDRESS:-}" \
  DISPLAY="${DISPLAY:-}" \
  XAUTHORITY="${XAUTHORITY:-}" \
  XDG_RUNTIME_DIR="${XDG_RUNTIME_DIR:-}" \
  python3 -m demo_dashboard.server --host "${HOST}" --port "${PORT}"
