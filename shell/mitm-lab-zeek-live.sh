#!/usr/bin/env bash
set -euo pipefail

LOG_DIR="/var/log/mitm-lab-zeek/current"
POLICY="/etc/mitm-lab/mitm-lab-live.zeek"

if command -v zeek >/dev/null 2>&1; then
  ZEEK_BIN="$(command -v zeek)"
elif [[ -x /opt/zeek/bin/zeek ]]; then
  ZEEK_BIN="/opt/zeek/bin/zeek"
else
  echo "zeek binary not found" >&2
  exit 1
fi

mkdir -p "${LOG_DIR}"
cd "${LOG_DIR}"

exec "${ZEEK_BIN}" -C -i vnic0 "Log::default_logdir=${LOG_DIR}" "${POLICY}"
