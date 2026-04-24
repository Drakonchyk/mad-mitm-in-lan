#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/../.." && pwd)"

# shellcheck source=/dev/null
source "${REPO_ROOT}/shell/common.sh"

INTERFACE="${1:-${IFACE:-${LAB_SWITCH_SENSOR_PORT}}}"
LOG_DIR="${REPO_ROOT}/generated/demo-ui/logs"
LOG_PATH="${LOG_DIR}/wireshark-launch.log"
DISPLAY_VALUE="${DEMO_DISPLAY:-${DISPLAY:-}}"
XAUTHORITY_VALUE="${DEMO_XAUTHORITY:-${XAUTHORITY:-}}"
XDG_RUNTIME_DIR_VALUE="${DEMO_XDG_RUNTIME_DIR:-${XDG_RUNTIME_DIR:-}}"
DBUS_VALUE="${DEMO_DBUS_SESSION_BUS_ADDRESS:-${DBUS_SESSION_BUS_ADDRESS:-}}"
REAL_USER="${DEMO_REAL_USER:-${SUDO_USER:-${USER}}}"
REAL_HOME="$(getent passwd "${REAL_USER}" | cut -d: -f6)"

command -v wireshark >/dev/null 2>&1 || {
  warn "wireshark is not installed on the host"
  exit 1
}

if [[ $(id -u) -ne 0 ]] && ! id -nG "${USER}" | tr ' ' '\n' | grep -qx wireshark; then
  warn "Current user cannot execute dumpcap. Run the dashboard via make demo-ui or add ${USER} to the wireshark group."
  exit 1
fi

mkdir -p "${LOG_DIR}"

if [[ -z "${DISPLAY_VALUE}" ]]; then
  warn "DISPLAY is not set for the desktop session; cannot open Wireshark GUI"
  exit 1
fi

WIRESHARK_CMD=(
  env -i
  HOME="${REAL_HOME:-/home/${REAL_USER}}"
  USER="${REAL_USER}"
  LOGNAME="${REAL_USER}"
  PATH="/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"
  DISPLAY="${DISPLAY_VALUE}"
  XAUTHORITY="${XAUTHORITY_VALUE}"
  XDG_RUNTIME_DIR="${XDG_RUNTIME_DIR_VALUE}"
)

if [[ -n "${DBUS_VALUE}" ]]; then
  WIRESHARK_CMD+=("DBUS_SESSION_BUS_ADDRESS=${DBUS_VALUE}")
fi

WIRESHARK_CMD+=(/usr/bin/wireshark -k -i "${INTERFACE}")

: >"${LOG_PATH}"

if [[ $(id -u) -eq 0 ]]; then
  nohup sudo -u "${REAL_USER}" "${WIRESHARK_CMD[@]}" >"${LOG_PATH}" 2>&1 </dev/null &
else
  nohup "${WIRESHARK_CMD[@]}" >"${LOG_PATH}" 2>&1 </dev/null &
fi

sleep 1
if pgrep -u "${REAL_USER}" -f "wireshark.*${INTERFACE}" >/dev/null 2>&1 || pgrep -f "wireshark.*${INTERFACE}" >/dev/null 2>&1; then
  info "Opened Wireshark on ${INTERFACE}"
else
  warn "Wireshark did not stay up; check ${LOG_PATH}"
  exit 1
fi
