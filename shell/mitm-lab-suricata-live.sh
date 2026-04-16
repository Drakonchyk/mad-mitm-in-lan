#!/usr/bin/env bash
set -euo pipefail

LOG_DIR="/var/log/mitm-lab-suricata/current"
RULES_PATH="/etc/mitm-lab/mitm-lab-suricata.rules"
CONFIG_PATH="/etc/suricata/suricata.yaml"

mkdir -p "${LOG_DIR}"
cd "${LOG_DIR}"

exec suricata -i vnic0 -l "${LOG_DIR}" -c "${CONFIG_PATH}" -S "${RULES_PATH}"
