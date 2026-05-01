#!/usr/bin/env bash
set -euo pipefail

LAB_SUBNET="__LAB_SUBNET__"
UP_IF="gw-up"
LAB_IF="gw-lab"

sysctl -w net.ipv4.ip_forward=1 >/dev/null

iptables -t nat -C POSTROUTING -s "${LAB_SUBNET}" -o "${UP_IF}" -j MASQUERADE 2>/dev/null || \
  iptables -t nat -A POSTROUTING -s "${LAB_SUBNET}" -o "${UP_IF}" -j MASQUERADE

iptables -C FORWARD -i "${UP_IF}" -o "${LAB_IF}" -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT 2>/dev/null || \
  iptables -A FORWARD -i "${UP_IF}" -o "${LAB_IF}" -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT

iptables -C FORWARD -i "${LAB_IF}" -o "${UP_IF}" -j ACCEPT 2>/dev/null || \
  iptables -A FORWARD -i "${LAB_IF}" -o "${UP_IF}" -j ACCEPT

systemctl restart dnsmasq
