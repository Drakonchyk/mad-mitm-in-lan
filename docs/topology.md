# Topology

This page documents the lab architecture used by the automated experiments.

## Architecture Diagram

![MITM lab topology](images/topology.png)

## What Lives Where

- Host machine:
  - provisions and starts the VMs
  - owns the Open vSwitch fabric and mirror port
  - runs the main detector on `mitm-sensor0`
  - runs Zeek and Suricata comparators on `mitm-sensor0` when enabled
  - captures `pcap/sensor.pcap` as the aggregate mirrored switch truth when `PCAP=1`
  - captures `pcap/ports/{gateway,victim,attacker}.pcap` from the individual OVS/libvirt port interfaces when `PORT_PCAP=1`
  - orchestrates scenario runs
  - collects artifacts into `results/`
  - builds the combined report
- `mitm-gateway`:
  - provides the lab gateway, DNS service, and DHCP pool
  - is treated as the trusted DHCP server on the switch-facing LAN
  - remains the only DHCP-server-trusted ingress port for OVS DHCP snooping monitor/enforce flows
  - can produce gateway-side pcap when guest captures are enabled
- Detector:
  - inspects mirrored ARP, DNS, ICMP, and DHCP packets directly
  - is compared to Zeek and Suricata on the same packet-only observation surface
- Trusted switch observation:
  - records OVS DHCP/ARP/DNS trust evidence from ingress-port-aware monitor flows
  - stays separate from Detector/Zeek/Suricata packet-alert counts
- `mitm-victim`:
  - receives its lab address over DHCP from the gateway
- `mitm-attacker`:
  - runs the automated attack-side scenario commands
  - discovers the victim host from the lab LAN during the normal automated attack path
  - receives its lab address over DHCP from the gateway
  - can produce attacker-side pcap when guest captures are enabled

## Artifact Placement

- detector logs and detector explanation:
  - `results/<run>/detector/`
- Zeek comparator artifacts:
  - `results/<run>/zeek/host/`
- Suricata comparator artifacts:
  - `results/<run>/suricata/host/`
- optional pcap artifacts:
  - `results/<run>/pcap/`
- generated reports:
  - `results/experiment-report/`
