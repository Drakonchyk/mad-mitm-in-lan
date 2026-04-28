# Evaluation Metrics

This page defines the metrics used in the generated reports.

## Detection And Reliability Metrics

- `detected`
  - whether a run produced at least one relevant alert for the scenario
- `time_to_first_alert`
  - delay between the alert and the timing basis used for comparison
- `event_recall`
  - fraction of trusted attack events matched by a tool for comparable packet-visible evidence
- `detection_survival`
  - whether a tool still produces at least one relevant alert at a given NetEm loss level

The lab baseline is a clean-sensor reference, not a representative production-traffic corpus. Generic classifier summaries that require broad benign traffic are better suited to future work with diverse real application traffic.

## Timing Basis

The report uses two timing notions:

- raw attack-start timing
  - used only for chronology and debugging
  - starts from the earliest observed ground-truth attack evidence
- comparison-basis timing
  - used for report figures and tool comparisons
  - starts from the first ground-truth attack evidence that the sensor actually supports

That means detector, Zeek, and Suricata are compared on a consistent basis even when their supported attack evidence differs.

Trusted-source observations are materialized into `ground-truth/trusted-observations.sqlite`. The database is built from OVS snooping artifacts and records the trusted gateway/DNS/DHCP authorities, ARP/DNS/DHCP trust violations, and detector/Zeek/Suricata comparisons.
When packet capture is enabled, `pcap/sensor.pcap` remains useful for manual validation and screenshot work. The detector's own JSON event stream is not treated as ground truth.
ARP truth is counted as gateway-IP ARP replies from non-gateway ports. DNS truth is counted as DNS replies claiming the trusted DNS/gateway source from non-gateway ports. DHCP truth is counted as DHCP server replies from non-gateway ports, even if the packet spoofs the gateway MAC/IP.
Per-port captures in `pcap/ports/` remain optional port-scoped evidence for focused debugging.

Detector heartbeat events report packet-analysis throughput:

- `interval_seen_pps`
- `interval_processed_pps`
- `packets_seen`
- `packets_processed`
- `avg_processing_ms`
- `max_processing_ms`

## Trusted Truth Versus Alert Counts

Two count families appear in the generated outputs and they should not be read as the same thing:

- trusted attack events
  - normalized attack evidence derived from OVS trusted-source observations, scenario metadata, and optional packet validation
  - this is the preferred ground-truth basis for packet-level scenarios
- sensor alert counts
  - detector packet alerts, Zeek notices, and Suricata alerts
  - these are raw sensor-side alert volumes and may exceed wire-truth counts because repeated spoof packets can trigger repeated alerts

Example:

- a 30-second ARP MITM run may show 8 wire-truth ARP packets but 16 detector packet alerts
- that does not automatically mean the evaluator is wrong; it usually means repeated spoof packets triggered repeated sensor alerts

## Detector Packet Alerts

The current summaries and report rows use detector packet-observation alerts as the primary detector count.

Common packet-level detector alerts include:

- `arp_spoof_packet_seen`
- `dns_spoof_packet_seen`
- `rogue_dhcp_server_seen`
- `dhcp_binding_conflict_seen`

Detector state transitions and narrative markers are still preserved in `detector.delta.jsonl`, but the main comparison path now focuses on packet-level detector evidence to stay closer to switch truth and comparator packet streams.

## Operational Metrics

- `ping_gateway_avg_ms`
  - mean gateway latency from the victim probe loop
- `ping_attacker_avg_ms`
  - mean latency to the attacker host from the victim probe loop
- `traffic_probe_icmp_packets`
  - ICMP packets sent by the default synthetic traffic probe
- `traffic_probe_dns_queries`
  - DNS queries sent by the default synthetic traffic probe
- `curl_total_s`
  - optional mean `curl time_total` from the legacy or baseline diagnostic probe
- `iperf_mbps`
  - optional throughput from the per-run `iperf3.json` sample

## Files Used To Compute Metrics

- run metadata:
  - `run-meta.json`
- detector events:
  - `detector/detector.delta.jsonl`
- victim probe loop:
  - `victim/traffic-window.txt`
- optional throughput sample:
  - `victim/iperf3.json`
- Zeek comparator:
  - `zeek/host/notice.log`
- Suricata comparator:
  - `suricata/host/eve.json`
- optional wire truth support:
  - `ground-truth/trusted-observations.sqlite` as the trusted-source ARP/DNS/DHCP database
  - `pcap/sensor.pcap`
  - `pcap/ports/*.pcap`
  - `pcap/victim.pcap` as a fallback/debug capture
  - `pcap/wire-truth.json` as the compact retained switch-truth artifact when full pcaps are pruned
  - `detector/ovs-switch-truth-snooping.txt` as compact ARP/DNS switch-truth when pcaps are disabled
  - `detector/ovs-dhcp-snooping.txt` as compact DHCP trusted-port truth

## Current Comparator Limitation

- On the current host Suricata build/config, the ARP comparison rule path may be unavailable.
- In that case Suricata should be interpreted as a DHCP+DNS+ICMP comparator only, and the run summary will state that explicitly.
