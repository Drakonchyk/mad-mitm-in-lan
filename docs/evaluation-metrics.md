# Evaluation Metrics

This page defines the metrics used in the generated reports.

## Detection Metrics

- `detected`
  - whether a run produced at least one relevant alert for the scenario
- `time_to_first_alert`
  - delay between the alert and the timing basis used for comparison
- `true_positive_rate`
  - fraction of positive runs correctly detected
- `false_positive_rate`
  - fraction of negative runs that still produced alerts
- `precision`
  - fraction of positive predictions that were correct
- `f1`
  - harmonic mean of precision and recall

## Timing Basis

The report uses two timing notions:

- raw attack-start timing
  - used only for chronology and debugging
  - starts from the earliest observed ground-truth attack evidence
- comparison-basis timing
  - used for report figures and tool comparisons
  - starts from the first ground-truth attack evidence that the sensor actually supports

That means detector, Zeek, and Suricata are compared on a consistent basis even when their supported attack evidence differs.

When packet capture is enabled, the observed-wire timing basis should prefer the raw switch-mirror capture on `pcap/sensor.pcap`. The detector's own JSON event stream is not treated as ground truth.

## Wire Truth Versus Alert Counts

Two count families appear in the generated outputs and they should not be read as the same thing:

- `wire-truth attack events`
  - normalized attack evidence extracted from the mirrored switch capture
  - this is the preferred ground-truth basis for packet-level scenarios
- sensor alert counts
  - detector packet alerts, Zeek notices, and Suricata alerts
  - these are raw sensor-side alert volumes and may exceed wire-truth counts because repeated spoof packets can trigger repeated alerts

Example:

- a 30-second ARP MITM run may show 8 wire-truth ARP events but 16 detector packet alerts
- that does not mean the evaluator is wrong; it means the switch-truth parser is counting normalized observed attack events while the sensor is counting repeated alerting packets

## Detector Semantic Alerts

The thesis-level detector alert count uses semantic detector state transitions rather than raw packet-observation events.

Included semantic detector alerts:

- `gateway_mac_changed`
- `multiple_gateway_macs_seen`
- `icmp_redirects_seen`
- `domain_resolution_changed`
- `rogue_dhcp_server_seen`
- `dhcp_binding_conflict_seen`
- `gateway_mac_restored`
- `single_gateway_mac_restored`
- `domain_resolution_restored`
- `rogue_dhcp_server_cleared`

Raw packet-level observations such as `arp_spoof_packet_seen` are still preserved in `detector.delta.jsonl`, but they are not the main alert count shown in summaries and thesis plots.

## Recovery Metrics

- `first_restored_ts`
  - first restoration-related detector event after mitigation
- `time_to_recovery`
  - delay between `mitigation_started_at` and the first restoration event

## Operational Metrics

- `ping_gateway_avg_ms`
  - mean gateway latency from the victim probe loop
- `ping_attacker_avg_ms`
  - mean latency to the attacker host from the victim probe loop
- `curl_total_s`
  - mean `curl time_total` from the victim probe loop
- `iperf_mbps`
  - throughput from the per-run `iperf3.json` sample

## Files Used To Compute Metrics

- run metadata:
  - `run-meta.json`
- detector events:
  - `detector/detector.delta.jsonl`
- victim probe loop:
  - `victim/traffic-window.txt`
- throughput sample:
  - `victim/iperf3.json`
- Zeek comparator:
  - `zeek/host/notice.log`
- Suricata comparator:
  - `suricata/host/eve.json`
- optional wire truth support:
  - `pcap/sensor.pcap`
  - `pcap/victim.pcap` as a fallback/debug capture

## Current Comparator Limitation

- On the current host Suricata build/config, the ARP comparison rule path may be unavailable.
- In that case Suricata should be interpreted as a DHCP+DNS+ICMP comparator only, and the run summary will state that explicitly.
