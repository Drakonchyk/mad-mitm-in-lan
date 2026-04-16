# Experiment plan for the diploma

## 0. One fix before you count any final runs
Normalize DNS answers in the detector before comparing them to the baseline.

Right now the detector compares ordered lists, so the same A-record set in a different order becomes a false alert.  
For final runs, compare either:

- `sorted(set(answers))`
- or just `set(answers)` if you do not care about preserving order

Do this both when storing the baseline and when checking the current answers.

---

## 1. Final scenario set

Use **5 scenario variants**:

1. **baseline**
   - No attack
   - Purpose: false positives and normal variance

2. **arp-poison-no-forward**
   - ARP poisoning without IP forwarding
   - Purpose: disruption-only case, distinguish breakage from real transparent MITM

3. **arp-mitm-forward**
   - ARP poisoning with forwarding enabled
   - Purpose: real MITM positioning

4. **arp-mitm-dns**
   - ARP MITM with forwarding + DNS spoofing
   - Purpose: correlated ARP + DNS evidence

5. **mitigation-recovery**
   - Start with ARP MITM + DNS spoofing, then apply mitigation mid-run
   - Purpose: measure restoration and recovery time

---

## 2. How many runs

Use this exact count:

- **1 warm-up run per scenario** → do not include in plots or metrics
- **10 measured runs per scenario**

So the final dataset is:

- 5 warm-up runs
- 50 measured runs

That is enough for a diploma and still realistic to execute.

---

## 3. Run durations

Use fixed durations:

- `baseline` → **90 s**
- `arp-poison-no-forward` → **90 s**
- `arp-mitm-forward` → **90 s**
- `arp-mitm-dns` → **90 s**
- `mitigation-recovery` → **120 s**

### Attack timing inside each run

For the 90-second attack runs:

- `t = 0..10 s` → clean pre-attack traffic
- `t = 10..70 s` → attack active
- `t = 70..90 s` → recovery tail

For mitigation:

- `t = 0..10 s` → clean prefix
- `t = 10..45 s` → attack active
- `t = 45 s` → mitigation applied
- `t = 45..120 s` → recovery observation

Log these timestamps explicitly in metadata.

---

## 4. Which commands / variants to support

## Existing ones you already have

### Benign baseline
```bash
make baseline
```

### Full ARP MITM with forwarding
```bash
make danger-arp-mitm-auto DURATION=90
```

### ARP MITM + DNS spoofing
```bash
make danger-arp-dns-auto DURATION=90
```

---

## Add one more automated wrapper: ARP without forwarding

Create a new dangerous wrapper, for example:

```bash
#!/usr/bin/env bash
set -euo pipefail

source "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/common.sh"

DURATION="${1:-${DURATION:-90}}"
REMOTE_ROOT="$(research_workspace_root)"
ATTACK_CMD="cd '${REMOTE_ROOT}' && exec sudo python3 ./python/setup_all.py --config ./lab.conf arp-poison --interface vnic0"

start_danger_python_recording \
  "arp-poison-no-forward" \
  "${DURATION}" \
  "Automated ARP poisoning without forwarding in isolated lab" \
  "arp-poison-no-forward" \
  "${ATTACK_CMD}"
```

This is important. Without this scenario, you cannot cleanly show the difference between:
- poisoning that only breaks traffic
- poisoning that creates a working MITM path

---

## Add one more focused DNS variant

For the combined scenario, spoof **one stable monitored domain only**, ideally `iana.org`, not all three domains at once.

Use:
```bash
sudo python3 ./python/setup_all.py --config ./lab.conf mitm-dns \
  --interface vnic0 \
  --enable-forwarding \
  --domains iana.org
```

That makes plots and detector interpretation much cleaner.

If you want, create a dedicated wrapper for this exact case.

---

## 5. Mitigation scenario: exact action

Use this exact mitigation during the `mitigation-recovery` run:

1. Start with the same attack as `arp-mitm-dns`
2. At `t = 45 s`, apply on the victim:
```bash
sudo ip neigh replace 10.20.20.1 lladdr 52:54:00:aa:20:01 nud permanent dev vnic0
```
3. Then stop the attacker job
4. Keep capturing until the end of the run
5. After the run, remove the permanent entry if needed:
```bash
sudo ip neigh del 10.20.20.1 dev vnic0
```

Why this version:
- it gives you a clear restoration point
- it is deterministic
- it should trigger recovery-related detector events

If you prefer, automate this as a scheduled step in the wrapper instead of doing it manually.

---

## 6. What to save in metadata for every run

Add these fields to your run metadata JSON:

```json
{
  "scenario": "...",
  "run_index": 1,
  "warmup": false,
  "duration_seconds": 90,
  "attack_started_at": "UTC timestamp",
  "attack_stopped_at": "UTC timestamp",
  "mitigation_started_at": null,
  "forwarding_enabled": true,
  "dns_spoof_enabled": false,
  "spoofed_domains": ["iana.org"]
}
```

For baseline, keep attack fields null.

You need these fields for plotting time-to-detection and time-to-recovery correctly.

---

## 7. Metrics to compute from each run

For each run, extract these values:

## Detection
- `detected` → 1 if at least one relevant alert appears during the attack window, else 0
- `first_alert_ts`
- `time_to_first_alert = first_alert_ts - attack_started_at`

## Recovery
- `first_restored_ts`
- `time_to_recovery = first_restored_ts - mitigation_started_at`

## Alert counts
- total detector alerts
- count of:
  - `gateway_mac_changed`
  - `multiple_gateway_macs_seen`
  - `icmp_redirects_seen`
  - `domain_resolution_changed`
  - `gateway_mac_restored`
  - `domain_resolution_restored`

## Operational impact
- average ping to gateway
- average ping to attacker
- `curl time_total`
- `iperf3` throughput
- optional Suricata alert count

---

## 8. How to define a “detected” run

Use this exact rule:

### For `baseline`
A correct run is **no alert** from the relevant alert set.

### For `arp-poison-no-forward` and `arp-mitm-forward`
A run is detected if at least one of these appears during the attack window:
- `gateway_mac_changed`
- `multiple_gateway_macs_seen`
- `icmp_redirects_seen`

### For `arp-mitm-dns`
A run is detected if at least one of these appears during the attack window:
- any ARP alert above
- `domain_resolution_changed` for the spoofed domain

### For `mitigation-recovery`
Detection is the same as `arp-mitm-dns`, and recovery is successful if at least one of these appears after mitigation:
- `gateway_mac_restored`
- `domain_resolution_restored`

---

## 9. Final aggregate metrics

After all 50 measured runs, compute:

- True Positive Rate
- False Positive Rate
- Precision
- F1 score
- mean time to first alert
- std dev of time to first alert
- mean time to recovery
- std dev of time to recovery

Treat:
- `baseline` as negative class
- all attack scenarios as positive class

You can also compute the same metrics per scenario.

---

## 10. Exactly what to plot

Make these figures:

## Figure 1 — time to first alert by scenario
- type: **box plot**
- scenarios on x-axis
- time to first alert (seconds) on y-axis

Scenarios:
- arp-poison-no-forward
- arp-mitm-forward
- arp-mitm-dns
- mitigation-recovery

Do not include baseline here.

---

## Figure 2 — detector alerts per run by scenario
- type: **bar chart with error bars**
- x-axis: scenario
- y-axis: mean number of detector alerts per run
- error bars: standard deviation

Include all 5 scenarios.

---

## Figure 3 — alert composition by scenario
- type: **stacked bar chart**
- x-axis: scenario
- stacks:
  - gateway_mac_changed
  - multiple_gateway_macs_seen
  - icmp_redirects_seen
  - domain_resolution_changed
  - restoration events

This is one of the most useful plots because it shows qualitative differences between scenarios.

---

## Figure 4 — latency impact by scenario
- type: **box plot**
- x-axis: scenario
- y-axis: average gateway ping latency

Make a separate second plot for:
- `curl time_total`

Do not combine them into one messy plot.

---

## Figure 5 — throughput impact by scenario
- type: **box plot**
- x-axis: scenario
- y-axis: `iperf3` Mbps

Interpret only comparatively, not as absolute LAN capacity.

---

## Figure 6 — recovery time
- type: **box plot**
- only for `mitigation-recovery`
- y-axis: time to recovery

If you have only one mitigation method, one box is enough.  
If later you compare two mitigation methods, use one box per method.

---

## Figure 7 — one representative timeline
Pick one clean representative `arp-mitm-dns` run and plot a timeline:

- x-axis: seconds since run start
- vertical markers for:
  - attack start
  - first ARP alert
  - first DNS alert
  - attack stop / mitigation
- optionally add shaded attack window

This figure is great for the thesis text because it explains the sequence, not just the aggregate numbers.

---

## 11. Tables to include in the thesis

### Table A — scenario design
Columns:
- scenario
- duration
- forwarding enabled
- DNS spoof enabled
- mitigation enabled
- repetitions

### Table B — final metric summary
Columns:
- scenario
- TPR
- FPR
- Precision
- F1
- mean time to first alert
- mean alert count
- mean ping latency
- mean curl time
- mean iperf throughput

### Table C — recovery summary
Columns:
- scenario / mitigation method
- restoration success rate
- mean recovery time
- std dev recovery time

---

## 12. Clean execution order

Run them in this order:

1. fix DNS normalization
2. warm-up all 5 scenarios
3. 10× baseline
4. 10× arp-poison-no-forward
5. 10× arp-mitm-forward
6. 10× arp-mitm-dns
7. 10× mitigation-recovery

This order matters because:
- you first prove the negative class is clean
- then you move from simpler attack signal to stronger correlated signal
- mitigation comes last because it depends on the attack behavior already being stable

---

## 13. Minimal code changes I strongly recommend

1. **Normalize DNS answers before comparison**
2. **Save attack/mitigation timestamps into `run-meta.json`**
3. **Add the `arp-poison-no-forward` wrapper**
4. **Add a domain-specific combined wrapper for `iana.org`**
5. **Make the summarizer emit per-event counts in machine-readable form**

That is enough to support all the plots above.

---

## 14. The shortest possible final version if you get tired

If you absolutely need to cut scope, keep:

- baseline
- arp-mitm-forward
- arp-mitm-dns
- mitigation-recovery

But the better thesis version is the full 5-scenario matrix because the no-forwarding ARP case makes the analysis much stronger.
