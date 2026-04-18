# Topology

This page documents the lab architecture used by the automated experiments.

## Architecture Diagram

```mermaid
flowchart LR
    subgraph Host["Host machine"]
        Orchestration["shell/ + python/\norchestration and report scripts"]
        Results["results/\nrun artifacts and reports"]
        SampleReports["make experiment-report\nmake experiment-report-extra\nmake demo-report"]
    end

    subgraph DefaultNet["libvirt default NAT network"]
        DefaultBridge["default"]
    end

    subgraph LabNet["isolated lab network\nmitm-lab on virbr11"]
        Bridge["virbr11"]

        subgraph Gateway["mitm-gateway\n10.20.20.1"]
            GwDNS["dnsmasq + forwarding"]
            GwCapture["gateway pcap\noptional"]
        end

        subgraph Victim["mitm-victim\n10.20.20.10"]
            Detector["Detector\n/usr/local/bin/mitm_lab_detector.py"]
            Zeek["Zeek comparator\noptional"]
            Suricata["Suricata comparator\noptional"]
            VictimCapture["victim pcap\noptional"]
        end

        subgraph Attacker["mitm-attacker\n10.20.20.66"]
            AttackScripts["python -m mitm.cli\nscenario actions"]
            AttackerCapture["attacker pcap\noptional"]
        end
    end

    Orchestration --> Gateway
    Orchestration --> Victim
    Orchestration --> Attacker
    Gateway --> DefaultBridge
    Gateway --> Bridge
    Victim --> Bridge
    Attacker --> Bridge

    Detector --> Results
    Zeek --> Results
    Suricata --> Results
    GwCapture --> Results
    VictimCapture --> Results
    AttackerCapture --> Results
    AttackScripts --> Results
    SampleReports --> Results
```

## What Lives Where

- Host machine:
  - provisions and starts the VMs
  - orchestrates scenario runs
  - collects artifacts into `results/`
  - builds the main and supplementary reports
- `mitm-gateway`:
  - provides the lab gateway and DNS service
  - can produce gateway-side pcap when `PCAP_ENABLE=1`
- `mitm-victim`:
  - runs the main detector
  - optionally runs Zeek and Suricata
  - is the main observation point for detector logs and comparator logs
- `mitm-attacker`:
  - runs the automated attack-side scenario commands
  - can produce attacker-side pcap when `PCAP_ENABLE=1`

## Artifact Placement

- detector logs and detector explanation:
  - `results/<run>/victim/`
- Zeek comparator artifacts:
  - `results/<run>/zeek/`
- Suricata comparator artifacts:
  - `results/<run>/suricata/`
- optional pcap artifacts:
  - `results/<run>/pcap/`
- generated reports:
  - `results/experiment-report/`
  - `results/experiment-report-extra/`
  - `results/demo-report/`
