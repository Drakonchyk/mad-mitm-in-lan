from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Any

REPO_ROOT = Path(__file__).resolve().parent.parent.parent
EVALUATION_CACHE_VERSION = 5
EVALUATION_DEPENDENCY_PATHS = [
    Path(__file__).resolve(),
    Path(__file__).resolve().with_name("core.py"),
    Path(__file__).resolve().with_name("parsers.py"),
    Path(__file__).resolve().with_name("aggregate.py"),
    Path(__file__).resolve().with_name("evaluator.py"),
    Path(__file__).resolve().with_name("primitives.py"),
]

ATTACK_TYPE_ORDER = [
    "arp_spoof",
    "icmp_redirect",
    "dns_spoof",
]

ATTACK_TYPE_LABELS = {
    "arp_spoof": "ARP spoof",
    "icmp_redirect": "ICMP redirect",
    "dns_spoof": "DNS spoof",
}

GROUND_TRUTH_ATTACK_EVENTS = {
    "arp_poison_cycle": "arp_spoof",
    "icmp_redirect_observed": "icmp_redirect",
    "dns_spoof": "dns_spoof",
}

DETECTOR_ALERT_EVENTS = {
    "arp_spoof_packet_seen": "arp_spoof",
    "icmp_redirect_packet_seen": "icmp_redirect",
    "dns_spoof_packet_seen": "dns_spoof",
}

ZEEK_ALERT_TYPES = {
    "MITMLab::ARP_Spoof": "arp_spoof",
    "MITMLab::ICMP_Redirect": "icmp_redirect",
    "MITMLab::DNS_Spoof": "dns_spoof",
}

SURICATA_ALERT_TYPES = {
    "MITM-LAB live ARP reply from attacker claims gateway IP to victim": "arp_spoof",
    "MITM-LAB live ICMP redirect from attacker to victim": "icmp_redirect",
    "MITM-LAB live DNS answer contains attacker IP": "dns_spoof",
}

SENSOR_COVERAGE = {
    "detector": {
        "arp_spoof": True,
        "icmp_redirect": True,
        "dns_spoof": True,
    },
    "zeek": {
        "arp_spoof": True,
        "icmp_redirect": True,
        "dns_spoof": True,
    },
    "suricata": {
        "arp_spoof": False,
        "icmp_redirect": True,
        "dns_spoof": True,
    },
}


@dataclass(frozen=True)
class SensorResult:
    alert_events: int
    alert_types: dict[str, int]
    unique_alert_type_count: int
    canonical_alert_types: dict[str, int]
    canonical_first_alert_at: dict[str, str]
    first_alert_at: str | None
    ttd_seconds: float | None
    supported_attack_started_at: str | None
    supported_ttd_seconds: float | None
    coverage: dict[str, bool]


@dataclass(frozen=True)
class RunEvaluation:
    run_id: str
    scenario: str
    attack_present: bool
    ground_truth_source: str
    ground_truth_total_events: int
    ground_truth_attack_events: int
    ground_truth_attacker_action_events: int
    ground_truth_observed_wire_events: int
    ground_truth_control_events: int
    ground_truth_attack_started_at: str | None
    ground_truth_attack_types: dict[str, int]
    ground_truth_attack_type_first_seen_at: dict[str, str]
    ground_truth_attacker_action_types: dict[str, int]
    ground_truth_observed_wire_types: dict[str, int]
    ground_truth_control_types: dict[str, int]
    detector_alert_events: int
    detector_alert_types: dict[str, int]
    detector_unique_alert_type_count: int
    detector_attack_type_counts: dict[str, int]
    detector_attack_type_first_alert_at: dict[str, str]
    detector_first_alert_at: str | None
    detector_ttd_seconds: float | None
    detector_supported_attack_started_at: str | None
    detector_supported_ttd_seconds: float | None
    detector_coverage: dict[str, bool]
    zeek_alert_events: int
    zeek_alert_types: dict[str, int]
    zeek_unique_alert_type_count: int
    zeek_attack_type_counts: dict[str, int]
    zeek_attack_type_first_alert_at: dict[str, str]
    zeek_first_alert_at: str | None
    zeek_ttd_seconds: float | None
    zeek_supported_attack_started_at: str | None
    zeek_supported_ttd_seconds: float | None
    zeek_coverage: dict[str, bool]
    suricata_alert_events: int
    suricata_alert_types: dict[str, int]
    suricata_unique_alert_type_count: int
    suricata_attack_type_counts: dict[str, int]
    suricata_attack_type_first_alert_at: dict[str, str]
    suricata_first_alert_at: str | None
    suricata_ttd_seconds: float | None
    suricata_supported_attack_started_at: str | None
    suricata_supported_ttd_seconds: float | None
    suricata_coverage: dict[str, bool]

    def as_dict(self) -> dict[str, Any]:
        return {
            "run_id": self.run_id,
            "scenario": self.scenario,
            "attack_present": self.attack_present,
            "ground_truth_source": self.ground_truth_source,
            "ground_truth_total_events": self.ground_truth_total_events,
            "ground_truth_attack_events": self.ground_truth_attack_events,
            "ground_truth_attacker_action_events": self.ground_truth_attacker_action_events,
            "ground_truth_observed_wire_events": self.ground_truth_observed_wire_events,
            "ground_truth_control_events": self.ground_truth_control_events,
            "ground_truth_attack_started_at": self.ground_truth_attack_started_at,
            "ground_truth_attack_types": self.ground_truth_attack_types,
            "ground_truth_attack_type_first_seen_at": self.ground_truth_attack_type_first_seen_at,
            "ground_truth_attacker_action_types": self.ground_truth_attacker_action_types,
            "ground_truth_observed_wire_types": self.ground_truth_observed_wire_types,
            "ground_truth_control_types": self.ground_truth_control_types,
            "detector_alert_events": self.detector_alert_events,
            "detector_alert_types": self.detector_alert_types,
            "detector_unique_alert_type_count": self.detector_unique_alert_type_count,
            "detector_attack_type_counts": self.detector_attack_type_counts,
            "detector_attack_type_first_alert_at": self.detector_attack_type_first_alert_at,
            "detector_first_alert_at": self.detector_first_alert_at,
            "detector_ttd_seconds": self.detector_ttd_seconds,
            "detector_supported_attack_started_at": self.detector_supported_attack_started_at,
            "detector_supported_ttd_seconds": self.detector_supported_ttd_seconds,
            "detector_coverage": self.detector_coverage,
            "zeek_alert_events": self.zeek_alert_events,
            "zeek_alert_types": self.zeek_alert_types,
            "zeek_unique_alert_type_count": self.zeek_unique_alert_type_count,
            "zeek_attack_type_counts": self.zeek_attack_type_counts,
            "zeek_attack_type_first_alert_at": self.zeek_attack_type_first_alert_at,
            "zeek_first_alert_at": self.zeek_first_alert_at,
            "zeek_ttd_seconds": self.zeek_ttd_seconds,
            "zeek_supported_attack_started_at": self.zeek_supported_attack_started_at,
            "zeek_supported_ttd_seconds": self.zeek_supported_ttd_seconds,
            "zeek_coverage": self.zeek_coverage,
            "suricata_alert_events": self.suricata_alert_events,
            "suricata_alert_types": self.suricata_alert_types,
            "suricata_unique_alert_type_count": self.suricata_unique_alert_type_count,
            "suricata_attack_type_counts": self.suricata_attack_type_counts,
            "suricata_attack_type_first_alert_at": self.suricata_attack_type_first_alert_at,
            "suricata_first_alert_at": self.suricata_first_alert_at,
            "suricata_ttd_seconds": self.suricata_ttd_seconds,
            "suricata_supported_attack_started_at": self.suricata_supported_attack_started_at,
            "suricata_supported_ttd_seconds": self.suricata_supported_ttd_seconds,
            "suricata_coverage": self.suricata_coverage,
            "combined_sensor_detected": (self.zeek_alert_events > 0 or self.suricata_alert_events > 0),
        }
