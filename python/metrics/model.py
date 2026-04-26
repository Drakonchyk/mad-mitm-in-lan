from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Any

REPO_ROOT = Path(__file__).resolve().parent.parent.parent
EVALUATION_CACHE_VERSION = 14
EVALUATION_DEPENDENCY_PATHS = [
    Path(__file__).resolve(),
    Path(__file__).resolve().with_name("core.py"),
    Path(__file__).resolve().with_name("parsers.py"),
]

ATTACK_TYPE_ORDER = [
    "arp_spoof",
    "icmp_redirect",
    "dns_spoof",
    "dhcp_spoof",
    "dhcp_starvation",
]

ATTACK_TYPE_LABELS = {
    "arp_spoof": "ARP spoof",
    "icmp_redirect": "ICMP redirect",
    "dns_spoof": "DNS spoof",
    "dhcp_spoof": "DHCP spoof",
    "dhcp_starvation": "DHCP starvation",
}

GROUND_TRUTH_ATTACK_EVENTS = {
    "arp_poison_cycle": "arp_spoof",
    "arp_spoof_observed": "arp_spoof",
    "icmp_redirect_observed": "icmp_redirect",
    "dns_spoof": "dns_spoof",
    "dns_spoof_observed": "dns_spoof",
    "rogue_dhcp_offer": "dhcp_spoof",
    "rogue_dhcp_ack": "dhcp_spoof",
    "rogue_dhcp_server_observed": "dhcp_spoof",
    "dhcp_starvation_discover": "dhcp_starvation",
    "dhcp_starvation_request": "dhcp_starvation",
    "dhcp_starvation_observed": "dhcp_starvation",
}

DETECTOR_ALERT_EVENTS = {
    "arp_spoof_packet_seen": "arp_spoof",
    "icmp_redirect_packet_seen": "icmp_redirect",
    "dns_spoof_packet_seen": "dns_spoof",
    "rogue_dhcp_server_seen": "dhcp_spoof",
    "dhcp_binding_conflict_seen": "dhcp_spoof",
    "dhcp_starvation_packet_seen": "dhcp_starvation",
}

ZEEK_ALERT_TYPES = {
    "MITMLab::ARP_Spoof": "arp_spoof",
    "MITMLab::ICMP_Redirect": "icmp_redirect",
    "MITMLab::DNS_Spoof": "dns_spoof",
    "MITMLab::DHCP_Spoof": "dhcp_spoof",
    "MITMLab::DHCP_Starvation": "dhcp_starvation",
}

SURICATA_ALERT_TYPES = {
    "MITM-LAB live ARP reply from attacker claims gateway IP to victim": "arp_spoof",
    "MITM-LAB Suricata EVE ARP reply from attacker claims gateway IP to victim": "arp_spoof",
    "MITM-LAB live ICMP redirect from attacker to victim": "icmp_redirect",
    "MITM-LAB live DNS answer contains attacker IP": "dns_spoof",
    "MITM-LAB live rogue DHCP reply from attacker": "dhcp_spoof",
    "MITM-LAB live DHCP starvation discover from spoofed client prefix": "dhcp_starvation",
    "MITM-LAB live DHCP starvation request from spoofed client prefix": "dhcp_starvation",
}

SENSOR_COVERAGE = {
    "detector": {
        "arp_spoof": True,
        "icmp_redirect": True,
        "dns_spoof": True,
        "dhcp_spoof": True,
        "dhcp_starvation": True,
    },
    "zeek": {
        "arp_spoof": True,
        "icmp_redirect": True,
        "dns_spoof": True,
        "dhcp_spoof": True,
        "dhcp_starvation": True,
    },
    "suricata": {
        "arp_spoof": False,
        "icmp_redirect": True,
        "dns_spoof": True,
        "dhcp_spoof": True,
        "dhcp_starvation": True,
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
    ground_truth_attack_ended_at: str | None
    ground_truth_capture_duration_seconds: float | None
    ground_truth_attack_duration_seconds: float | None
    ground_truth_attack_types: dict[str, int]
    ground_truth_attack_type_first_seen_at: dict[str, str]
    ground_truth_attack_type_durations_seconds: dict[str, float | None]
    ground_truth_attack_type_packet_rates_pps: dict[str, float | None]
    ground_truth_attacker_action_types: dict[str, int]
    ground_truth_observed_wire_types: dict[str, int]
    ground_truth_control_types: dict[str, int]
    ground_truth_dns_query_count: int
    ground_truth_dns_spoof_success_ratio: float | None
    ground_truth_arp_spoof_direction_counts: dict[str, int]
    ground_truth_control_plane_packet_counts: dict[str, int]
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
            "ground_truth_total_events": self.ground_truth_total_events,
            "ground_truth_attack_events": self.ground_truth_attack_events,
            "ground_truth_attacker_action_events": self.ground_truth_attacker_action_events,
            "ground_truth_control_events": self.ground_truth_control_events,
            "ground_truth_attack_started_at": self.ground_truth_attack_started_at,
            "ground_truth_attack_ended_at": self.ground_truth_attack_ended_at,
            "ground_truth_capture_duration_seconds": self.ground_truth_capture_duration_seconds,
            "ground_truth_attack_duration_seconds": self.ground_truth_attack_duration_seconds,
            "ground_truth_attack_types": self.ground_truth_attack_types,
            "ground_truth_attack_type_first_seen_at": self.ground_truth_attack_type_first_seen_at,
            "ground_truth_attack_type_durations_seconds": self.ground_truth_attack_type_durations_seconds,
            "ground_truth_attack_type_packet_rates_pps": self.ground_truth_attack_type_packet_rates_pps,
            "ground_truth_attacker_action_types": self.ground_truth_attacker_action_types,
            "ground_truth_control_types": self.ground_truth_control_types,
            "ground_truth_dns_query_count": self.ground_truth_dns_query_count,
            "ground_truth_dns_spoof_success_ratio": self.ground_truth_dns_spoof_success_ratio,
            "ground_truth_arp_spoof_direction_counts": self.ground_truth_arp_spoof_direction_counts,
            "ground_truth_control_plane_packet_counts": self.ground_truth_control_plane_packet_counts,
            "detector_alert_events": self.detector_alert_events,
            "detector_alert_types": self.detector_alert_types,
            "detector_unique_alert_type_count": self.detector_unique_alert_type_count,
            "detector_attack_type_counts": self.detector_attack_type_counts,
            "detector_attack_type_first_alert_at": self.detector_attack_type_first_alert_at,
            "detector_first_alert_at": self.detector_first_alert_at,
            "detector_ttd_seconds": self.detector_ttd_seconds,
            "zeek_alert_events": self.zeek_alert_events,
            "zeek_alert_types": self.zeek_alert_types,
            "zeek_unique_alert_type_count": self.zeek_unique_alert_type_count,
            "zeek_attack_type_counts": self.zeek_attack_type_counts,
            "zeek_attack_type_first_alert_at": self.zeek_attack_type_first_alert_at,
            "zeek_first_alert_at": self.zeek_first_alert_at,
            "zeek_ttd_seconds": self.zeek_ttd_seconds,
            "suricata_alert_events": self.suricata_alert_events,
            "suricata_alert_types": self.suricata_alert_types,
            "suricata_unique_alert_type_count": self.suricata_unique_alert_type_count,
            "suricata_attack_type_counts": self.suricata_attack_type_counts,
            "suricata_attack_type_first_alert_at": self.suricata_attack_type_first_alert_at,
            "suricata_first_alert_at": self.suricata_first_alert_at,
            "suricata_ttd_seconds": self.suricata_ttd_seconds,
            "combined_sensor_detected": (self.zeek_alert_events > 0 or self.suricata_alert_events > 0),
        }
