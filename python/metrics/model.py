from __future__ import annotations

from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any

REPO_ROOT = Path(__file__).resolve().parent.parent.parent
EVALUATION_CACHE_VERSION = 23
EVALUATION_DEPENDENCY_PATHS = [
    Path(__file__).resolve(),
    Path(__file__).resolve().with_name("core.py"),
    Path(__file__).resolve().with_name("parsers.py"),
    Path(__file__).resolve().with_name("truth_db.py"),
]

ATTACK_TYPE_ORDER = [
    "arp_spoof",
    "icmp_redirect",
    "dns_spoof",
    "dns_source_violation",
    "dhcp_spoof",
    "dhcp_rogue_server",
    "dhcp_untrusted_switch_port",
]

ATTACK_TYPE_LABELS = {
    "arp_spoof": "ARP spoof",
    "icmp_redirect": "ICMP redirect",
    "dns_spoof": "DNS spoof",
    "dns_source_violation": "DNS reply from untrusted switch port",
    "dhcp_spoof": "DHCP spoof",
    "dhcp_rogue_server": "DHCP spoof server identity",
    "dhcp_untrusted_switch_port": "DHCP reply from untrusted switch port",
}

GROUND_TRUTH_ATTACK_EVENTS = {
    "arp_poison_cycle": "arp_spoof",
    "arp_spoof_observed": "arp_spoof",
    "icmp_redirect_observed": "icmp_redirect",
    "dns_spoof": "dns_spoof",
    "dns_spoof_observed": "dns_spoof",
    "dns_source_violation_observed": "dns_source_violation",
    "rogue_dhcp_offer": "dhcp_rogue_server",
    "rogue_dhcp_ack": "dhcp_rogue_server",
    "rogue_dhcp_server_observed": "dhcp_rogue_server",
    "untrusted_port_sent_dhcp_server_reply": "dhcp_untrusted_switch_port",
}

DETECTOR_ALERT_EVENTS = {
    "arp_spoof_packet_seen": "arp_spoof",
    "icmp_redirect_packet_seen": "icmp_redirect",
    "dns_spoof_packet_seen": "dns_spoof",
    "rogue_dhcp_server_seen": "dhcp_rogue_server",
}

ZEEK_ALERT_TYPES = {
    "MITMLab::ARP_Spoof": "arp_spoof",
    "MITMLab::ICMP_Redirect": "icmp_redirect",
    "MITMLab::DNS_Spoof": "dns_spoof",
    "MITMLab::DHCP_Spoof": "dhcp_rogue_server",
}

SURICATA_ALERT_TYPES = {
    "MITM-LAB live ARP reply from attacker claims gateway IP to victim": "arp_spoof",
    "MITM-LAB Suricata EVE ARP reply from attacker claims gateway IP to victim": "arp_spoof",
    "MITM-LAB live ICMP redirect from attacker to victim": "icmp_redirect",
    "MITM-LAB live DNS answer contains attacker IP": "dns_spoof",
    "MITM-LAB live rogue DHCP reply from attacker": "dhcp_rogue_server",
    "MITM-LAB live rogue DHCP reply from non-gateway server": "dhcp_rogue_server",
}

SENSOR_COVERAGE = {
    "detector": {
        "arp_spoof": True,
        "icmp_redirect": True,
        "dns_spoof": True,
        "dns_source_violation": False,
        "dhcp_spoof": True,
        "dhcp_rogue_server": True,
        "dhcp_untrusted_switch_port": False,
    },
    "zeek": {
        "arp_spoof": True,
        "icmp_redirect": True,
        "dns_spoof": True,
        "dns_source_violation": False,
        "dhcp_spoof": True,
        "dhcp_rogue_server": True,
        "dhcp_untrusted_switch_port": False,
    },
    "suricata": {
        "arp_spoof": False,
        "icmp_redirect": True,
        "dns_spoof": True,
        "dns_source_violation": False,
        "dhcp_spoof": True,
        "dhcp_rogue_server": True,
        "dhcp_untrusted_switch_port": False,
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
        payload = asdict(self)
        payload["combined_sensor_detected"] = self.zeek_alert_events > 0 or self.suricata_alert_events > 0
        return payload
