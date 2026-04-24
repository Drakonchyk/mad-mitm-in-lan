#!/usr/bin/env python3
from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class ScenarioDefinition:
    name: str
    group: str
    label: str
    detector_events: frozenset[str]
    attack_types: frozenset[str]


SCENARIOS: dict[str, ScenarioDefinition] = {
    "baseline": ScenarioDefinition(
        name="baseline",
        group="main",
        label="baseline",
        detector_events=frozenset(),
        attack_types=frozenset(),
    ),
    "arp-poison-no-forward": ScenarioDefinition(
        name="arp-poison-no-forward",
        group="main",
        label="arp-poison-no-forward",
        detector_events=frozenset({"gateway_mac_changed", "multiple_gateway_macs_seen"}),
        attack_types=frozenset({"arp_spoof"}),
    ),
    "arp-mitm-forward": ScenarioDefinition(
        name="arp-mitm-forward",
        group="main",
        label="arp-mitm-forward",
        detector_events=frozenset({"gateway_mac_changed", "multiple_gateway_macs_seen"}),
        attack_types=frozenset({"arp_spoof"}),
    ),
    "arp-mitm-dns": ScenarioDefinition(
        name="arp-mitm-dns",
        group="main",
        label="arp-mitm-dns",
        detector_events=frozenset({
            "gateway_mac_changed",
            "multiple_gateway_macs_seen",
            "domain_resolution_changed",
        }),
        attack_types=frozenset({"arp_spoof", "dns_spoof"}),
    ),
    "dhcp-spoof": ScenarioDefinition(
        name="dhcp-spoof",
        group="main",
        label="dhcp-spoof",
        detector_events=frozenset({
            "rogue_dhcp_server_seen",
            "dhcp_binding_conflict_seen",
        }),
        attack_types=frozenset({"dhcp_spoof"}),
    ),
    "mitigation-recovery": ScenarioDefinition(
        name="mitigation-recovery",
        group="main",
        label="mitigation-recovery",
        detector_events=frozenset({
            "gateway_mac_changed",
            "multiple_gateway_macs_seen",
            "domain_resolution_changed",
        }),
        attack_types=frozenset({"arp_spoof", "dns_spoof"}),
    ),
    "intermittent-arp-mitm-dns": ScenarioDefinition(
        name="intermittent-arp-mitm-dns",
        group="supplementary",
        label="intermittent-arp-mitm-dns",
        detector_events=frozenset({
            "gateway_mac_changed",
            "multiple_gateway_macs_seen",
            "domain_resolution_changed",
        }),
        attack_types=frozenset({"arp_spoof", "dns_spoof"}),
    ),
    "noisy-benign-baseline": ScenarioDefinition(
        name="noisy-benign-baseline",
        group="supplementary",
        label="noisy-benign-baseline",
        detector_events=frozenset(),
        attack_types=frozenset(),
    ),
    "reduced-observability": ScenarioDefinition(
        name="reduced-observability",
        group="supplementary",
        label="reduced-observability",
        detector_events=frozenset({
            "gateway_mac_changed",
            "multiple_gateway_macs_seen",
            "domain_resolution_changed",
        }),
        attack_types=frozenset({"arp_spoof", "dns_spoof"}),
    ),
    "intermittent-dhcp-spoof": ScenarioDefinition(
        name="intermittent-dhcp-spoof",
        group="supplementary",
        label="intermittent-dhcp-spoof",
        detector_events=frozenset({
            "rogue_dhcp_server_seen",
            "dhcp_binding_conflict_seen",
        }),
        attack_types=frozenset({"dhcp_spoof"}),
    ),
    "dhcp-offer-only": ScenarioDefinition(
        name="dhcp-offer-only",
        group="supplementary",
        label="dhcp-offer-only",
        detector_events=frozenset({
            "rogue_dhcp_server_seen",
            "dhcp_binding_conflict_seen",
        }),
        attack_types=frozenset({"dhcp_spoof"}),
    ),
}

MAIN_SCENARIOS = [name for name, definition in SCENARIOS.items() if definition.group == "main"]
SUPPLEMENTARY_SCENARIOS = [name for name, definition in SCENARIOS.items() if definition.group == "supplementary"]
SCENARIO_ORDER_ALL = [*MAIN_SCENARIOS, *SUPPLEMENTARY_SCENARIOS]
SCENARIO_LABELS = {name: definition.label for name, definition in SCENARIOS.items()}
DETECTOR_DETECTION_EVENTS = {name: set(definition.detector_events) for name, definition in SCENARIOS.items()}
SCENARIO_ATTACK_TYPES = {name: set(definition.attack_types) for name, definition in SCENARIOS.items()}


def selected_scenarios(profile: str) -> list[str]:
    if profile == "main":
        return list(MAIN_SCENARIOS)
    if profile == "supplementary":
        return list(SUPPLEMENTARY_SCENARIOS)
    return list(SCENARIO_ORDER_ALL)



def scenario_sort_key(scenario: str) -> int:
    if scenario in SCENARIO_ORDER_ALL:
        return SCENARIO_ORDER_ALL.index(scenario)
    return len(SCENARIO_ORDER_ALL)
