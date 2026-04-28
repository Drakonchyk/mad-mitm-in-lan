#!/usr/bin/env python3
from __future__ import annotations

from collections import Counter
from datetime import datetime, timezone
import argparse
import json
from pathlib import Path
import sqlite3
from typing import Any, Iterable

from metrics.model import ATTACK_TYPE_ORDER, DETECTOR_ALERT_EVENTS, SURICATA_ALERT_TYPES, ZEEK_ALERT_TYPES
from metrics.run_artifacts import (
    detector_delta_path,
    load_json,
    load_jsonl,
    parse_ovs_dhcp_snooping_stats,
    parse_ovs_switch_truth_snooping_stats,
    suricata_eve_path,
    zeek_notice_path,
)

TRUTH_DB_RELATIVE_PATH = Path("ground-truth") / "trusted-observations.sqlite"


def truth_db_path(run_dir: Path) -> Path:
    return run_dir / TRUTH_DB_RELATIVE_PATH


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def json_dumps(value: Any) -> str:
    return json.dumps(value, sort_keys=True, ensure_ascii=False)


def comparison_timestamp(meta: dict[str, Any]) -> str | None:
    value = meta.get("attack_started_at") or meta.get("started_at")
    return str(value) if value else None


def create_schema(connection: sqlite3.Connection) -> None:
    connection.executescript(
        """
        PRAGMA user_version = 1;

        CREATE TABLE metadata (
            key TEXT PRIMARY KEY,
            value TEXT NOT NULL
        );

        CREATE TABLE trusted_authorities (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            protocol TEXT NOT NULL,
            role TEXT NOT NULL,
            ip TEXT,
            mac TEXT,
            port_role TEXT,
            source TEXT NOT NULL,
            details_json TEXT NOT NULL DEFAULT '{}'
        );

        CREATE TABLE trusted_observations (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            attack_type TEXT NOT NULL,
            protocol TEXT NOT NULL,
            event_name TEXT NOT NULL,
            observed_at TEXT,
            count INTEGER NOT NULL,
            source TEXT NOT NULL,
            source_artifact TEXT NOT NULL,
            trusted_basis TEXT NOT NULL,
            details_json TEXT NOT NULL DEFAULT '{}'
        );

        CREATE TABLE sensor_alerts (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            sensor TEXT NOT NULL,
            attack_type TEXT NOT NULL,
            event_name TEXT NOT NULL,
            first_seen_at TEXT,
            count INTEGER NOT NULL,
            source_artifact TEXT NOT NULL
        );

        CREATE TABLE comparisons (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            sensor TEXT NOT NULL,
            attack_type TEXT NOT NULL,
            truth_count INTEGER NOT NULL,
            alert_count INTEGER NOT NULL,
            detected INTEGER NOT NULL,
            basis TEXT NOT NULL
        );
        """
    )


def insert_metadata(connection: sqlite3.Connection, meta: dict[str, Any]) -> None:
    rows = {
        "generated_at": utc_now(),
        "run_id": str(meta.get("run_id", "")),
        "scenario": str(meta.get("scenario", "")),
        "started_at": str(meta.get("started_at", "")),
        "attack_started_at": str(meta.get("attack_started_at", "")),
        "ground_truth_model": "trusted_authorities_plus_switch_snooping",
        "ground_truth_note": (
            "ARP/DNS/DHCP truth is stored from trusted switch/gateway artifacts. "
            "Detector, Zeek, and Suricata alerts are compared against this database."
        ),
    }
    connection.executemany(
        "INSERT INTO metadata(key, value) VALUES (?, ?)",
        sorted(rows.items()),
    )


def insert_authorities(connection: sqlite3.Connection, meta: dict[str, Any]) -> None:
    gateway_ip = str(meta.get("gateway_lab_ip") or "")
    gateway_mac = str(meta.get("gateway_lab_mac") or "").lower()
    dns_ip = str(meta.get("gateway_lab_ip") or meta.get("dns_server") or "")
    rows = [
        (
            "arp",
            "trusted_gateway_identity",
            gateway_ip,
            gateway_mac,
            "gateway",
            "run-meta.json",
            {"meaning": "ARP replies claiming this gateway identity are trusted only from the gateway port."},
        ),
        (
            "dns",
            "trusted_dns_responder",
            dns_ip,
            gateway_mac,
            "gateway",
            "run-meta.json",
            {"meaning": "DNS replies claiming this source are trusted only from the gateway port."},
        ),
        (
            "dhcp",
            "trusted_dhcp_server",
            gateway_ip,
            gateway_mac,
            "gateway",
            "run-meta.json",
            {"meaning": "DHCP server replies are trusted only from the gateway switch port."},
        ),
    ]
    connection.executemany(
        """
        INSERT INTO trusted_authorities(protocol, role, ip, mac, port_role, source, details_json)
        VALUES (?, ?, ?, ?, ?, ?, ?)
        """,
        [(protocol, role, ip, mac, port_role, source, json_dumps(details)) for protocol, role, ip, mac, port_role, source, details in rows],
    )


def insert_observation(
    connection: sqlite3.Connection,
    *,
    attack_type: str,
    protocol: str,
    event_name: str,
    observed_at: str | None,
    count: int,
    source: str,
    source_artifact: str,
    trusted_basis: str,
    details: dict[str, Any],
) -> None:
    if count <= 0:
        return
    connection.execute(
        """
        INSERT INTO trusted_observations(
            attack_type, protocol, event_name, observed_at, count, source,
            source_artifact, trusted_basis, details_json
        )
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
        """,
        (
            attack_type,
            protocol,
            event_name,
            observed_at,
            count,
            source,
            source_artifact,
            trusted_basis,
            json_dumps(details),
        ),
    )


def insert_switch_truth(connection: sqlite3.Connection, run_dir: Path, meta: dict[str, Any]) -> None:
    observed_at = comparison_timestamp(meta)
    switch_stats = parse_ovs_switch_truth_snooping_stats(run_dir / "detector" / "ovs-switch-truth-snooping.txt")
    switch_counts = switch_stats.get("packets_by_type", {})
    if isinstance(switch_counts, dict):
        insert_observation(
            connection,
            attack_type="arp_spoof",
            protocol="arp",
            event_name="untrusted_port_claimed_gateway_ip",
            observed_at=observed_at,
            count=int(switch_counts.get("arp_spoof", 0) or 0),
            source="ovs_switch_snooping",
            source_artifact="detector/ovs-switch-truth-snooping.txt",
            trusted_basis="gateway_ip_reply_seen_on_non_gateway_port",
            details={"stats": switch_stats},
        )
        insert_observation(
            connection,
            attack_type="dns_spoof",
            protocol="dns",
            event_name="untrusted_port_claimed_trusted_dns_source",
            observed_at=observed_at,
            count=int(switch_counts.get("dns_source_violation", 0) or 0),
            source="ovs_switch_snooping",
            source_artifact="detector/ovs-switch-truth-snooping.txt",
            trusted_basis="dns_reply_from_trusted_source_ip_seen_on_non_gateway_port",
            details={"stats": switch_stats},
        )

    dhcp_stats = parse_ovs_dhcp_snooping_stats(run_dir / "detector" / "ovs-dhcp-snooping.txt")
    insert_observation(
        connection,
        attack_type="dhcp_untrusted_switch_port",
        protocol="dhcp",
        event_name="untrusted_port_sent_dhcp_server_reply",
        observed_at=observed_at,
        count=int(dhcp_stats.get("packets", 0) or 0),
        source="ovs_dhcp_snooping",
        source_artifact="detector/ovs-dhcp-snooping.txt",
        trusted_basis="dhcp_server_reply_seen_on_non_gateway_port",
        details={"stats": dhcp_stats},
    )


def first_timestamp(records: Iterable[dict[str, Any]], timestamp_key: str) -> str | None:
    values = [str(record[timestamp_key]) for record in records if record.get(timestamp_key)]
    return sorted(values)[0] if values else None


def insert_sensor_counts(
    connection: sqlite3.Connection,
    *,
    sensor: str,
    counts: Counter[str],
    first_seen: dict[str, str | None],
    source_artifact: str,
) -> None:
    for attack_type, count in sorted(counts.items()):
        if count <= 0:
            continue
        connection.execute(
            """
            INSERT INTO sensor_alerts(sensor, attack_type, event_name, first_seen_at, count, source_artifact)
            VALUES (?, ?, ?, ?, ?, ?)
            """,
            (sensor, attack_type, attack_type, first_seen.get(attack_type), count, source_artifact),
        )


def detector_counts(run_dir: Path) -> tuple[Counter[str], dict[str, str | None]]:
    records = load_jsonl(detector_delta_path(run_dir))
    counts: Counter[str] = Counter()
    grouped: dict[str, list[dict[str, Any]]] = {}
    for record in records:
        attack_type = DETECTOR_ALERT_EVENTS.get(str(record.get("event")))
        if not attack_type:
            continue
        counts[attack_type] += 1
        grouped.setdefault(attack_type, []).append(record)
    return counts, {attack_type: first_timestamp(values, "ts") for attack_type, values in grouped.items()}


def zeek_counts(run_dir: Path) -> tuple[Counter[str], dict[str, str | None]]:
    records = load_jsonl(zeek_notice_path(run_dir))
    counts: Counter[str] = Counter()
    grouped: dict[str, list[dict[str, Any]]] = {}
    for record in records:
        attack_type = ZEEK_ALERT_TYPES.get(str(record.get("note")))
        if not attack_type:
            continue
        counts[attack_type] += 1
        grouped.setdefault(attack_type, []).append(record)
    return counts, {attack_type: first_timestamp(values, "ts") for attack_type, values in grouped.items()}


def suricata_counts(run_dir: Path) -> tuple[Counter[str], dict[str, str | None]]:
    records = load_jsonl(suricata_eve_path(run_dir))
    counts: Counter[str] = Counter()
    grouped: dict[str, list[dict[str, Any]]] = {}
    for record in records:
        if record.get("event_type") != "alert":
            continue
        signature = str(record.get("alert", {}).get("signature", ""))
        attack_type = SURICATA_ALERT_TYPES.get(signature)
        if not attack_type:
            continue
        counts[attack_type] += 1
        grouped.setdefault(attack_type, []).append(record)
    return counts, {attack_type: first_timestamp(values, "timestamp") for attack_type, values in grouped.items()}


def insert_sensor_alerts(connection: sqlite3.Connection, run_dir: Path) -> None:
    counts, first_seen = detector_counts(run_dir)
    insert_sensor_counts(
        connection,
        sensor="detector",
        counts=counts,
        first_seen=first_seen,
        source_artifact="detector/detector.delta.jsonl",
    )
    counts, first_seen = zeek_counts(run_dir)
    insert_sensor_counts(
        connection,
        sensor="zeek",
        counts=counts,
        first_seen=first_seen,
        source_artifact="zeek/host/notice.log",
    )
    counts, first_seen = suricata_counts(run_dir)
    insert_sensor_counts(
        connection,
        sensor="suricata",
        counts=counts,
        first_seen=first_seen,
        source_artifact="suricata/host/eve.json",
    )


def insert_comparisons(connection: sqlite3.Connection) -> None:
    truth_counts = Counter(
        {
            attack_type: count
            for attack_type, count in connection.execute(
                """
                SELECT attack_type, COALESCE(SUM(count), 0)
                FROM trusted_observations
                GROUP BY attack_type
                """
            )
        }
    )
    sensor_counts: dict[tuple[str, str], int] = {
        (sensor, attack_type): count
        for sensor, attack_type, count in connection.execute(
            """
            SELECT sensor, attack_type, COALESCE(SUM(count), 0)
            FROM sensor_alerts
            GROUP BY sensor, attack_type
            """
        )
    }
    rows = []
    for sensor in ("detector", "zeek", "suricata"):
        for attack_type in ATTACK_TYPE_ORDER:
            truth_count = int(truth_counts.get(attack_type, 0))
            alert_count = int(sensor_counts.get((sensor, attack_type), 0))
            rows.append((sensor, attack_type, truth_count, alert_count, 1 if alert_count > 0 else 0, "trusted_observations"))
    connection.executemany(
        """
        INSERT INTO comparisons(sensor, attack_type, truth_count, alert_count, detected, basis)
        VALUES (?, ?, ?, ?, ?, ?)
        """,
        rows,
    )


def build_truth_database(run_dir: Path) -> Path:
    run_dir = run_dir.resolve()
    meta = load_json(run_dir / "run-meta.json")
    output_path = truth_db_path(run_dir)
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.unlink(missing_ok=True)

    with sqlite3.connect(output_path) as connection:
        create_schema(connection)
        insert_metadata(connection, meta)
        insert_authorities(connection, meta)
        insert_switch_truth(connection, run_dir, meta)
        insert_sensor_alerts(connection, run_dir)
        insert_comparisons(connection)
        connection.commit()
    return output_path


def trusted_observation_counts(run_dir: Path) -> dict[str, int]:
    path = truth_db_path(run_dir)
    if not path.exists():
        return {}
    with sqlite3.connect(path) as connection:
        return {
            str(attack_type): int(count or 0)
            for attack_type, count in connection.execute(
                """
                SELECT attack_type, COALESCE(SUM(count), 0)
                FROM trusted_observations
                GROUP BY attack_type
                """
            )
        }


def trusted_observation_epochs_by_type(run_dir: Path) -> dict[str, list[str]]:
    path = truth_db_path(run_dir)
    if not path.exists():
        return {}
    epochs: dict[str, list[str]] = {}
    with sqlite3.connect(path) as connection:
        for attack_type, observed_at, count in connection.execute(
            """
            SELECT attack_type, observed_at, count
            FROM trusted_observations
            WHERE count > 0
            """
        ):
            if not observed_at:
                continue
            try:
                epoch = f"{datetime.fromisoformat(str(observed_at).replace('Z', '+00:00')).timestamp():.6f}"
            except ValueError:
                continue
            epochs.setdefault(str(attack_type), []).extend([epoch] * int(count or 0))
    return dict(sorted(epochs.items()))


def main() -> int:
    parser = argparse.ArgumentParser(description="Build trusted ground-truth SQLite DB for one run.")
    parser.add_argument("run_dir", type=Path)
    args = parser.parse_args()
    print(build_truth_database(args.run_dir))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
