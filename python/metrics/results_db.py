#!/usr/bin/env python3
from __future__ import annotations

import argparse
from pathlib import Path
import sqlite3
import sys
from typing import Any

from metrics.core import load_or_evaluate_single_run
from metrics.primitives import time_to_detection_seconds
from metrics.run_artifacts import (
    detector_delta_path,
    detector_throughput_summary,
    load_json,
    load_jsonl,
    parse_synthetic_traffic_summary,
    suricata_eve_path,
    suricata_throughput_summary,
    zeek_stats_path,
    zeek_throughput_summary,
)
from metrics.truth_db import build_truth_database, truth_db_path

RESULTS_DB_NAME = "experiment-results.sqlite"


def default_db_path(run_dir: Path) -> Path:
    return run_dir.resolve().parent / RESULTS_DB_NAME


def bool_int(value: Any) -> int:
    return 1 if bool(value) else 0


def optional_float(value: Any) -> float | None:
    try:
        return float(value) if value is not None and value != "" else None
    except (TypeError, ValueError):
        return None


def optional_int(value: Any) -> int | None:
    try:
        return int(value) if value is not None and value != "" else None
    except (TypeError, ValueError):
        return None


def json_text(value: Any) -> str:
    import json

    return json.dumps(value, sort_keys=True, ensure_ascii=False)


def create_schema(connection: sqlite3.Connection) -> None:
    connection.executescript(
        """
        PRAGMA user_version = 1;

        CREATE TABLE IF NOT EXISTS metadata (
            key TEXT PRIMARY KEY,
            value TEXT NOT NULL
        );

        CREATE TABLE IF NOT EXISTS runs (
            run_id TEXT PRIMARY KEY,
            run_dir TEXT NOT NULL UNIQUE,
            scenario TEXT NOT NULL,
            mode TEXT,
            started_at TEXT,
            ended_at TEXT,
            duration_seconds REAL,
            attack_present INTEGER NOT NULL,
            ground_truth_source TEXT,
            pcap_requested INTEGER NOT NULL,
            port_pcap_requested INTEGER NOT NULL,
            raw_artifacts_retained INTEGER NOT NULL,
            trusted_ground_truth_db TEXT,
            traffic_probe_mode TEXT,
            traffic_probe_icmp_packets INTEGER,
            traffic_probe_dns_queries INTEGER,
            detector_alert_events INTEGER NOT NULL,
            zeek_alert_events INTEGER NOT NULL,
            suricata_alert_events INTEGER NOT NULL,
            detector_supported_ttd_seconds REAL,
            zeek_supported_ttd_seconds REAL,
            suricata_supported_ttd_seconds REAL,
            detector_packets_seen INTEGER,
            detector_packets_processed INTEGER,
            detector_packets_dropped INTEGER,
            detector_max_seen_pps REAL,
            detector_max_processed_pps REAL,
            zeek_packets_seen INTEGER,
            zeek_packets_processed INTEGER,
            zeek_packets_dropped INTEGER,
            zeek_max_seen_pps REAL,
            zeek_max_processed_pps REAL,
            suricata_packets_seen INTEGER,
            suricata_packets_processed INTEGER,
            suricata_packets_dropped INTEGER,
            suricata_max_seen_pps REAL,
            suricata_max_processed_pps REAL,
            reliability_loss_percent REAL,
            reliability_delay_ms REAL,
            reliability_jitter_ms REAL,
            reliability_rate TEXT,
            created_or_updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
        );

        CREATE TABLE IF NOT EXISTS truth_counts (
            run_id TEXT NOT NULL,
            attack_type TEXT NOT NULL,
            truth_count INTEGER NOT NULL,
            attacker_action_count INTEGER NOT NULL,
            observed_wire_count INTEGER NOT NULL,
            first_seen_at TEXT,
            duration_seconds REAL,
            packet_rate_pps REAL,
            PRIMARY KEY (run_id, attack_type),
            FOREIGN KEY (run_id) REFERENCES runs(run_id) ON DELETE CASCADE
        );

        CREATE TABLE IF NOT EXISTS sensor_counts (
            run_id TEXT NOT NULL,
            sensor TEXT NOT NULL,
            attack_type TEXT NOT NULL,
            alert_count INTEGER NOT NULL,
            first_alert_at TEXT,
            supported_ttd_seconds REAL,
            PRIMARY KEY (run_id, sensor, attack_type),
            FOREIGN KEY (run_id) REFERENCES runs(run_id) ON DELETE CASCADE
        );

        CREATE TABLE IF NOT EXISTS artifacts (
            run_id TEXT NOT NULL,
            name TEXT NOT NULL,
            relative_path TEXT NOT NULL,
            exists_on_disk INTEGER NOT NULL,
            PRIMARY KEY (run_id, name),
            FOREIGN KEY (run_id) REFERENCES runs(run_id) ON DELETE CASCADE
        );

        CREATE TABLE IF NOT EXISTS trusted_authorities (
            run_id TEXT NOT NULL,
            protocol TEXT NOT NULL,
            role TEXT NOT NULL,
            ip TEXT,
            mac TEXT,
            port_role TEXT,
            source TEXT NOT NULL,
            details_json TEXT NOT NULL DEFAULT '{}',
            FOREIGN KEY (run_id) REFERENCES runs(run_id) ON DELETE CASCADE
        );

        CREATE TABLE IF NOT EXISTS trusted_observations (
            run_id TEXT NOT NULL,
            attack_type TEXT NOT NULL,
            protocol TEXT NOT NULL,
            event_name TEXT NOT NULL,
            observed_at TEXT,
            count INTEGER NOT NULL,
            source TEXT NOT NULL,
            source_artifact TEXT NOT NULL,
            trusted_basis TEXT NOT NULL,
            details_json TEXT NOT NULL DEFAULT '{}',
            FOREIGN KEY (run_id) REFERENCES runs(run_id) ON DELETE CASCADE
        );

        DROP VIEW IF EXISTS run_overview;
        DROP VIEW IF EXISTS attack_matrix;

        CREATE VIEW run_overview AS
        SELECT
            run_id,
            scenario,
            started_at,
            duration_seconds,
            ground_truth_source,
            detector_alert_events,
            zeek_alert_events,
            suricata_alert_events,
            detector_max_processed_pps,
            zeek_max_processed_pps,
            suricata_max_processed_pps,
            run_dir
        FROM runs
        ORDER BY started_at, run_id;

        CREATE VIEW attack_matrix AS
        SELECT
            r.run_id,
            r.scenario,
            t.attack_type,
            t.truth_count,
            COALESCE(d.alert_count, 0) AS detector_alerts,
            COALESCE(z.alert_count, 0) AS zeek_alerts,
            COALESCE(s.alert_count, 0) AS suricata_alerts
        FROM runs r
        JOIN truth_counts t ON t.run_id = r.run_id
        LEFT JOIN sensor_counts d ON d.run_id = r.run_id AND d.attack_type = t.attack_type AND d.sensor = 'detector'
        LEFT JOIN sensor_counts z ON z.run_id = r.run_id AND z.attack_type = t.attack_type AND z.sensor = 'zeek'
        LEFT JOIN sensor_counts s ON s.run_id = r.run_id AND s.attack_type = t.attack_type AND s.sensor = 'suricata'
        ORDER BY r.started_at, r.run_id, t.attack_type;
        """
    )
    ensure_column(connection, "runs", "raw_artifacts_retained", "INTEGER NOT NULL DEFAULT 1")
    for column in (
        "detector_packets_seen INTEGER",
        "detector_packets_processed INTEGER",
        "detector_packets_dropped INTEGER",
        "zeek_packets_seen INTEGER",
        "zeek_packets_processed INTEGER",
        "zeek_packets_dropped INTEGER",
        "zeek_max_seen_pps REAL",
        "zeek_max_processed_pps REAL",
        "suricata_packets_seen INTEGER",
        "suricata_packets_processed INTEGER",
        "suricata_packets_dropped INTEGER",
        "suricata_max_seen_pps REAL",
        "suricata_max_processed_pps REAL",
    ):
        name, definition = column.split(" ", 1)
        ensure_column(connection, "runs", name, definition)


def ensure_column(connection: sqlite3.Connection, table: str, column: str, definition: str) -> None:
    columns = {
        str(row[1])
        for row in connection.execute(f"PRAGMA table_info({table})")
    }
    if column not in columns:
        connection.execute(f"ALTER TABLE {table} ADD COLUMN {column} {definition}")


def artifact_rows(run_dir: Path, run_id: str, *, retained: bool) -> list[tuple[str, str, str, int]]:
    candidates = {
        "run_meta": "run-meta.json",
        "evaluation": "evaluation.json",
        "summary": "summary.txt",
        "trusted_ground_truth_db": str(truth_db_path(run_dir).relative_to(run_dir)),
        "detector_delta": "detector/detector.delta.jsonl",
        "zeek_notice": "zeek/host/notice.log",
        "zeek_stats": "zeek/host/stats.log",
        "suricata_eve": "suricata/host/eve.json",
        "suricata_stats": "suricata/host/stats.log",
        "wire_truth": "pcap/wire-truth.json",
        "sensor_pcap": "pcap/sensor.pcap",
        "ovs_switch_truth": "detector/ovs-switch-truth-snooping.txt",
        "ovs_dhcp_snooping": "detector/ovs-dhcp-snooping.txt",
    }
    rows = []
    for name, relative in sorted(candidates.items()):
        rows.append((run_id, name, relative, 1 if retained and (run_dir / relative).exists() else 0))
    return rows


def delete_existing_run_rows(connection: sqlite3.Connection, run_id: str) -> None:
    for table in ("truth_counts", "sensor_counts", "artifacts", "trusted_authorities", "trusted_observations", "runs"):
        connection.execute(f"DELETE FROM {table} WHERE run_id = ?", (run_id,))


def copy_trusted_truth(connection: sqlite3.Connection, run_dir: Path, run_id: str) -> None:
    source_path = truth_db_path(run_dir)
    if not source_path.exists():
        return
    with sqlite3.connect(source_path) as source:
        authority_rows = source.execute(
            """
            SELECT protocol, role, ip, mac, port_role, source, details_json
            FROM trusted_authorities
            """
        ).fetchall()
        observation_rows = source.execute(
            """
            SELECT attack_type, protocol, event_name, observed_at, count, source,
                   source_artifact, trusted_basis, details_json
            FROM trusted_observations
            """
        ).fetchall()

    connection.executemany(
        """
        INSERT INTO trusted_authorities(
            run_id, protocol, role, ip, mac, port_role, source, details_json
        )
        VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        """,
        [(run_id, *row) for row in authority_rows],
    )
    connection.executemany(
        """
        INSERT INTO trusted_observations(
            run_id, attack_type, protocol, event_name, observed_at, count, source,
            source_artifact, trusted_basis, details_json
        )
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """,
        [(run_id, *row) for row in observation_rows],
    )


def upsert_run(
    run_dir: Path,
    db_path: Path | None = None,
    *,
    rebuild_truth: bool = True,
    raw_artifacts_retained: bool = True,
) -> Path:
    run_dir = run_dir.resolve()
    db_path = db_path.resolve() if db_path else default_db_path(run_dir)
    db_path.parent.mkdir(parents=True, exist_ok=True)

    if rebuild_truth or not truth_db_path(run_dir).exists():
        build_truth_database(run_dir)

    evaluation = load_or_evaluate_single_run(run_dir, use_cache=False, write_cache=True)
    meta = load_json(run_dir / "run-meta.json")
    detector_throughput = detector_throughput_summary(load_jsonl(detector_delta_path(run_dir)))
    zeek_throughput = zeek_throughput_summary(zeek_stats_path(run_dir))
    suricata_throughput = suricata_throughput_summary(suricata_eve_path(run_dir))
    synthetic_traffic = parse_synthetic_traffic_summary(run_dir / "victim" / "traffic-window.txt")
    trusted_db_relative = str(truth_db_path(run_dir).relative_to(run_dir)) if truth_db_path(run_dir).exists() else None

    with sqlite3.connect(db_path) as connection:
        connection.execute("PRAGMA foreign_keys = ON")
        create_schema(connection)
        connection.execute(
            "INSERT OR REPLACE INTO metadata(key, value) VALUES (?, ?)",
            ("schema", "experiment_results_v1"),
        )
        delete_existing_run_rows(connection, evaluation.run_id)
        connection.execute(
            """
            INSERT INTO runs(
                run_id, run_dir, scenario, mode, started_at, ended_at, duration_seconds,
                attack_present, ground_truth_source, pcap_requested, port_pcap_requested,
                raw_artifacts_retained, trusted_ground_truth_db, traffic_probe_mode, traffic_probe_icmp_packets,
                traffic_probe_dns_queries, detector_alert_events, zeek_alert_events,
                suricata_alert_events, detector_supported_ttd_seconds,
                zeek_supported_ttd_seconds, suricata_supported_ttd_seconds,
                detector_packets_seen, detector_packets_processed, detector_packets_dropped,
                detector_max_seen_pps, detector_max_processed_pps,
                zeek_packets_seen, zeek_packets_processed, zeek_packets_dropped,
                zeek_max_seen_pps, zeek_max_processed_pps,
                suricata_packets_seen, suricata_packets_processed, suricata_packets_dropped,
                suricata_max_seen_pps, suricata_max_processed_pps,
                reliability_loss_percent, reliability_delay_ms, reliability_jitter_ms,
                reliability_rate
            )
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                evaluation.run_id,
                str(run_dir),
                evaluation.scenario,
                meta.get("mode"),
                meta.get("started_at"),
                meta.get("ended_at"),
                optional_float(meta.get("duration_seconds")),
                bool_int(evaluation.attack_present),
                evaluation.ground_truth_source,
                bool_int(meta.get("pcap_requested")),
                bool_int(meta.get("port_pcap_requested")),
                bool_int(raw_artifacts_retained),
                trusted_db_relative,
                meta.get("traffic_probe_mode"),
                optional_int(synthetic_traffic.get("sent_icmp")),
                optional_int(synthetic_traffic.get("sent_dns_queries")),
                int(evaluation.detector_alert_events),
                int(evaluation.zeek_alert_events),
                int(evaluation.suricata_alert_events),
                evaluation.detector_supported_ttd_seconds,
                evaluation.zeek_supported_ttd_seconds,
                evaluation.suricata_supported_ttd_seconds,
                optional_int(detector_throughput.get("packets_seen")),
                optional_int(detector_throughput.get("packets_processed")),
                optional_int(detector_throughput.get("packets_dropped")),
                optional_float(detector_throughput.get("max_interval_seen_pps")),
                optional_float(detector_throughput.get("max_interval_processed_pps")),
                optional_int(zeek_throughput.get("packets_seen")),
                optional_int(zeek_throughput.get("packets_processed")),
                optional_int(zeek_throughput.get("packets_dropped")),
                optional_float(zeek_throughput.get("max_interval_seen_pps")),
                optional_float(zeek_throughput.get("max_interval_processed_pps")),
                optional_int(suricata_throughput.get("packets_seen")),
                optional_int(suricata_throughput.get("packets_processed")),
                optional_int(suricata_throughput.get("packets_dropped")),
                optional_float(suricata_throughput.get("max_interval_seen_pps")),
                optional_float(suricata_throughput.get("max_interval_processed_pps")),
                optional_float(meta.get("reliability_netem_loss_percent")),
                optional_float(meta.get("reliability_netem_delay_ms")),
                optional_float(meta.get("reliability_netem_jitter_ms")),
                meta.get("reliability_netem_rate"),
            ),
        )

        for attack_type, truth_count in sorted(evaluation.ground_truth_attack_types.items()):
            connection.execute(
                """
                INSERT INTO truth_counts(
                    run_id, attack_type, truth_count, attacker_action_count,
                    observed_wire_count, first_seen_at, duration_seconds, packet_rate_pps
                )
                VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    evaluation.run_id,
                    attack_type,
                    int(truth_count),
                    int(evaluation.ground_truth_attacker_action_types.get(attack_type, 0)),
                    int(evaluation.ground_truth_observed_wire_types.get(attack_type, 0)),
                    evaluation.ground_truth_attack_type_first_seen_at.get(attack_type),
                    evaluation.ground_truth_attack_type_durations_seconds.get(attack_type),
                    evaluation.ground_truth_attack_type_packet_rates_pps.get(attack_type),
                ),
            )

        sensor_maps = {
            "detector": (evaluation.detector_attack_type_counts, evaluation.detector_attack_type_first_alert_at),
            "zeek": (evaluation.zeek_attack_type_counts, evaluation.zeek_attack_type_first_alert_at),
            "suricata": (evaluation.suricata_attack_type_counts, evaluation.suricata_attack_type_first_alert_at),
        }
        for sensor, (counts, first_seen) in sensor_maps.items():
            for attack_type, alert_count in sorted(counts.items()):
                attack_type_ttd = time_to_detection_seconds(
                    evaluation.ground_truth_attack_type_first_seen_at.get(attack_type),
                    first_seen.get(attack_type),
                )
                connection.execute(
                    """
                    INSERT INTO sensor_counts(run_id, sensor, attack_type, alert_count, first_alert_at, supported_ttd_seconds)
                    VALUES (?, ?, ?, ?, ?, ?)
                    """,
                    (
                        evaluation.run_id,
                        sensor,
                        attack_type,
                        int(alert_count),
                        first_seen.get(attack_type),
                        attack_type_ttd,
                    ),
                )

        connection.executemany(
            """
            INSERT INTO artifacts(run_id, name, relative_path, exists_on_disk)
            VALUES (?, ?, ?, ?)
            """,
            artifact_rows(run_dir, evaluation.run_id, retained=raw_artifacts_retained),
        )
        copy_trusted_truth(connection, run_dir, evaluation.run_id)
        connection.commit()
    return db_path


def find_run_dirs(target: Path) -> list[Path]:
    if (target / "run-meta.json").exists():
        return [target]
    return sorted(path for path in target.iterdir() if (path / "run-meta.json").exists())


def rebuild(target: Path, db_path: Path | None = None) -> Path:
    run_dirs = find_run_dirs(target)
    output = (db_path or (run_dirs[0].resolve().parent if run_dirs else target) / RESULTS_DB_NAME).resolve()
    if not run_dirs:
        return output

    output.parent.mkdir(parents=True, exist_ok=True)
    tmp_output = output.with_name(f".{output.name}.tmp")
    if tmp_output.exists():
        tmp_output.unlink()
    for index, run_dir in enumerate(run_dirs, start=1):
        print(f"rebuild {index}/{len(run_dirs)} {run_dir.name}", file=sys.stderr)
        upsert_run(run_dir, tmp_output)
    tmp_output.replace(output)
    return output


def print_overview(db_path: Path) -> None:
    if not db_path.exists():
        print(f"{db_path} does not exist")
        return
    with sqlite3.connect(db_path) as connection:
        rows = connection.execute(
            """
            SELECT run_id, scenario, ground_truth_source, detector_alert_events,
                   zeek_alert_events, suricata_alert_events,
                   detector_max_processed_pps, zeek_max_processed_pps,
                   suricata_max_processed_pps, run_dir
            FROM run_overview
            ORDER BY started_at DESC, run_id DESC
            LIMIT 20
            """
        ).fetchall()
    headers = [
        "run_id",
        "scenario",
        "truth",
        "detector",
        "zeek",
        "suricata",
        "detector_pps",
        "zeek_pps",
        "suricata_pps",
        "run_dir",
    ]
    print("| " + " | ".join(headers) + " |")
    print("| " + " | ".join("---" for _ in headers) + " |")
    for row in rows:
        print("| " + " | ".join(str(value) for value in row) + " |")


def main() -> int:
    parser = argparse.ArgumentParser(description="Maintain compact SQLite experiment results index.")
    subparsers = parser.add_subparsers(dest="command", required=True)

    upsert_parser = subparsers.add_parser("upsert-run", help="Insert or replace one run in the results DB.")
    upsert_parser.add_argument("run_dir", type=Path)
    upsert_parser.add_argument("--db", type=Path, default=None)
    upsert_parser.add_argument("--compact", action="store_true", help="Mark raw per-run artifacts as not retained.")

    rebuild_parser = subparsers.add_parser("rebuild", help="Rebuild the results DB from a run directory or results root.")
    rebuild_parser.add_argument("target", type=Path, nargs="?", default=Path("results"))
    rebuild_parser.add_argument("--db", type=Path, default=None)

    overview_parser = subparsers.add_parser("overview", help="Print the newest rows from the results DB.")
    overview_parser.add_argument("--db", type=Path, default=Path("results") / RESULTS_DB_NAME)

    args = parser.parse_args()
    if args.command == "upsert-run":
        print(upsert_run(args.run_dir, args.db, raw_artifacts_retained=not args.compact))
    elif args.command == "rebuild":
        print(rebuild(args.target, args.db))
    elif args.command == "overview":
        print_overview(args.db)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
