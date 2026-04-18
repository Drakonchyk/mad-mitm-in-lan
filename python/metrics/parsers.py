from __future__ import annotations

from datetime import datetime, timezone
from fnmatch import fnmatch
import json
from pathlib import Path
import shutil
import subprocess
from typing import Any, Iterable

from lab.config import load_lab_config
from metrics.model import GROUND_TRUTH_ATTACK_EVENTS


def load_json(path: Path) -> dict[str, Any]:
    return json.loads(path.read_text(encoding="utf-8"))


def load_jsonl(path: Path) -> list[dict[str, Any]]:
    records: list[dict[str, Any]] = []
    if not path.exists():
        return records
    for line in path.read_text(encoding="utf-8", errors="replace").splitlines():
        if not line.strip():
            continue
        try:
            payload = json.loads(line)
        except json.JSONDecodeError:
            continue
        if isinstance(payload, dict):
            records.append(payload)
    return records


def parse_concatenated_json(path: Path) -> list[dict[str, Any]]:
    if not path.exists():
        return []

    text = path.read_text(encoding="utf-8", errors="replace")
    decoder = json.JSONDecoder()
    index = 0
    records: list[dict[str, Any]] = []

    while index < len(text):
        while index < len(text) and text[index].isspace():
            index += 1
        if index >= len(text):
            break
        try:
            payload, next_index = decoder.raw_decode(text, index)
        except json.JSONDecodeError:
            index += 1
            continue
        if isinstance(payload, dict):
            records.append(payload)
        index = next_index
    return records


def parse_timestamp(value: str | None) -> datetime | None:
    if not value:
        return None
    return datetime.fromisoformat(value.replace("Z", "+00:00"))


def normalize_timestamp(value: Any) -> str | None:
    if value is None or value == "":
        return None
    if isinstance(value, (int, float)):
        return datetime.fromtimestamp(float(value), timezone.utc).isoformat()
    if isinstance(value, str):
        try:
            return datetime.fromtimestamp(float(value), timezone.utc).isoformat()
        except ValueError:
            return value
    return None


def run_tshark_fields(pcap_path: Path, display_filter: str, field: str) -> list[str]:
    if not pcap_path.exists() or shutil.which("tshark") is None:
        return []

    result = subprocess.run(
        [
            "tshark",
            "-r",
            str(pcap_path),
            "-Y",
            display_filter,
            "-T",
            "fields",
            "-e",
            field,
        ],
        check=False,
        capture_output=True,
        text=True,
    )
    if result.returncode != 0:
        return []
    return [line.strip() for line in result.stdout.splitlines() if line.strip()]


def attacker_mac_for_run(meta: dict[str, Any], attack_records: list[dict[str, Any]]) -> str | None:
    for record in attack_records:
        attacker_mac = record.get("attacker_mac")
        if attacker_mac:
            return str(attacker_mac).lower()

    attacker_mac = meta.get("attacker_mac")
    if attacker_mac:
        return str(attacker_mac).lower()

    try:
        return load_lab_config().get("ATTACKER_MAC", "").lower() or None
    except (FileNotFoundError, KeyError):
        return None


def observed_wire_attack_records(run_dir: Path, meta: dict[str, Any]) -> list[dict[str, Any]]:
    pcap_path = run_dir / "pcap" / "victim.pcap"
    victim_ip = meta.get("victim_ip")
    attacker_ip = meta.get("attacker_ip")
    if not victim_ip or not attacker_ip:
        return []

    icmp_epochs = run_tshark_fields(
        pcap_path,
        f"icmp.type==5 && ip.src=={attacker_ip} && ip.dst=={victim_ip}",
        "frame.time_epoch",
    )

    records: list[dict[str, Any]] = []
    for value in icmp_epochs:
        try:
            ts = datetime.fromtimestamp(float(value), timezone.utc).isoformat()
        except ValueError:
            continue
        records.append({"event": "icmp_redirect_observed", "ts": ts})
    return records


def observed_wire_attack_type_first_seen_at(
    run_dir: Path,
    meta: dict[str, Any],
    attack_records: list[dict[str, Any]],
) -> dict[str, str]:
    pcap_path = run_dir / "pcap" / "victim.pcap"
    victim_ip = meta.get("victim_ip")
    attacker_ip = meta.get("attacker_ip")
    gateway_ip = meta.get("gateway_lab_ip")
    attacker_mac = attacker_mac_for_run(meta, attack_records)
    if not pcap_path.exists():
        return {}

    filters: dict[str, str] = {}
    if attacker_mac and gateway_ip and victim_ip:
        filters["arp_spoof"] = (
            f"arp.opcode==2 && eth.src=={attacker_mac} && "
            f"arp.src.proto_ipv4=={gateway_ip} && arp.dst.proto_ipv4=={victim_ip}"
        )
    if attacker_ip and victim_ip:
        filters["icmp_redirect"] = f"icmp.type==5 && ip.src=={attacker_ip} && ip.dst=={victim_ip}"
    if attacker_ip and victim_ip and gateway_ip:
        filters["dns_spoof"] = (
            f"ip.src=={gateway_ip} && ip.dst=={victim_ip} && "
            f"dns.flags.response==1 && dns.a=={attacker_ip}"
        )

    first_seen_at: dict[str, str] = {}
    for attack_type, display_filter in filters.items():
        epochs = run_tshark_fields(pcap_path, display_filter, "frame.time_epoch")
        if not epochs:
            continue
        try:
            first_seen_at[attack_type] = datetime.fromtimestamp(float(epochs[0]), timezone.utc).isoformat()
        except ValueError:
            continue
    return dict(sorted(first_seen_at.items()))


def observed_wire_attack_start_candidates(
    run_dir: Path,
    meta: dict[str, Any],
    attack_records: list[dict[str, Any]],
) -> list[str]:
    return list(observed_wire_attack_type_first_seen_at(run_dir, meta, attack_records).values())


def normalize_ground_truth_event(payload: dict[str, Any]) -> dict[str, Any]:
    if "event" in payload:
        return payload
    if {"answer_ip", "client_ip", "query_name"} <= payload.keys():
        return {
            "event": "dns_spoof",
            "answer_ip": payload["answer_ip"],
            "client_ip": payload["client_ip"],
            "query_name": payload["query_name"],
        }
    return payload


def canonical_attack_type(event_name: str | None) -> str | None:
    if not event_name:
        return None
    return GROUND_TRUTH_ATTACK_EVENTS.get(event_name)


def canonical_counter_from_records(
    records: Iterable[dict[str, Any]],
    *,
    raw_type_key: str,
    type_map: dict[str, str],
    timestamp_key: str,
) -> tuple[dict[str, int], dict[str, str], dict[str, int]]:
    raw_counter: dict[str, int] = {}
    canonical_counter: dict[str, int] = {}
    first_seen_at: dict[str, str] = {}

    for record in records:
        raw_type = record.get(raw_type_key)
        if not raw_type:
            continue
        raw_key = str(raw_type)
        raw_counter[raw_key] = raw_counter.get(raw_key, 0) + 1
        canonical_type = type_map.get(raw_key)
        if canonical_type is None:
            continue
        canonical_counter[canonical_type] = canonical_counter.get(canonical_type, 0) + 1
        ts = normalize_timestamp(record.get(timestamp_key))
        if ts:
            previous = first_seen_at.get(canonical_type)
            if previous is None:
                first_seen_at[canonical_type] = ts
            else:
                previous_dt = parse_timestamp(previous)
                current_dt = parse_timestamp(ts)
                if current_dt is not None and (previous_dt is None or current_dt < previous_dt):
                    first_seen_at[canonical_type] = ts

    return dict(sorted(canonical_counter.items())), dict(sorted(first_seen_at.items())), dict(sorted(raw_counter.items()))


def canonical_ground_truth_counts(records: Iterable[dict[str, Any]]) -> tuple[dict[str, int], dict[str, str]]:
    counter: dict[str, int] = {}
    first_seen_at: dict[str, str] = {}
    for record in records:
        attack_type = canonical_attack_type(record.get("event"))
        if attack_type is None:
            continue
        counter[attack_type] = counter.get(attack_type, 0) + 1
        ts = normalize_timestamp(record.get("ts"))
        if ts:
            previous = first_seen_at.get(attack_type)
            if previous is None:
                first_seen_at[attack_type] = ts
            else:
                previous_dt = parse_timestamp(previous)
                current_dt = parse_timestamp(ts)
                if current_dt is not None and (previous_dt is None or current_dt < previous_dt):
                    first_seen_at[attack_type] = ts
    return dict(sorted(counter.items())), dict(sorted(first_seen_at.items()))


def merge_first_seen_maps(*maps: dict[str, str]) -> dict[str, str]:
    merged: dict[str, str] = {}
    for values in maps:
        for attack_type, ts in values.items():
            previous = merged.get(attack_type)
            if previous is None:
                merged[attack_type] = ts
                continue
            previous_dt = parse_timestamp(previous)
            current_dt = parse_timestamp(ts)
            if current_dt is not None and (previous_dt is None or current_dt < previous_dt):
                merged[attack_type] = ts
    return dict(sorted(merged.items()))


def supported_attack_started_at(
    ground_truth_first_seen_at: dict[str, str],
    coverage: dict[str, bool],
) -> str | None:
    candidates = [
        ts
        for attack_type, ts in ground_truth_first_seen_at.items()
        if coverage.get(attack_type, False)
    ]
    return first_timestamp(candidates)


def first_timestamp(values: Iterable[str | None]) -> str | None:
    normalized = [value for value in values if value]
    return next(
        (
            value
            for value in sorted(
                normalized,
                key=lambda candidate: parse_timestamp(candidate) or datetime.max.replace(tzinfo=timezone.utc),
            )
        ),
        None,
    )


def find_run_dirs(target: Path) -> list[Path]:
    if (target / "run-meta.json").exists():
        return [target]
    return sorted(path for path in target.iterdir() if (path / "run-meta.json").exists())


def filter_run_dirs(run_dirs: list[Path], patterns: list[str] | None) -> list[Path]:
    if not patterns:
        return run_dirs
    return [run_dir for run_dir in run_dirs if any(fnmatch(run_dir.name, pattern) for pattern in patterns)]


def find_attack_stdout_files(run_dir: Path) -> list[Path]:
    files = sorted(run_dir.glob("attacker/*.stdout"))
    return [path for path in files if path.name not in {"versions.txt"}]
