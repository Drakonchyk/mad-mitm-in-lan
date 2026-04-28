from __future__ import annotations

from datetime import datetime, timezone
from fnmatch import fnmatch
import json
import os
from pathlib import Path
import shutil
import subprocess
from typing import Any, Iterable

from lab.config import load_lab_config
from metrics.model import GROUND_TRUTH_ATTACK_EVENTS
from metrics.run_artifacts import parse_ovs_dhcp_snooping_stats, parse_ovs_switch_truth_snooping_stats
from metrics.truth_db import TRUTH_DB_RELATIVE_PATH, trusted_observation_counts, trusted_observation_epochs_by_type

WIRE_TRUTH_SUMMARY_NAME = "wire-truth.json"
TSHARK_TIMEOUT_SECONDS = float(os.getenv("MITM_LAB_TSHARK_TIMEOUT_SECONDS", "10"))


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

    try:
        result = subprocess.run(
            [
                "tshark",
                "-n",
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
            timeout=TSHARK_TIMEOUT_SECONDS,
        )
    except subprocess.TimeoutExpired:
        return []
    if result.returncode != 0:
        return []
    return [line.strip() for line in result.stdout.splitlines() if line.strip()]


def run_tshark_rows(pcap_path: Path, display_filter: str, fields: list[str]) -> list[list[str]]:
    if not pcap_path.exists() or shutil.which("tshark") is None:
        return []

    command = [
        "tshark",
        "-n",
        "-r",
        str(pcap_path),
        "-Y",
        display_filter,
        "-T",
        "fields",
    ]
    for field in fields:
        command.extend(["-e", field])
    command.extend(["-E", "separator=\t"])
    try:
        result = subprocess.run(
            command,
            check=False,
            capture_output=True,
            text=True,
            timeout=TSHARK_TIMEOUT_SECONDS,
        )
    except subprocess.TimeoutExpired:
        return []
    if result.returncode != 0:
        return []
    return [line.split("\t") for line in result.stdout.splitlines() if line.strip()]


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


def normalize_domain_name(value: str | None) -> str | None:
    if not value:
        return None
    return value.rstrip(".").lower()


def monitored_domains_for_run(meta: dict[str, Any]) -> set[str]:
    domains: set[str] = set()
    spoofed_domains = meta.get("spoofed_domains")
    if isinstance(spoofed_domains, list):
        domains.update(filter(None, (normalize_domain_name(str(item)) for item in spoofed_domains)))
    raw_domains = meta.get("domains")
    if isinstance(raw_domains, str):
        domains.update(filter(None, (normalize_domain_name(item) for item in raw_domains.split())))
    return domains


def observed_wire_pcap_path(run_dir: Path) -> Path | None:
    preferred = [
        run_dir / "pcap" / "sensor.pcap",
        run_dir / "pcap" / "victim.pcap",
    ]
    for path in preferred:
        if path.exists():
            return path
    return None


def untrusted_switch_port_pcap_paths(run_dir: Path) -> list[Path]:
    ports_dir = run_dir / "pcap" / "ports"
    candidates = [
        ports_dir / "attacker.pcap",
        ports_dir / "victim.pcap",
    ]
    return [path for path in candidates if path.exists()]


def ovs_dhcp_snooping_epoch_fallback(run_dir: Path, meta: dict[str, Any]) -> list[str]:
    stats = parse_ovs_dhcp_snooping_stats(run_dir / "detector" / "ovs-dhcp-snooping.txt")
    try:
        packet_count = int(stats.get("packets", 0))
    except (TypeError, ValueError):
        return []
    if packet_count <= 0:
        return []

    ts = parse_timestamp(str(meta.get("attack_started_at") or meta.get("started_at") or ""))
    if ts is None:
        return []
    epoch = f"{ts.timestamp():.6f}"
    return [epoch] * packet_count


def repeated_epochs_from_count(meta: dict[str, Any], count: int) -> list[str]:
    if count <= 0:
        return []
    ts = parse_timestamp(str(meta.get("attack_started_at") or meta.get("started_at") or ""))
    if ts is None:
        return []
    epoch = f"{ts.timestamp():.6f}"
    return [epoch] * count


def switch_snooping_attack_epochs_by_type(run_dir: Path, meta: dict[str, Any]) -> dict[str, list[str]]:
    stats = parse_ovs_switch_truth_snooping_stats(run_dir / "detector" / "ovs-switch-truth-snooping.txt")
    by_type = stats.get("packets_by_type", {})
    epochs: dict[str, list[str]] = {}
    if isinstance(by_type, dict):
        for attack_type in ("arp_spoof",):
            try:
                count = int(by_type.get(attack_type, 0))
            except (TypeError, ValueError):
                count = 0
            values = repeated_epochs_from_count(meta, count)
            if values:
                epochs[attack_type] = values

    dhcp_values = ovs_dhcp_snooping_epoch_fallback(run_dir, meta)
    if dhcp_values:
        epochs["dhcp_untrusted_switch_port"] = dhcp_values
    return epochs


def wire_truth_summary_path(run_dir: Path) -> Path:
    return run_dir / "pcap" / WIRE_TRUTH_SUMMARY_NAME


def load_wire_truth_summary(run_dir: Path) -> dict[str, Any]:
    path = wire_truth_summary_path(run_dir)
    if not path.exists():
        return {}
    try:
        payload = load_json(path)
    except json.JSONDecodeError:
        return {}
    return payload if isinstance(payload, dict) else {}


def observed_wire_source_label(run_dir: Path) -> str | None:
    pcap_path = observed_wire_pcap_path(run_dir)
    if pcap_path is not None:
        return "switch_pcap" if pcap_path.name == "sensor.pcap" else "victim_pcap"

    summary = load_wire_truth_summary(run_dir)
    source = summary.get("ground_truth_source")
    if isinstance(source, str) and source in {"switch_pcap", "victim_pcap", "trusted_observation_db", "switch_snooping"}:
        return source
    if summary:
        return "wire_truth_summary"
    if trusted_observation_epochs_by_type(run_dir):
        return "trusted_observation_db"
    if switch_snooping_attack_epochs_by_type(run_dir, load_json(run_dir / "run-meta.json")):
        return "switch_snooping"
    return None


def observed_wire_attack_epochs_by_type(
    run_dir: Path,
    meta: dict[str, Any],
    attack_records: list[dict[str, Any]],
) -> dict[str, list[str]]:
    pcap_path = observed_wire_pcap_path(run_dir)
    victim_ip = meta.get("victim_ip")
    attacker_ip = meta.get("attacker_ip")
    gateway_ip = meta.get("gateway_lab_ip")
    gateway_mac = str(meta.get("gateway_lab_mac", "")).lower() or None
    attacker_mac = attacker_mac_for_run(meta, attack_records)
    if pcap_path is None:
        db_epochs = trusted_observation_epochs_by_type(run_dir)
        if db_epochs:
            return db_epochs
        summary = load_wire_truth_summary(run_dir)
        values = summary.get("attack_epochs_by_type", {})
        if not isinstance(values, dict):
            return switch_snooping_attack_epochs_by_type(run_dir, meta)
        normalized: dict[str, list[str]] = {}
        for attack_type, epochs in values.items():
            if not isinstance(attack_type, str) or not isinstance(epochs, list):
                continue
            normalized[attack_type] = [str(epoch) for epoch in epochs if str(epoch)]
        for attack_type, epochs in switch_snooping_attack_epochs_by_type(run_dir, meta).items():
            normalized.setdefault(attack_type, epochs)
        return dict(sorted(normalized.items()))

    epochs: dict[str, list[str]] = {}
    if attacker_mac and gateway_ip and victim_ip:
        gateway_to_victim = run_tshark_fields(
            pcap_path,
            f"arp.opcode==2 && eth.src=={attacker_mac} && "
            f"arp.src.proto_ipv4=={gateway_ip} && arp.dst.proto_ipv4=={victim_ip}",
            "frame.time_epoch",
        )
        victim_to_gateway = run_tshark_fields(
            pcap_path,
            f"arp.opcode==2 && eth.src=={attacker_mac} && "
            f"arp.src.proto_ipv4=={victim_ip} && arp.dst.proto_ipv4=={gateway_ip}",
            "frame.time_epoch",
        )
        epochs["arp_spoof"] = sorted([*gateway_to_victim, *victim_to_gateway], key=float)
        epochs["arp_spoof_gateway_to_victim"] = gateway_to_victim
        epochs["arp_spoof_victim_to_gateway"] = victim_to_gateway
    if victim_ip and attacker_ip and gateway_ip:
        epochs["dns_spoof"] = run_tshark_fields(
            pcap_path,
            f"ip.src=={gateway_ip} && ip.dst=={victim_ip} && "
            f"dns.flags.response==1 && dns.a=={attacker_ip}",
            "frame.time_epoch",
        )
    if victim_ip and attacker_ip:
        epochs["icmp_redirect"] = run_tshark_fields(
            pcap_path,
            f"icmp.type==5 && ip.src=={attacker_ip} && ip.dst=={victim_ip}",
            "frame.time_epoch",
        )
    if gateway_mac:
        untrusted_dhcp_epochs: list[str] = []
        for port_pcap in untrusted_switch_port_pcap_paths(run_dir):
            untrusted_dhcp_epochs.extend(
                run_tshark_fields(
                    port_pcap,
                    "bootp && udp.srcport==67 && udp.dstport==68",
                    "frame.time_epoch",
                )
            )
        if untrusted_dhcp_epochs:
            epochs["dhcp_untrusted_switch_port"] = sorted(untrusted_dhcp_epochs, key=float)
        else:
            epochs["dhcp_untrusted_switch_port"] = run_tshark_fields(
                pcap_path,
                f"bootp && udp.srcport==67 && udp.dstport==68 && eth.src!={gateway_mac}",
                "frame.time_epoch",
            )
        if not epochs["dhcp_untrusted_switch_port"]:
            epochs["dhcp_untrusted_switch_port"] = ovs_dhcp_snooping_epoch_fallback(run_dir, meta)
    if gateway_ip and not epochs.get("arp_spoof"):
        switch_epochs = switch_snooping_attack_epochs_by_type(run_dir, meta)
        if switch_epochs.get("arp_spoof"):
            epochs["arp_spoof"] = switch_epochs["arp_spoof"]
    return epochs


def observed_wire_dns_query_rows(run_dir: Path, meta: dict[str, Any]) -> list[list[str]]:
    pcap_path = observed_wire_pcap_path(run_dir)
    victim_ip = meta.get("victim_ip")
    dns_server = meta.get("gateway_lab_ip")
    domains = monitored_domains_for_run(meta)
    if pcap_path is None or not victim_ip or not dns_server or not domains:
        return []

    rows = run_tshark_rows(
        pcap_path,
        f"ip.src=={victim_ip} && ip.dst=={dns_server} && dns.flags.response==0",
        ["frame.time_epoch", "dns.qry.name"],
    )
    filtered: list[list[str]] = []
    for row in rows:
        if len(row) < 2:
            continue
        qname = normalize_domain_name(row[1])
        if qname in domains:
            filtered.append(row)
    return filtered


def observed_wire_dns_query_count(run_dir: Path, meta: dict[str, Any]) -> int:
    pcap_path = observed_wire_pcap_path(run_dir)
    if pcap_path is None:
        summary = load_wire_truth_summary(run_dir)
        value = summary.get("dns_query_count")
        if isinstance(value, int):
            return value
        return 0
    return len(observed_wire_dns_query_rows(run_dir, meta))


def observed_wire_control_plane_packet_counts(run_dir: Path) -> dict[str, int]:
    pcap_path = observed_wire_pcap_path(run_dir)
    if pcap_path is None:
        summary = load_wire_truth_summary(run_dir)
        counts = summary.get("control_plane_packet_counts", {})
        if not isinstance(counts, dict):
            return {}
        normalized: dict[str, int] = {}
        for key, value in counts.items():
            if not isinstance(key, str):
                continue
            try:
                normalized[key] = int(value)
            except (TypeError, ValueError):
                continue
        return dict(sorted(normalized.items()))

    return {
        "arp": len(run_tshark_fields(pcap_path, "arp", "frame.number")),
        "dhcp": len(run_tshark_fields(pcap_path, "bootp || dhcp", "frame.number")),
        "dns": len(run_tshark_fields(pcap_path, "dns", "frame.number")),
        "broadcast_l2": len(run_tshark_fields(pcap_path, "eth.dst==ff:ff:ff:ff:ff:ff", "frame.number")),
    }


def observed_wire_capture_duration_seconds(run_dir: Path) -> float | None:
    pcap_path = observed_wire_pcap_path(run_dir)
    if pcap_path is None:
        summary = load_wire_truth_summary(run_dir)
        value = summary.get("capture_duration_seconds")
        try:
            return float(value) if value is not None else None
        except (TypeError, ValueError):
            return None
    epochs = run_tshark_fields(pcap_path, "frame", "frame.time_epoch")
    if len(epochs) < 2:
        return None
    try:
        return max(float(epochs[-1]) - float(epochs[0]), 0.0)
    except ValueError:
        return None


def observed_wire_attack_records(run_dir: Path, meta: dict[str, Any]) -> list[dict[str, Any]]:
    epochs_by_type = observed_wire_attack_epochs_by_type(run_dir, meta, [])

    records: list[dict[str, Any]] = []
    for value in epochs_by_type.get("arp_spoof", []):
        try:
            ts = datetime.fromtimestamp(float(value), timezone.utc).isoformat()
        except ValueError:
            continue
        records.append({"event": "arp_spoof_observed", "ts": ts})
    for value in epochs_by_type.get("dns_spoof", []):
        try:
            ts = datetime.fromtimestamp(float(value), timezone.utc).isoformat()
        except ValueError:
            continue
        records.append({"event": "dns_spoof_observed", "ts": ts})
    for value in epochs_by_type.get("dns_source_violation", []):
        try:
            ts = datetime.fromtimestamp(float(value), timezone.utc).isoformat()
        except ValueError:
            continue
        records.append({"event": "dns_source_violation_observed", "ts": ts})
    for value in epochs_by_type.get("icmp_redirect", []):
        try:
            ts = datetime.fromtimestamp(float(value), timezone.utc).isoformat()
        except ValueError:
            continue
        records.append({"event": "icmp_redirect_observed", "ts": ts})
    for value in epochs_by_type.get("dhcp_untrusted_switch_port", []):
        try:
            ts = datetime.fromtimestamp(float(value), timezone.utc).isoformat()
        except ValueError:
            continue
        records.append({"event": "untrusted_port_sent_dhcp_server_reply", "ts": ts})
    return records


def observed_wire_attack_type_first_seen_at(
    run_dir: Path,
    meta: dict[str, Any],
    attack_records: list[dict[str, Any]],
) -> dict[str, str]:
    first_seen_at: dict[str, str] = {}
    for attack_type, epochs in observed_wire_attack_epochs_by_type(run_dir, meta, attack_records).items():
        if attack_type.startswith("arp_spoof_"):
            continue
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


def build_wire_truth_summary(
    run_dir: Path,
    meta: dict[str, Any],
    attack_records: list[dict[str, Any]],
) -> dict[str, Any]:
    source = observed_wire_source_label(run_dir)
    if source is None:
        return {}

    epochs_by_type = observed_wire_attack_epochs_by_type(run_dir, meta, attack_records)
    return {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "ground_truth_source": source,
        "trusted_observation_db": str(TRUTH_DB_RELATIVE_PATH) if (run_dir / TRUTH_DB_RELATIVE_PATH).exists() else None,
        "trusted_observation_counts_by_type": trusted_observation_counts(run_dir),
        "switch_snooping_attack_epochs_by_type": switch_snooping_attack_epochs_by_type(run_dir, meta),
        "dhcp_truth_source": "untrusted_switch_port_pcap" if untrusted_switch_port_pcap_paths(run_dir) else source,
        "switch_truth_snooping_packets_by_type": parse_ovs_switch_truth_snooping_stats(
            run_dir / "detector" / "ovs-switch-truth-snooping.txt"
        ).get("packets_by_type", {}),
        "dhcp_snooping_untrusted_reply_packets": parse_ovs_dhcp_snooping_stats(
            run_dir / "detector" / "ovs-dhcp-snooping.txt"
        ).get("packets", 0),
        "capture_duration_seconds": observed_wire_capture_duration_seconds(run_dir),
        "attack_epochs_by_type": epochs_by_type,
        "dns_query_count": observed_wire_dns_query_count(run_dir, meta),
        "control_plane_packet_counts": observed_wire_control_plane_packet_counts(run_dir),
    }


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
