#!/usr/bin/env python3
"""
Terminal GUI for correlating AP/network identifiers in 802.11 captures.

The app keeps every discovered identifier tied to evidence, so selecting a
candidate in the UI explains why it was considered related to the user input.
"""

from __future__ import annotations

import argparse
import base64
import csv
import json
import os
import ipaddress
import re
import shutil
import subprocess
import sys
from collections import Counter
from concurrent.futures import ThreadPoolExecutor
from dataclasses import asdict, dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Iterable
from urllib.parse import unquote


MAC_RE = re.compile(r"^(?:[0-9a-fA-F]{2}:){5}[0-9a-fA-F]{2}$")
BAD_MAC_PREFIXES = ("ff:ff:ff:ff:ff:ff", "33:33:", "01:00:", "01:80:c2:")
LOCAL_MULTICAST_IPS = ("224.", "239.", "255.255.255.255")
ANALYSIS_LEVELS = {"basic", "moderate", "deep"}


def normalize_analysis_level(value: str) -> str:
    value = (value or "deep").strip().lower()
    return value if value in ANALYSIS_LEVELS else "deep"


def normalize_mac(value: str) -> str:
    value = value.strip().lower().replace("-", ":")
    compact = re.sub(r"[^0-9a-f]", "", value)
    if len(compact) == 12:
        return ":".join(compact[i : i + 2] for i in range(0, 12, 2))
    return value


def is_mac(value: str) -> bool:
    return bool(MAC_RE.match(normalize_mac(value)))


def is_noise_mac(value: str) -> bool:
    value = normalize_mac(value)
    return not is_mac(value) or any(value.startswith(prefix) for prefix in BAD_MAC_PREFIXES)


def bssid_middle_octets(value: str) -> str:
    parts = normalize_mac(value).split(":")
    return ":".join(parts[1:4]) if len(parts) == 6 else ""


def escape_filter_string(value: str) -> str:
    return value.replace("\\", "\\\\").replace('"', '\\"')


def decode_ssid(value: str) -> str:
    value = (value or "").strip()
    if not value:
        return "<EMPTY SSID>"
    compact = value.replace(":", "")
    if len(compact) % 2 == 0 and re.fullmatch(r"[0-9a-fA-F]+", compact):
        try:
            decoded = bytes.fromhex(compact).decode("utf-8", errors="replace")
            return decoded if decoded else "<EMPTY SSID>"
        except ValueError:
            pass
    return value


def uniq_rows(rows: Iterable[dict[str, str]]) -> list[dict[str, str]]:
    seen: set[tuple[tuple[str, str], ...]] = set()
    output: list[dict[str, str]] = []
    for row in rows:
        key = tuple(sorted((k, v) for k, v in row.items()))
        if key not in seen:
            seen.add(key)
            output.append(row)
    return output


def split_multi(value: str) -> list[str]:
    values: list[str] = []
    for piece in re.split(r"\s*,\s*", value or ""):
        piece = piece.strip()
        if piece and piece not in values:
            values.append(piece)
    return values


def row_values(row: dict[str, str], *field_names: str) -> list[str]:
    values: list[str] = []
    for field_name in field_names:
        for value in split_multi(row.get(field_name, "")):
            if value not in values:
                values.append(value)
    return values


def first_row_value(row: dict[str, str], *field_names: str) -> str:
    values = row_values(row, *field_names)
    return values[0] if values else ""


def field_present(row: dict[str, str], *field_names: str) -> bool:
    return any(bool(row.get(field_name, "").strip()) for field_name in field_names)


def infer_protocol(row: dict[str, str]) -> str:
    protocols = (row.get("frame.protocols", "") or "").lower()
    checks = [
        ("DHCP", ("dhcp", "bootp"), ("dhcp.ip.your", "bootp.ip.your", "dhcp.option.hostname", "bootp.option.hostname")),
        ("ARP", ("arp",), ("arp.src.proto_ipv4", "arp.dst.proto_ipv4")),
        ("DNS", ("dns", "mdns", "llmnr", "nbns"), ("dns.qry.name", "dns.resp.name", "dns.srv.instance", "nbns.name")),
        ("HTTP", ("http",), ("http.user_agent", "http.server", "http.host", "http.request.full_uri")),
        ("TLS", ("tls", "ssl"), ("tls.handshake.extensions_server_name", "tls.handshake.ja3")),
        ("TCP", ("tcp",), ("tcp.srcport", "tcp.dstport")),
        ("UDP", ("udp",), ("udp.srcport", "udp.dstport")),
        ("IP", ("ip",), ("ip.src", "ip.dst")),
    ]
    for label, proto_tokens, fields in checks:
        if any(token in protocols for token in proto_tokens) or field_present(row, *fields):
            return label
    return ""


def cipher_name(value: str) -> str:
    names = {
        "0": "Use group cipher suite",
        "1": "WEP-40",
        "2": "TKIP",
        "3": "Reserved",
        "4": "CCMP-128/AES",
        "5": "WEP-104",
        "6": "BIP-CMAC-128",
        "7": "Group addressed traffic not allowed",
        "8": "GCMP-128",
        "9": "GCMP-256",
        "10": "CCMP-256",
        "11": "BIP-GMAC-128",
        "12": "BIP-GMAC-256",
        "13": "BIP-CMAC-256",
    }
    return names.get(value, value)


def akm_name(value: str) -> str:
    names = {
        "1": "802.1X",
        "2": "PSK",
        "3": "FT-802.1X",
        "4": "FT-PSK",
        "5": "802.1X-SHA256",
        "6": "PSK-SHA256",
        "7": "TDLS",
        "8": "SAE/WPA3-Personal",
        "9": "FT-SAE",
        "10": "AP PeerKey",
        "11": "802.1X-SUITE-B",
        "12": "802.1X-SUITE-B-192",
        "13": "FT-802.1X-SHA384",
        "14": "FILS-SHA256",
        "15": "FILS-SHA384",
        "16": "FT-FILS-SHA256",
        "17": "FT-FILS-SHA384",
        "18": "OWE/Enhanced Open",
        "19": "Reserved/Invalid AKM",
    }
    return names.get(value, value)


def decode_csv_values(value: str, decoder) -> str:
    if not value:
        return ""
    return ", ".join(decoder(part.strip()) for part in value.split(",") if part.strip())


def channel_to_frequency(channel: str) -> str:
    try:
        chan = int(channel)
    except (TypeError, ValueError):
        return ""
    if 1 <= chan <= 13:
        return f"{2407 + chan * 5} MHz"
    if chan == 14:
        return "2484 MHz"
    if 32 <= chan <= 177:
        return f"{5000 + chan * 5} MHz"
    if 1 <= chan <= 233:
        return f"{5950 + chan * 5} MHz"
    return ""


def frequency_to_band(frequency: str, channel: str = "") -> str:
    try:
        freq = int(str(frequency).replace("MHz", "").strip())
    except (TypeError, ValueError):
        freq = 0
    if not freq and channel:
        derived = channel_to_frequency(channel)
        try:
            freq = int(derived.replace("MHz", "").strip())
        except (TypeError, ValueError):
            freq = 0
    if 2400 <= freq < 2500:
        return "2.4 GHz"
    if 4900 <= freq < 5900:
        return "5 GHz"
    if 5925 <= freq < 7125:
        return "6 GHz"
    return ""


def confidence_badge(score: int) -> str:
    if score >= 120:
        return "High confidence"
    if score >= 70:
        return "Medium confidence"
    if score >= 30:
        return "Weak clue"
    return "Needs more evidence"


def oui_prefix(mac: str) -> str:
    mac = normalize_mac(mac)
    if not is_mac(mac):
        return ""
    return ":".join(mac.split(":")[:3]).upper()


def normalize_ip(value: str) -> str:
    value = (value or "").strip()
    if not value:
        return ""
    try:
        return str(ipaddress.ip_address(value))
    except ValueError:
        return value


def is_ip(value: str) -> bool:
    try:
        ipaddress.ip_address(value)
        return True
    except ValueError:
        return False


def ip_scope(value: str) -> str:
    try:
        ip = ipaddress.ip_address(value)
    except ValueError:
        return ""
    if ip.is_loopback:
        return "loopback"
    if ip.is_multicast:
        return "multicast"
    if ip.is_link_local:
        return "link-local"
    if ip.is_private:
        return "local/private"
    if ip.is_global:
        return "external/global"
    return "special"


def clean_hostname(value: str) -> str:
    value = (value or "").strip().strip(".")
    if not value:
        return ""
    lowered = value.lower()
    if lowered in {"<root>", "root", "localhost", "local"}:
        return ""
    if is_ip(normalize_ip(value)):
        return ""
    if lowered.endswith((".in-addr.arpa", ".ip6.arpa")):
        return ""
    if "._dns-sd." in lowered or "._tcp." in lowered or "._udp." in lowered:
        return ""
    labels = [label for label in value.split(".") if label]
    if not labels:
        return ""
    if any(label.startswith("_") for label in labels):
        return ""
    if all(label.isdigit() for label in labels):
        return ""
    if any(not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_-]{0,62}", label) for label in labels):
        return ""
    return value


def clean_hostnames(values: Iterable[str]) -> list[str]:
    cleaned: list[str] = []
    for value in values:
        hostname = clean_hostname(value)
        if hostname and hostname not in cleaned:
            cleaned.append(hostname)
    return cleaned


def clean_dns_name(value: str) -> str:
    value = (value or "").strip().strip(".")
    if not value:
        return ""
    lowered = value.lower()
    if lowered in {"<root>", "root"}:
        return ""
    if is_ip(normalize_ip(value)):
        return ""
    if any(ch in value for ch in "<>\x00"):
        return ""
    return value


def is_reverse_dns_name(value: str) -> bool:
    lowered = (value or "").strip().strip(".").lower()
    return lowered.endswith((".in-addr.arpa", ".ip6.arpa"))


def is_service_discovery_name(value: str) -> bool:
    lowered = (value or "").strip().strip(".").lower()
    return (
        "._dns-sd." in lowered
        or "._tcp." in lowered
        or "._udp." in lowered
        or lowered.startswith(("_services.", "_dns-sd.", "_tcp.", "_udp."))
    )


def split_dns_question_names(values: Iterable[str]) -> tuple[list[str], list[str], list[str]]:
    dns_queries: list[str] = []
    reverse_queries: list[str] = []
    service_names: list[str] = []
    for value in values:
        name = clean_dns_name(value)
        if not name:
            continue
        target = service_names if is_service_discovery_name(name) else reverse_queries if is_reverse_dns_name(name) else dns_queries
        if name not in target:
            target.append(name)
    return dns_queries, reverse_queries, service_names


def clean_nbns_names(values: Iterable[str]) -> list[str]:
    cleaned: list[str] = []
    for value in values:
        name = (value or "").strip().strip(".")
        if not name or any(ch in name for ch in "<>\x00"):
            continue
        if is_ip(normalize_ip(name)):
            continue
        if name not in cleaned:
            cleaned.append(name)
    return cleaned


def is_local_identity_ip(value: str) -> bool:
    scope = ip_scope(normalize_ip(value))
    return scope in {"local/private", "link-local"}


def is_local_admin_mac(value: str) -> bool:
    value = normalize_mac(value)
    if not is_mac(value):
        return False
    return bool(int(value.split(":")[0], 16) & 0b10)


def clean_hex(value: str) -> str:
    return re.sub(r"[^0-9a-fA-F]", "", value or "").lower()


def extract_gtks_from_key_data(value: str) -> set[str]:
    data = clean_hex(value)
    if len(data) < 16:
        return set()
    raw = bytes.fromhex(data)
    gtks: set[str] = set()
    index = 0
    while index + 2 <= len(raw):
        tag = raw[index]
        if tag == 0x00:
            index += 1
            continue
        if index + 2 > len(raw):
            break
        length = raw[index + 1]
        end = index + 2 + length
        if end > len(raw):
            break
        payload = raw[index + 2 : end]
        # RSN GTK KDE: vendor-specific tag dd, OUI 00:0f:ac, data type 1,
        # two key-info bytes, then the GTK itself.
        if tag == 0xDD and len(payload) >= 22 and payload[:4] == b"\x00\x0f\xac\x01":
            gtk = payload[6:]
            if len(gtk) in {16, 24, 32}:
                gtks.add(gtk.hex())
        index = end
    return gtks


@dataclass
class Evidence:
    source: str
    reason: str
    score: int
    fields: dict[str, str] = field(default_factory=dict)
    command: list[str] = field(default_factory=list)
    count: int = 1

    def signature(self) -> tuple[str, str, tuple[tuple[str, str], ...]]:
        """Group repeated sightings without letting frame volume inflate score."""
        ignored = {"frame.number"}
        if self.source == "AP discovery":
            keep = {"wlan.bssid", "wlan.ssid", "wlan.ds.current_channel", "wlan.ht.info.primarychannel"}
            stable_fields = tuple(sorted((key, value) for key, value in self.fields.items() if key in keep and value))
            return self.source, self.reason, stable_fields
        if self.source == "Security inspection":
            keep = {
                "wlan.bssid",
                "wlan.rsn.pcs.type",
                "wlan.rsn.akms.type",
                "wlan.rsn.capabilities.mfpr",
                "wlan.rsn.capabilities.mfpc",
            }
            stable_fields = tuple(sorted((key, value) for key, value in self.fields.items() if key in keep and value))
            return self.source, self.reason, stable_fields
        stable_fields = tuple(
            sorted((key, value) for key, value in self.fields.items() if key not in ignored and value)
        )
        return self.source, self.reason, stable_fields


@dataclass
class Candidate:
    kind: str
    value: str
    confidence: int = 0
    labels: set[str] = field(default_factory=set)
    related: set[str] = field(default_factory=set)
    evidence: list[Evidence] = field(default_factory=list)
    _evidence_index: dict[tuple[str, str, tuple[tuple[str, str], ...]], int] = field(default_factory=dict, repr=False)

    @property
    def key(self) -> str:
        return f"{self.kind}:{self.value}"

    def add_evidence(self, evidence: Evidence) -> None:
        signature = evidence.signature()
        if signature in self._evidence_index:
            self.evidence[self._evidence_index[signature]].count += evidence.count
            return
        self._evidence_index[signature] = len(self.evidence)
        self.confidence += evidence.score
        self.evidence.append(evidence)


@dataclass
class DeviceProfile:
    key: str
    role: str = ""
    mac: str = ""
    bssids: set[str] = field(default_factory=set)
    ssids: set[str] = field(default_factory=set)
    hostnames: set[str] = field(default_factory=set)
    vendor: str = ""
    make: str = ""
    model: str = ""
    firmware: str = ""
    channel: str = ""
    frequency: str = ""
    channels: set[str] = field(default_factory=set)
    frequencies: set[str] = field(default_factory=set)
    band: str = ""
    encryption: str = ""
    akm: str = ""
    strongest_rssi: str = ""
    average_rssi: str = ""
    uptime: str = ""
    handshakes: set[str] = field(default_factory=set)
    pmkids: set[str] = field(default_factory=set)
    ips: set[str] = field(default_factory=set)
    peers: set[str] = field(default_factory=set)
    dns_queries: set[str] = field(default_factory=set)
    reverse_dns_queries: set[str] = field(default_factory=set)
    service_discovery_names: set[str] = field(default_factory=set)
    nbns_names: set[str] = field(default_factory=set)
    http_hosts: set[str] = field(default_factory=set)
    http_uris: set[str] = field(default_factory=set)
    services: set[str] = field(default_factory=set)
    dhcp_vendor_classes: set[str] = field(default_factory=set)
    dhcp_parameter_lists: set[str] = field(default_factory=set)
    dhcp_servers: set[str] = field(default_factory=set)
    dhcp_routers: set[str] = field(default_factory=set)
    dhcp_dns_servers: set[str] = field(default_factory=set)
    dhcp_subnet_masks: set[str] = field(default_factory=set)
    dhcp_requested_ips: set[str] = field(default_factory=set)
    http_user_agents: set[str] = field(default_factory=set)
    http_servers: set[str] = field(default_factory=set)
    http_auth_realms: set[str] = field(default_factory=set)
    credential_indicators: set[str] = field(default_factory=set)
    tls_sni: set[str] = field(default_factory=set)
    tls_ja3: set[str] = field(default_factory=set)
    discovery_protocols: set[str] = field(default_factory=set)
    management_ips: set[str] = field(default_factory=set)
    platform: str = ""
    software: str = ""
    serial: str = ""
    port_ids: set[str] = field(default_factory=set)
    interface_names: set[str] = field(default_factory=set)
    vlans: set[str] = field(default_factory=set)
    mesh_ids: set[str] = field(default_factory=set)
    topology_roles: set[str] = field(default_factory=set)
    mesh_peers: set[str] = field(default_factory=set)
    hwmp_peers: set[str] = field(default_factory=set)
    neighbor_bssids: set[str] = field(default_factory=set)
    rnr_bssids: set[str] = field(default_factory=set)
    wds_peers: set[str] = field(default_factory=set)
    vendor_ap_names: set[str] = field(default_factory=set)
    vendor_mesh_clues: set[str] = field(default_factory=set)
    mobility_domains: set[str] = field(default_factory=set)
    device_type_scores: dict[str, int] = field(default_factory=dict)
    device_type_evidence: dict[str, list[str]] = field(default_factory=dict)
    role_hints: set[str] = field(default_factory=set)
    protocols: set[str] = field(default_factory=set)
    first_seen: str = ""
    last_seen: str = ""
    frame_count: int = 0
    rssi_samples: list[int] = field(default_factory=list)
    warnings: set[str] = field(default_factory=set)

    def merge_frame(self, frame: str) -> None:
        try:
            frame_num = int(frame)
        except (TypeError, ValueError):
            return
        self.frame_count += 1
        if not self.first_seen or frame_num < int(self.first_seen):
            self.first_seen = str(frame_num)
        if not self.last_seen or frame_num > int(self.last_seen):
            self.last_seen = str(frame_num)

    def set_if_empty(self, field_name: str, value: str) -> None:
        if value and not getattr(self, field_name):
            setattr(self, field_name, value)

    def add_rssi(self, value: str) -> None:
        try:
            sample = int(float(value))
        except (TypeError, ValueError):
            return
        self.rssi_samples.append(sample)
        strongest = max(self.rssi_samples)
        average = round(sum(self.rssi_samples) / len(self.rssi_samples), 1)
        self.strongest_rssi = f"{strongest} dBm"
        self.average_rssi = f"{average} dBm"


@dataclass
class IPHostStats:
    ip: str
    source_frames: int = 0
    destination_frames: int = 0
    unicast_source_frames: int = 0
    arp_replies: int = 0
    arp_requests_for: int = 0
    tcp_syn_sent: set[str] = field(default_factory=set)
    tcp_synack_ports: set[str] = field(default_factory=set)
    tcp_rst_ports: set[str] = field(default_factory=set)
    udp_response_ports: set[str] = field(default_factory=set)
    protocols: Counter = field(default_factory=Counter)
    peers: Counter = field(default_factory=Counter)
    scanned_targets: set[str] = field(default_factory=set)
    scanned_by: set[str] = field(default_factory=set)
    macs: set[str] = field(default_factory=set)
    hostnames: set[str] = field(default_factory=set)
    dns_queries: set[str] = field(default_factory=set)
    reverse_dns_queries: set[str] = field(default_factory=set)
    service_discovery_names: set[str] = field(default_factory=set)
    nbns_names: set[str] = field(default_factory=set)
    http_hosts: set[str] = field(default_factory=set)
    http_uris: set[str] = field(default_factory=set)
    services: set[str] = field(default_factory=set)
    dhcp_vendor_classes: set[str] = field(default_factory=set)
    dhcp_parameter_lists: set[str] = field(default_factory=set)
    dhcp_servers: set[str] = field(default_factory=set)
    dhcp_routers: set[str] = field(default_factory=set)
    dhcp_dns_servers: set[str] = field(default_factory=set)
    dhcp_subnet_masks: set[str] = field(default_factory=set)
    dhcp_requested_ips: set[str] = field(default_factory=set)
    dhcp_leases: set[str] = field(default_factory=set)
    http_user_agents: set[str] = field(default_factory=set)
    http_servers: set[str] = field(default_factory=set)
    tls_sni: set[str] = field(default_factory=set)
    tls_ja3: set[str] = field(default_factory=set)
    first_frame: str = ""
    last_frame: str = ""

    def merge_frame(self, frame: str) -> None:
        try:
            frame_num = int(frame)
        except (TypeError, ValueError):
            return
        if not self.first_frame or frame_num < int(self.first_frame):
            self.first_frame = str(frame_num)
        if not self.last_frame or frame_num > int(self.last_frame):
            self.last_frame = str(frame_num)

    @property
    def total_frames(self) -> int:
        return self.source_frames + self.destination_frames


@dataclass
class AnalysisResult:
    candidates: dict[str, Candidate] = field(default_factory=dict)
    profiles: dict[str, DeviceProfile] = field(default_factory=dict)
    ap_rows: list[dict[str, str]] = field(default_factory=list)
    ap_observation_rows: list[dict[str, str]] = field(default_factory=list)
    ssid_group_rows: list[dict[str, str]] = field(default_factory=list)
    topology_rows: list[dict[str, str]] = field(default_factory=list)
    discovery_rows: list[dict[str, str]] = field(default_factory=list)
    credential_rows: list[dict[str, str]] = field(default_factory=list)
    http_uri_rows: list[dict[str, str]] = field(default_factory=list)
    client_rows: list[dict[str, str]] = field(default_factory=list)
    ip_device_rows: list[dict[str, str]] = field(default_factory=list)
    conversation_rows: list[dict[str, str]] = field(default_factory=list)
    scan_rows: list[dict[str, str]] = field(default_factory=list)
    service_rows: list[dict[str, str]] = field(default_factory=list)
    open_service_rows: list[dict[str, str]] = field(default_factory=list)
    closed_service_rows: list[dict[str, str]] = field(default_factory=list)
    device_type_rows: list[dict[str, str]] = field(default_factory=list)
    security_rows: list[dict[str, str]] = field(default_factory=list)
    handshake_rows: list[dict[str, str]] = field(default_factory=list)
    decrypted_rows: list[dict[str, str]] = field(default_factory=list)
    messages: list[str] = field(default_factory=list)
    started_at: str = field(default_factory=lambda: datetime.now().isoformat(timespec="seconds"))
    source_file: str = ""
    analysis_level: str = ""
    target_ssid: str = ""
    target_mac: str = ""
    target_ip: str = ""

    def add_candidate(
        self,
        kind: str,
        value: str,
        evidence: Evidence,
        labels: Iterable[str] = (),
        related: Iterable[str] = (),
    ) -> Candidate:
        value = normalize_mac(value) if kind in {"BSSID", "Client", "Wired/Upstream", "MAC"} else normalize_ip(value) if kind == "IP" else value
        key = f"{kind}:{value}"
        candidate = self.candidates.setdefault(key, Candidate(kind=kind, value=value))
        candidate.labels.update(label for label in labels if label)
        candidate.related.update(item for item in related if item)
        candidate.add_evidence(evidence)
        profile = self.profiles.setdefault(candidate.key, DeviceProfile(key=candidate.key))
        profile.role = kind
        if kind in {"BSSID", "Client", "Wired/Upstream", "MAC"}:
            profile.mac = value
            profile.vendor = profile.vendor or oui_prefix(value)
            if is_local_admin_mac(value):
                profile.warnings.add("MAC is locally administered; it may be randomized")
        elif kind == "SSID":
            profile.ssids.add(value)
        elif kind == "IP":
            profile.ips.add(value)
            profile.role_hints.add(ip_scope(value))
        elif kind == "Hostname":
            profile.hostnames.add(value)
        return candidate

    def profile_for(self, candidate: Candidate) -> DeviceProfile:
        return self.profiles.setdefault(candidate.key, DeviceProfile(key=candidate.key, role=candidate.kind))

    def sorted_candidates(self) -> list[Candidate]:
        return sorted(
            self.candidates.values(),
            key=lambda item: (-item.confidence, item.kind, item.value),
        )

    def export_json(self, path: Path) -> None:
        def clean_candidate(candidate: Candidate) -> dict:
            data = asdict(candidate)
            data["labels"] = sorted(candidate.labels)
            data["related"] = sorted(candidate.related)
            data.pop("_evidence_index", None)
            return data

        def clean_profile(profile: DeviceProfile) -> dict:
            data = asdict(profile)
            for key, value in list(data.items()):
                if isinstance(value, set):
                    data[key] = sorted(value)
            return data

        payload = {
            "started_at": self.started_at,
            "source_file": self.source_file,
            "analysis_level": self.analysis_level,
            "targets": {"ssid": self.target_ssid, "mac": self.target_mac, "ip": self.target_ip},
            "messages": self.messages,
            "candidates": [clean_candidate(c) for c in self.sorted_candidates()],
            "profiles": {key: clean_profile(profile) for key, profile in self.profiles.items()},
            "ap_rows": self.ap_rows,
            "ap_observation_rows": self.ap_observation_rows,
            "ssid_group_rows": self.ssid_group_rows,
            "topology_rows": self.topology_rows,
            "discovery_rows": self.discovery_rows,
            "credential_rows": self.credential_rows,
            "http_uri_rows": self.http_uri_rows,
            "client_rows": self.client_rows,
            "ip_device_rows": self.ip_device_rows,
            "conversation_rows": self.conversation_rows,
            "scan_rows": self.scan_rows,
            "service_rows": self.service_rows,
            "open_service_rows": self.open_service_rows,
            "closed_service_rows": self.closed_service_rows,
            "device_type_rows": self.device_type_rows,
            "security_rows": self.security_rows,
            "handshake_rows": self.handshake_rows,
            "decrypted_rows": self.decrypted_rows,
        }
        path.write_text(json.dumps(payload, indent=2), encoding="utf-8")

    def export_markdown(self, path: Path) -> None:
        lines = [
            "---",
            "Author:",
            f"Date: {self._md_yaml(self.started_at)}",
            'Title: "Wireless Network Analysis Report"',
            f"File Used: {self._md_yaml(self.source_file)}",
            f"Analysis Level: {self._md_yaml((self.analysis_level or 'unknown').title())}",
            "---",
            "",
            "# Network Analysis Report",
            "",
        ]
        targets = [("SSID", self.target_ssid), ("MAC", self.target_mac), ("IP", self.target_ip)]
        targets = [(label, value) for label, value in targets if self._has_value(value)]
        if targets:
            lines.extend(["## Targets", ""])
            for label, value in targets:
                lines.append(f"- **{label}:** {self._md_code(value)}")
            lines.append("")

        wireless = [row for row in self.client_rows if row.get("Role") == "Wireless client"]
        wired = [row for row in self.client_rows if row.get("Role") == "Wired/Upstream"]
        lines.extend([
            "## Summary",
            "",
            f"- **Access points observed:** {len(self.ap_rows)}",
            f"- **Wireless clients observed:** {len(wireless)}",
            f"- **Wired/upstream clients observed:** {len(wired)}",
            f"- **IP devices observed:** {len(self.ip_device_rows)}",
            f"- **Handshake records:** {len(self.handshake_rows)}",
            f"- **Open service records:** {len(self.open_service_rows)}",
            "",
        ])

        if self.ap_rows:
            lines.extend(["## Observed Access Points", ""])
            for row in self.ap_rows:
                bssid = row.get("BSSID", "")
                profile = self.profiles.get(f"BSSID:{bssid}", DeviceProfile(key=f"BSSID:{bssid}"))
                ssids = row.get("SSIDs", "")
                title = f"{ssids} - {bssid}" if self._has_value(ssids) else bssid
                lines.extend([f"### {self._md_text(title)}", ""])
                fields = [
                    ("SSID", ssids, True), ("BSSID", bssid, True),
                    ("Manufacturer", profile.make or row.get("Manufacturer", ""), False),
                    ("Model", profile.model or row.get("Model", ""), False),
                    ("Firmware", profile.firmware, False), ("Platform", profile.platform, False),
                    ("Channel", row.get("Channel", ""), False), ("All observed channels", row.get("All Channels", ""), False),
                    ("Frequency", self._with_unit(row.get("Frequency", ""), "MHz"), False), ("All observed frequencies", row.get("All Freqs", ""), False),
                    ("Band", row.get("Band", ""), False), ("Security", row.get("Security", ""), False),
                    ("Strongest RSSI", self._with_unit(row.get("Best RSSI", ""), "dBm"), False),
                    ("Average RSSI", self._with_unit(row.get("Avg RSSI", ""), "dBm"), False),
                    ("Uptime", profile.uptime, False), ("Handshakes", row.get("Handshakes", ""), False),
                    ("PMKID", ", ".join(sorted(profile.pmkids)), False),
                    ("Topology role", ", ".join(sorted(profile.topology_roles)), False),
                    ("Mesh ID", ", ".join(sorted(profile.mesh_ids)), False),
                    ("Management IP", ", ".join(sorted(profile.management_ips)), True),
                ]
                self._append_md_fields(lines, fields)

        self._append_client_section(lines, "Wireless Clients", wireless, "Client")
        self._append_client_section(lines, "Wired/Upstream Clients", wired, "Wired/Upstream")

        if self.topology_rows:
            self._append_md_table_section(lines, "Mesh and Network Topology", self.topology_rows, [
                ("Device", "Device", True), ("Role", "Role Guess", True), ("Confidence", "Confidence", False),
                ("Mesh ID", "Mesh ID", False), ("Mesh Peers", "Mesh Peers", False), ("WDS Peers", "WDS Peers", False),
                ("Neighbor BSSIDs", "Neighbor BSSIDs", False), ("RNR BSSIDs", "RNR BSSIDs", False),
                ("Mobility Domain", "Mobility Domain", False), ("Vendor/AP Name", "Vendor/AP Name", False),
            ])

        if self.handshake_rows:
            handshake_rows = []
            for row in self.handshake_rows:
                handshake_rows.append({
                    **row,
                    "GTK Available": "Yes" if self._has_value(row.get("GTK", "")) else "",
                })
            self._append_md_table_section(lines, "Handshakes", handshake_rows, [
                ("BSSID", "BSSID", True), ("Source", "Source", False), ("Destination", "Destination", False),
                ("EAPOL Message", "EAPOL Msg", False), ("PMKID", "PMKID", False),
                ("GTK Available", "GTK Available", False), ("Frame", "Frame", False),
            ])

        if self.ip_device_rows:
            lines.extend(["## IP Devices", ""])
            for row in self.ip_device_rows:
                ip = row.get("IP", "")
                profile = self.profiles.get(f"IP:{ip}", DeviceProfile(key=f"IP:{ip}"))
                lines.extend([f"### {self._md_code(ip)}", ""])
                inferred = self._best_device_type(profile)
                fields = [
                    ("MAC", profile.mac or row.get("MAC", ""), True),
                    ("Hostname", ", ".join(sorted(profile.hostnames)) or row.get("Hostnames", ""), False),
                    ("Device type", inferred, False), ("Scope", row.get("Scope", ""), False),
                    ("Role", ", ".join(sorted(profile.role_hints)) or row.get("Role Hints", ""), False),
                    ("DHCP server", row.get("DHCP Server", ""), True), ("Router", row.get("Router", ""), True),
                    ("DNS servers", row.get("DNS Servers", ""), True),
                    ("Management IP", ", ".join(sorted(profile.management_ips)), True),
                    ("Protocols", row.get("Protocols", ""), False),
                    ("Services", ", ".join(sorted(profile.services)), False),
                    ("DNS queries", ", ".join(sorted(profile.dns_queries)), False),
                    ("Reverse DNS queries", ", ".join(sorted(profile.reverse_dns_queries)), False),
                    ("Service discovery names", ", ".join(sorted(profile.service_discovery_names)), False),
                    ("NBNS/LLMNR names", ", ".join(sorted(profile.nbns_names)), False),
                    ("HTTP hosts", ", ".join(sorted(profile.http_hosts)), False),
                    ("HTTP URIs", ", ".join(sorted(profile.http_uris)), False),
                    ("TLS SNI", ", ".join(sorted(profile.tls_sni)), False),
                    ("Platform", profile.platform, False), ("Software", profile.software, False),
                ]
                self._append_md_fields(lines, fields)

        self._append_md_table_section(lines, "Open Services", self.open_service_rows, [
            ("IP", "IP", True), ("Port", "Port", True), ("Protocol", "Proto", False),
            ("State", "State", False), ("Service", "Service Hint", False),
        ])
        self._append_md_table_section(lines, "Confirmed HTTP Resources", self.http_uri_rows, [
            ("IP", "IP", True), ("Port", "Port", True), ("Host", "Host", False),
            ("Status", "Status", False), ("URI", "URI", True), ("Server", "Server", False),
        ])
        self._append_md_table_section(lines, "Passive Discovery", self.discovery_rows, [
            ("Protocol", "Protocol", True), ("MAC", "MAC", True), ("IP", "IP", True),
            ("Hostname/ID", "Hostname/ID", False), ("Platform/Model", "Platform/Model", False),
            ("Software/Firmware", "Software/Firmware", False), ("Port/Interface", "Port/Interface", False),
            ("Uptime/TTL", "Uptime/TTL", False), ("Role", "Role Hints", False),
        ])

        if self.credential_rows:
            safe_rows = []
            for row in self.credential_rows:
                safe_rows.append({**row, "Secret/Hash": self._mask_secret(row.get("Secret/Hash", ""))})
            lines.extend(["## Sensitive Findings", "", "> Sensitive HTTP credential material was observed. Secret values are masked in this report; preserve the JSON report securely if full forensic detail is required.", ""])
            lines.extend(self._md_table(safe_rows, [
                ("Source", "Source", True), ("Destination", "Destination", True), ("Host", "Host", False),
                ("Type", "Type", False), ("Username", "Username", False), ("Secret/Hash", "Secret/Hash", False),
                ("Field", "Field", False), ("Frame", "Frame", False),
            ]))
            lines.append("")

        notes = [message for message in self.messages if any(term in message.lower() for term in ["error", "warning", "returned", "not found", "does not expose", "skipping", "unavailable", "no ipv4", "no wlan"])]
        if notes:
            lines.extend(["## Analysis Notes and Limitations", ""])
            lines.extend(f"- {self._md_text(message)}" for message in dict.fromkeys(notes))
            lines.append("")

        lines.extend(["## Actions Taken", "", *[f"- {item}" for item in self._analysis_actions()], ""])
        path.write_text("\n".join(lines).rstrip() + "\n", encoding="utf-8")

    def export_selected_markdown(self, candidate: Candidate, path: Path) -> None:
        profile = self.profile_for(candidate)
        lines = [
            "---", "Author:", f"Date: {self._md_yaml(self.started_at)}",
            f"Title: {self._md_yaml(candidate.kind + ' Device Report')}",
            f"File Used: {self._md_yaml(self.source_file)}", "---", "",
            f"# {self._md_text(candidate.kind)} {self._md_code(candidate.value)}", "",
        ]
        fields = [
            ("Role", profile.role or candidate.kind, False), ("MAC", profile.mac, True),
            ("IP addresses", ", ".join(sorted(profile.ips)), True), ("Hostnames", ", ".join(sorted(profile.hostnames)), False),
            ("SSIDs", ", ".join(sorted(profile.ssids)), False), ("BSSIDs", ", ".join(sorted(profile.bssids)), True),
            ("Vendor", profile.vendor, False), ("Make", profile.make, False), ("Model", profile.model, False),
            ("Firmware", profile.firmware, False), ("Platform", profile.platform, False), ("Software", profile.software, False),
            ("Device type", self._best_device_type(profile), False), ("Services", ", ".join(sorted(profile.services)), False),
            ("Role hints", ", ".join(sorted(profile.role_hints)), False),
            ("DNS queries", ", ".join(sorted(profile.dns_queries)), False),
            ("Reverse DNS queries", ", ".join(sorted(profile.reverse_dns_queries)), False),
            ("Service discovery names", ", ".join(sorted(profile.service_discovery_names)), False),
            ("NBNS/LLMNR names", ", ".join(sorted(profile.nbns_names)), False),
            ("HTTP hosts", ", ".join(sorted(profile.http_hosts)), False),
            ("HTTP URIs", ", ".join(sorted(profile.http_uris)), False),
            ("TLS SNI", ", ".join(sorted(profile.tls_sni)), False),
        ]
        self._append_md_fields(lines, fields)
        if candidate.evidence:
            lines.extend(["## Evidence", ""])
            for evidence in candidate.evidence:
                count = f"; observed {evidence.count} times" if evidence.count > 1 else ""
                lines.append(f"- **{self._md_text(evidence.source)}:** {self._md_text(evidence.reason)}{count}")
            lines.append("")
        path.write_text("\n".join(lines).rstrip() + "\n", encoding="utf-8")

    def _append_client_section(self, lines: list[str], title: str, rows: list[dict[str, str]], profile_kind: str) -> None:
        if not rows:
            return
        report_rows = []
        for row in rows:
            mac = normalize_mac(row.get("MAC", ""))
            profile = self.profiles.get(f"{profile_kind}:{mac}") or self.profiles.get(f"MAC:{mac}") or DeviceProfile(key=f"{profile_kind}:{mac}")
            bssid = row.get("BSSID", "")
            bssid_profile = self.profiles.get(f"BSSID:{bssid}", DeviceProfile(key=f"BSSID:{bssid}"))
            report_rows.append({
                "MAC": mac, "BSSID": bssid, "SSID": ", ".join(sorted(profile.ssids or bssid_profile.ssids)),
                "Vendor": profile.vendor, "IPs": ", ".join(sorted(profile.ips)),
                "Device Type": self._best_device_type(profile), "Strongest RSSI": profile.strongest_rssi,
            })
        self._append_md_table_section(lines, title, report_rows, [
            ("MAC", "MAC", True), ("Associated BSSID", "BSSID", True), ("SSID", "SSID", False),
            ("Vendor", "Vendor", False), ("IP Addresses", "IPs", True),
            ("Device Type", "Device Type", False), ("Strongest RSSI", "Strongest RSSI", False),
        ])

    def _best_device_type(self, profile: DeviceProfile) -> str:
        if not profile.device_type_scores:
            return ""
        device_type, score = max(profile.device_type_scores.items(), key=lambda item: (item[1], item[0]))
        return f"{device_type} ({score}%)" if score > 70 else ""

    def _append_md_fields(self, lines: list[str], fields: list[tuple[str, str, bool]]) -> None:
        for label, value, code in fields:
            if not self._has_value(value):
                continue
            rendered = self._md_code(value) if code else self._md_text(value)
            lines.append(f"- **{label}:** {rendered}")
        lines.append("")

    def _append_md_table_section(self, lines: list[str], title: str, rows: list[dict[str, str]], columns: list[tuple[str, str, bool]]) -> None:
        if not rows:
            return
        table = self._md_table(rows, columns)
        if not table:
            return
        lines.extend([f"## {title}", "", *table, ""])

    def _md_table(self, rows: list[dict[str, str]], columns: list[tuple[str, str, bool]]) -> list[str]:
        active = [(label, key, code) for label, key, code in columns if any(self._has_value(row.get(key, "")) for row in rows)]
        if not active:
            return []
        output = ["| " + " | ".join(label for label, _, _ in active) + " |", "| " + " | ".join("---" for _ in active) + " |"]
        for row in rows:
            values = []
            for _, key, code in active:
                value = row.get(key, "")
                values.append(self._md_code(value) if code and self._has_value(value) else self._md_text(value) if self._has_value(value) else "")
            output.append("| " + " | ".join(values) + " |")
        return output

    def _analysis_actions(self) -> list[str]:
        actions = ["Enumerated observed access points, SSIDs, clients, security capabilities, and wireless topology.", "Parsed passive LLDP, CDP, and MNDP discovery information when present."]
        if self.analysis_level in {"moderate", "deep"}:
            actions.append("Analyzed cleartext IP hosts, DHCP/DNS identity clues, conversations, and responding services.")
            actions.append("Correlated confirming HTTP responses with their original requests and recorded representative URIs.")
        if self.analysis_level == "deep":
            actions.append("Attempted WPA/TK/GTK decryption and repeated IP/name analysis over decrypted traffic when keys were available.")
        return actions

    def _has_value(self, value: object) -> bool:
        return str(value or "").strip() not in {"", "-", "Unknown", "unknown", "None"}

    def _md_text(self, value: object) -> str:
        return re.sub(r"\s+", " ", str(value or "")).strip().replace("|", "\\|")

    def _md_code(self, value: object) -> str:
        text = self._md_text(value).replace("`", "\\`")
        return f"`{text}`" if text else ""

    def _md_yaml(self, value: object) -> str:
        return json.dumps(str(value or ""))

    def _with_unit(self, value: str, unit: str) -> str:
        value = str(value or "").strip()
        return f"{value} {unit}" if value and unit not in value else value

    def _mask_secret(self, value: str) -> str:
        value = str(value or "")
        if len(value) <= 8:
            return "*" * len(value)
        return value[:4] + "..." + value[-4:]


class TsharkRunner:
    def __init__(self, tshark_path: str = "tshark") -> None:
        self.tshark_path = tshark_path
        self._valid_fields: set[str] | None = None

    def exists(self) -> bool:
        return bool(shutil.which(self.tshark_path) or Path(self.tshark_path).exists())

    def valid_fields(self) -> set[str] | None:
        if self._valid_fields is not None:
            return self._valid_fields
        proc = subprocess.run(
            [self.tshark_path, "-G", "fields"],
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
        )
        if proc.returncode != 0:
            return None
        fields: set[str] = set()
        for line in proc.stdout.splitlines():
            parts = line.split("\t")
            if len(parts) >= 3 and parts[0] == "F":
                fields.add(parts[2])
        self._valid_fields = fields
        return self._valid_fields

    def has_field(self, field_name: str) -> bool:
        valid = self.valid_fields()
        return valid is None or field_name in valid

    def fields(
        self,
        file_path: str,
        display_filter: str,
        fields: list[str],
        decrypt: list[str] | None = None,
        occurrence: str = "f",
        aggregator: str = ",",
        quiet_missing: bool = False,
        two_pass: bool = False,
    ) -> tuple[list[dict[str, str]], list[str]]:
        messages: list[str] = []
        valid_fields = self.valid_fields()
        query_fields = fields
        if valid_fields:
            query_fields = [field_name for field_name in fields if field_name in valid_fields]
            missing_fields = [field_name for field_name in fields if field_name not in valid_fields]
            if missing_fields and not quiet_missing:
                messages.append(f"tshark does not expose these optional fields: {', '.join(missing_fields)}")
        command = [self.tshark_path, "-n", "-r", file_path]
        if two_pass:
            command.append("-2")
        command.extend(decrypt or [])
        command.extend(["-Y", display_filter, "-T", "fields", "-E", "separator=\t", "-E", f"occurrence={occurrence}"])
        if occurrence == "a" and aggregator:
            command.extend(["-E", f"aggregator={aggregator}"])
        for field_name in query_fields:
            command.extend(["-e", field_name])
        proc = subprocess.run(command, capture_output=True, text=True, encoding="utf-8", errors="replace")
        if proc.returncode not in (0,):
            messages.append(f"tshark returned {proc.returncode} for filter: {display_filter}")
            if proc.stderr.strip():
                messages.append(proc.stderr.strip())
        rows: list[dict[str, str]] = []
        reader = csv.reader(proc.stdout.splitlines(), delimiter="\t")
        for values in reader:
            padded = values + [""] * (len(query_fields) - len(values))
            row = {field_name: "" for field_name in fields}
            row.update(dict(zip(query_fields, padded[: len(query_fields)])))
            rows.append(row)
        return rows, messages


class APAnalyzer:
    def __init__(
        self,
        file_path: str,
        ssid: str = "",
        mac: str = "",
        ip: str = "",
        mac_role: str = "Unknown",
        password: str = "",
        temporal_key: str = "",
        analysis_level: str = "deep",
        tshark_path: str = "tshark",
    ) -> None:
        self.file_path = str(Path(file_path).expanduser())
        self.ssid = ssid.strip()
        self.mac = normalize_mac(mac)
        self.ip = normalize_ip(ip)
        self.mac_role = mac_role
        self.password = password
        self.temporal_key = temporal_key.strip()
        self.analysis_level = normalize_analysis_level(analysis_level)
        self.extracted_gtks: set[str] = set()
        self._seed_bssids: list[str] = []
        self.runner = TsharkRunner(tshark_path)
        self.result = AnalysisResult()
        self.result.source_file = self.file_path
        self.result.analysis_level = self.analysis_level
        self.result.target_ssid = self.ssid
        self.result.target_mac = self.mac
        self.result.target_ip = self.ip

    def _profile(self, kind: str, value: str) -> DeviceProfile:
        value = normalize_mac(value) if kind in {"BSSID", "Client", "Wired/Upstream", "MAC"} else normalize_ip(value) if kind == "IP" else value
        key = f"{kind}:{value}"
        profile = self.result.profiles.setdefault(key, DeviceProfile(key=key, role=kind))
        profile.role = kind
        if kind in {"BSSID", "Client", "Wired/Upstream", "MAC"}:
            profile.mac = value
            profile.vendor = profile.vendor or oui_prefix(value)
            if is_local_admin_mac(value):
                profile.warnings.add("MAC is locally administered; it may be randomized")
        elif kind == "SSID":
            profile.ssids.add(value)
        elif kind == "IP":
            profile.ips.add(value)
            profile.role_hints.add(ip_scope(value))
        elif kind == "Hostname":
            profile.hostnames.add(value)
        return profile

    def _update_radio_profile(self, profile: DeviceProfile, row: dict[str, str]) -> None:
        channel = row.get("wlan.ds.current_channel") or row.get("wlan.ht.info.primarychannel") or row.get("wlan_radio.channel", "")
        frequency = row.get("wlan_radio.frequency", "")
        rssi = row.get("radiotap.dbm_antsignal") or row.get("wlan_radio.signal_dbm", "")
        profile.merge_frame(row.get("frame.number", ""))
        profile.set_if_empty("channel", channel)
        if channel:
            profile.channels.add(channel)
        profile.set_if_empty("frequency", f"{frequency} MHz" if frequency and not frequency.endswith("MHz") else frequency)
        if frequency:
            profile.frequencies.add(f"{frequency} MHz" if not frequency.endswith("MHz") else frequency)
        if not profile.frequency and channel:
            profile.frequency = channel_to_frequency(channel)
        if profile.frequency:
            profile.frequencies.add(profile.frequency)
        profile.set_if_empty("band", frequency_to_band(profile.frequency, profile.channel))
        profile.set_if_empty("uptime", row.get("wlan.fixed.timestamp", ""))
        profile.add_rssi(rssi)

    def _profiles_for_mac(self, mac: str) -> list[DeviceProfile]:
        mac = normalize_mac(mac)
        profiles: list[DeviceProfile] = []
        for kind in ["Client", "Wired/Upstream", "MAC", "BSSID"]:
            key = f"{kind}:{mac}"
            if key in self.result.candidates or key in self.result.profiles:
                profiles.append(self._profile(kind, mac))
        if not profiles and is_mac(mac):
            profiles.append(self._profile("MAC", mac))
        return profiles

    def _new_fragment_analyzer(self) -> APAnalyzer:
        analyzer = APAnalyzer(
            file_path=self.file_path,
            ssid=self.ssid,
            mac=self.mac,
            ip=self.ip,
            mac_role=self.mac_role,
            password=self.password,
            temporal_key=self.temporal_key,
            analysis_level=self.analysis_level,
            tshark_path=self.runner.tshark_path,
        )
        analyzer.runner = self.runner
        analyzer.extracted_gtks = set(self.extracted_gtks)
        analyzer._seed_bssids = self._candidate_bssids()
        return analyzer

    def _run_isolated_tasks(self, tasks: list[tuple[str, str, tuple, dict]]) -> None:
        if not tasks:
            return

        def execute(task: tuple[str, str, tuple, dict]) -> tuple[str, AnalysisResult]:
            label, method_name, args, kwargs = task
            worker = self._new_fragment_analyzer()
            getattr(worker, method_name)(*args, **kwargs)
            return label, worker.result

        worker_count = min(3, len(tasks))
        if worker_count == 1:
            _, fragment = execute(tasks[0])
            self._merge_analysis_result(fragment)
            return
        if worker_count > 1:
            self.result.messages.append(f"Running {len(tasks)} independent tshark analysis passes with {worker_count} workers.")
        with ThreadPoolExecutor(max_workers=worker_count, thread_name_prefix="ap-analysis") as executor:
            futures = [executor.submit(execute, task) for task in tasks]
            for task, future in zip(tasks, futures):
                label = task[0]
                try:
                    _, fragment = future.result()
                except Exception as exc:
                    self.result.messages.append(f"Analysis pass failed ({label}): {exc}")
                    continue
                self._merge_analysis_result(fragment)

    def _coalesce_service_rows(self, rows: list[dict[str, str]]) -> list[dict[str, str]]:
        merged: dict[tuple[str, str, str, str], dict[str, str]] = {}
        for row in rows:
            key = tuple(row.get(field_name, "") for field_name in ["IP", "Port", "Proto", "State"])
            existing = merged.setdefault(key, dict(row))
            old_hint = existing.get("Service Hint", "")
            new_hint = row.get("Service Hint", "")
            if not new_hint or new_hint == old_hint:
                continue
            if old_hint and old_hint in new_hint:
                existing["Service Hint"] = new_hint
            elif new_hint not in old_hint:
                existing["Service Hint"] = " | ".join(part for part in [old_hint, new_hint] if part)
        return list(merged.values())

    def _merge_analysis_result(self, fragment: AnalysisResult) -> None:
        for candidate in fragment.sorted_candidates():
            target = self.result.candidates.setdefault(candidate.key, Candidate(kind=candidate.kind, value=candidate.value))
            target.labels.update(candidate.labels)
            target.related.update(candidate.related)
            for evidence in candidate.evidence:
                target.add_evidence(Evidence(evidence.source, evidence.reason, evidence.score, dict(evidence.fields), list(evidence.command), evidence.count))
        for key, profile in fragment.profiles.items():
            self._merge_device_profile(self.result.profiles.setdefault(key, DeviceProfile(key=key)), profile)
        row_attributes = [
            "ap_rows", "ap_observation_rows", "ssid_group_rows", "topology_rows", "discovery_rows",
            "credential_rows", "http_uri_rows", "client_rows", "ip_device_rows", "conversation_rows",
            "scan_rows", "service_rows", "open_service_rows", "closed_service_rows", "device_type_rows",
            "security_rows", "handshake_rows", "decrypted_rows",
        ]
        for attribute in row_attributes:
            getattr(self.result, attribute).extend(dict(row) for row in getattr(fragment, attribute))
        for message in fragment.messages:
            if message not in self.result.messages:
                self.result.messages.append(message)

    def _merge_device_profile(self, target: DeviceProfile, incoming: DeviceProfile) -> None:
        for field_name in incoming.__dataclass_fields__:
            if field_name == "key":
                continue
            source_value = getattr(incoming, field_name)
            target_value = getattr(target, field_name)
            if isinstance(source_value, set):
                target_value.update(source_value)
            elif isinstance(source_value, list):
                target_value.extend(source_value)
            elif isinstance(source_value, dict):
                if field_name == "device_type_scores":
                    for key, value in source_value.items():
                        target_value[key] = max(target_value.get(key, 0), value)
                else:
                    for key, value in source_value.items():
                        if isinstance(value, list):
                            existing = target_value.setdefault(key, [])
                            existing.extend(item for item in value if item not in existing)
                        else:
                            target_value.setdefault(key, value)
            elif field_name == "first_seen":
                target.first_seen = self._min_frame(target.first_seen, source_value)
            elif field_name == "last_seen":
                target.last_seen = self._max_frame(target.last_seen, source_value)
            elif field_name == "frame_count":
                target.frame_count = max(target.frame_count, source_value)
            elif source_value and not target_value:
                setattr(target, field_name, source_value)

    def analyze(self) -> AnalysisResult:
        self._record_user_inputs()
        if not Path(self.file_path).exists():
            self.result.messages.append(f"Capture file not found: {self.file_path}")
            return self.result
        if not self.runner.exists():
            self.result.messages.append("tshark was not found on PATH. Install Wireshark/tshark or enter a full tshark path.")
            return self.result

        has_wlan = self.runner.has_field("wlan.bssid")
        has_ip = self.runner.has_field("ip.src") or self.runner.has_field("arp.src.proto_ipv4")
        capture_mode = "mixed wireless/IP" if has_wlan and has_ip else "wireless monitor-mode" if has_wlan else "Ethernet/IP" if has_ip else "unknown"
        self.result.messages.append(f"Capture capability detected: {capture_mode}.")
        self.result.messages.append(f"Analysis level: {self.analysis_level.title()}.")

        if has_wlan:
            self._discover_aps()
            self._inspect_security_and_handshakes()
            self._classify_clients_and_upstream()
            self._inspect_topology()
        else:
            self.result.messages.append("No wlan.bssid field found; skipping monitor-mode wireless AP/client analysis.")

        tasks: list[tuple[str, str, tuple, dict]] = [
            ("passive discovery", "_inspect_discovery_protocols", (), {}),
        ]
        decrypted_tasks: list[tuple[str, str, tuple, dict]] = []
        if has_wlan and self.analysis_level == "deep":
            self._extract_gtks()

        if self.analysis_level in {"moderate", "deep"} and has_ip:
            tasks.extend([
                ("cleartext IP and identity", "_inspect_ip_traffic", (), {}),
                ("cleartext HTTP services", "_inspect_http_services", (), {}),
            ])
            decrypt = self._decrypt_options() if has_wlan and self.analysis_level == "deep" else []
            if decrypt:
                key_sources = []
                if self.password and self.ssid:
                    key_sources.append("SSID/password")
                if self.temporal_key:
                    key_sources.append("manual TK/GTK")
                if self.extracted_gtks:
                    key_sources.append(f"{len(self.extracted_gtks)} extracted GTK(s)")
                self.result.messages.append(f"Running decrypted IP/name analysis using: {', '.join(key_sources)}.")
                decrypted_tasks.extend([
                    ("decrypted frame inventory", "_inspect_decrypted_traffic", (), {}),
                    ("decrypted IP and identity", "_inspect_ip_traffic", (), {"decrypt": decrypt, "source_label": "decrypted"}),
                    ("decrypted HTTP services", "_inspect_http_services", (), {"decrypt": decrypt, "source_label": "decrypted"}),
                ])
        else:
            if self.analysis_level == "basic":
                self.result.messages.append("Basic analysis selected; skipping IP host, service, credential, and decryption analysis.")
            else:
                self.result.messages.append("No IPv4/ARP fields found; skipping IP device analysis.")
        self._run_isolated_tasks(tasks)
        self._run_isolated_tasks(decrypted_tasks)
        self.result.ap_observation_rows = uniq_rows(self.result.ap_observation_rows)
        self.result.ap_rows = self._summarize_ap_rows()
        self.result.ssid_group_rows = self._build_ssid_groups()
        self.result.topology_rows = uniq_rows(self.result.topology_rows)
        self.result.discovery_rows = uniq_rows(self.result.discovery_rows)
        self.result.credential_rows = uniq_rows(self.result.credential_rows)
        self.result.http_uri_rows = uniq_rows(self.result.http_uri_rows)
        self.result.client_rows = uniq_rows(self.result.client_rows)
        self.result.ip_device_rows = self._summarize_ip_devices()
        self.result.conversation_rows = uniq_rows(self.result.conversation_rows)
        self.result.scan_rows = uniq_rows(self.result.scan_rows)
        self.result.service_rows = uniq_rows(self._coalesce_service_rows(self.result.service_rows))
        self.result.open_service_rows = uniq_rows(self._coalesce_service_rows(self.result.open_service_rows))
        self.result.closed_service_rows = uniq_rows(self._coalesce_service_rows(self.result.closed_service_rows))
        self.result.security_rows = uniq_rows(self.result.security_rows)
        self.result.handshake_rows = uniq_rows(self.result.handshake_rows)
        self.result.decrypted_rows = uniq_rows(self.result.decrypted_rows)
        self._finalize_profiles()
        self.result.device_type_rows = self._build_device_type_rows()
        return self.result

    def _summarize_ap_rows(self) -> list[dict[str, str]]:
        by_bssid: dict[str, list[dict[str, str]]] = {}
        for row in self.result.ap_observation_rows:
            bssid = row.get("BSSID", "")
            if bssid:
                by_bssid.setdefault(bssid, []).append(row)
        summaries: list[dict[str, str]] = []
        security_by_bssid = {row.get("BSSID", ""): row for row in self.result.security_rows}
        handshakes_by_bssid: dict[str, set[str]] = {}
        for row in self.result.handshake_rows:
            bssid = row.get("BSSID", "")
            marker = "PMKID" if row.get("PMKID") else f"EAPOL {row.get('EAPOL Msg', '').strip()}".strip()
            if bssid and marker:
                handshakes_by_bssid.setdefault(bssid, set()).add(marker)
        for bssid, rows in by_bssid.items():
            candidate = self.result.candidates.get(f"BSSID:{bssid}")
            profile = self._profile("BSSID", bssid)
            ssids = sorted({row.get("SSID", "") for row in rows if row.get("SSID", "")})
            channels = [row.get("Channel", "") for row in rows if row.get("Channel", "")]
            freqs = [row.get("Frequency", "") for row in rows if row.get("Frequency", "")]
            rssi_values: list[int] = []
            for row in rows:
                try:
                    rssi_values.append(int(float(row.get("RSSI", ""))))
                except (TypeError, ValueError):
                    pass
            channel = Counter(channels).most_common(1)[0][0] if channels else ""
            frequency = Counter(freqs).most_common(1)[0][0] if freqs else channel_to_frequency(channel)
            best_rssi = f"{max(rssi_values)}" if rssi_values else ""
            avg_rssi = f"{round(sum(rssi_values) / len(rssi_values), 1)}" if rssi_values else ""
            security = security_by_bssid.get(bssid, {})
            encryption = security.get("Pairwise Cipher", "")
            akm = security.get("AKM", "")
            security_summary = " ".join(part for part in [akm, encryption] if part) or "Unknown"
            handshake_summary = ", ".join(sorted(handshakes_by_bssid.get(bssid, set()))) or "-"
            reasons = sorted({row.get("Why", "") for row in rows if row.get("Why", "")})
            summaries.append(
                {
                    "Rank": self._rank_for(candidate),
                    "BSSID": bssid,
                    "SSIDs": ", ".join(ssids) or "-",
                    "Channel": channel,
                    "All Channels": ", ".join(sorted(profile.channels, key=self._sort_number_text)) or ", ".join(sorted(set(channels), key=self._sort_number_text)),
                    "Band": frequency_to_band(frequency, channel),
                    "Frequency": frequency,
                    "All Freqs": ", ".join(sorted(profile.frequencies, key=self._sort_number_text)) or ", ".join(sorted(set(freqs), key=self._sort_number_text)),
                    "Best RSSI": best_rssi,
                    "Avg RSSI": avg_rssi,
                    "Security": security_summary,
                    "Handshakes": handshake_summary,
                    "Sightings": str(len(rows)),
                    "First Frame": profile.first_seen,
                    "Last Frame": profile.last_seen,
                    "Manufacturer": next((row.get("Manufacturer", "") for row in rows if row.get("Manufacturer", "")), ""),
                    "Model": next((row.get("Model", "") for row in rows if row.get("Model", "")), ""),
                    "Why": "; ".join(reasons[:3]),
                }
            )
        return sorted(summaries, key=lambda row: (self._rank_sort(row.get("Rank", "")), row.get("BSSID", "")))

    def _build_ssid_groups(self) -> list[dict[str, str]]:
        groups: dict[str, list[dict[str, str]]] = {}
        for row in self.result.ap_rows:
            for ssid in [part.strip() for part in row.get("SSIDs", "").split(",") if part.strip() and part.strip() != "-"]:
                groups.setdefault(ssid, []).append(row)
        output: list[dict[str, str]] = []
        for ssid, rows in groups.items():
            output.append(
                {
                    "SSID": ssid,
                    "BSSIDs": ", ".join(row.get("BSSID", "") for row in rows),
                    "Bands": ", ".join(sorted({row.get("Band", "") for row in rows if row.get("Band", "")})),
                    "Channels": ", ".join(sorted({row.get("Channel", "") for row in rows if row.get("Channel", "")}, key=self._sort_number_text)),
                    "Best RSSI": max((row.get("Best RSSI", "") for row in rows), key=lambda value: self._sort_number_text(value)[0], default=""),
                    "AP Count": str(len(rows)),
                    "Ranks": ", ".join(sorted({row.get("Rank", "") for row in rows if row.get("Rank", "")})),
                }
            )
        return sorted(output, key=lambda row: row.get("SSID", ""))

    def _rank_for(self, candidate: Candidate | None) -> str:
        if not candidate:
            return "Possible"
        labels = candidate.labels
        if "exact-mac" in labels or "exact-ssid" in labels:
            return "Primary"
        if candidate.confidence >= 70:
            return "Related"
        if candidate.confidence >= 30:
            return "Possible"
        return "Weak"

    def _rank_sort(self, rank: str) -> int:
        return {"Primary": 0, "Related": 1, "Possible": 2, "Weak": 3}.get(rank, 9)

    def _sort_number_text(self, value: str) -> tuple[int, str]:
        match = re.search(r"-?\d+(?:\.\d+)?", str(value))
        return (int(float(match.group(0))) if match else 999999, str(value))

    def _finalize_profiles(self) -> None:
        for candidate in self.result.candidates.values():
            profile = self.result.profile_for(candidate)
            profile.frame_count = max(profile.frame_count, sum(ev.count for ev in candidate.evidence))
            if not profile.frequency and profile.channel:
                profile.frequency = channel_to_frequency(profile.channel)
            if profile.channel:
                profile.channels.add(profile.channel)
            if profile.frequency:
                profile.frequencies.add(profile.frequency)
            if not profile.band:
                profile.band = frequency_to_band(profile.frequency, profile.channel)
            if candidate.kind == "BSSID" and not profile.encryption:
                profile.warnings.add("Encryption/security details were not found for this AP candidate")
            if not profile.strongest_rssi:
                profile.warnings.add("RSSI unavailable; capture may not include radiotap/radio metadata")
            if candidate.kind in {"Client", "Wired/Upstream", "MAC"} and not profile.bssids:
                profile.warnings.add("No target BSSID relationship was confirmed for this MAC")
            self._infer_device_types(candidate, profile)

    def _add_device_type(self, profile: DeviceProfile, device_type: str, score: int, evidence: str) -> None:
        profile.device_type_scores[device_type] = min(100, profile.device_type_scores.get(device_type, 0) + score)
        evidence_list = profile.device_type_evidence.setdefault(device_type, [])
        if evidence not in evidence_list:
            evidence_list.append(evidence)

    def _infer_device_types(self, candidate: Candidate, profile: DeviceProfile) -> None:
        profile.device_type_scores.clear()
        profile.device_type_evidence.clear()
        text_parts = [
            profile.vendor,
            profile.make,
            profile.model,
            profile.platform,
            profile.software,
            profile.mac,
            " ".join(profile.hostnames),
            " ".join(profile.dns_queries),
            " ".join(profile.service_discovery_names),
            " ".join(profile.nbns_names),
            " ".join(profile.services),
            " ".join(profile.discovery_protocols),
            " ".join(profile.protocols),
            " ".join(profile.role_hints),
            " ".join(profile.topology_roles),
            " ".join(profile.mesh_ids),
            " ".join(profile.vendor_ap_names),
            " ".join(profile.vendor_mesh_clues),
            " ".join(profile.dhcp_vendor_classes),
            " ".join(profile.dhcp_servers),
            " ".join(profile.dhcp_routers),
            " ".join(profile.dhcp_dns_servers),
            " ".join(profile.http_hosts),
            " ".join(profile.http_uris),
            " ".join(profile.http_user_agents),
            " ".join(profile.http_servers),
            " ".join(profile.tls_sni),
        ]
        text = " ".join(part for part in text_parts if part).lower()
        services = " ".join(profile.services).lower()
        protocols = {proto.upper() for proto in profile.protocols}
        vendor = (profile.vendor or "").lower()

        if candidate.kind == "BSSID" or "candidate-ap" in candidate.labels:
            self._add_device_type(profile, "Access point", 70, "Device is observed as a BSSID/AP candidate")
        if profile.mesh_ids or any("mesh" in role.lower() for role in profile.topology_roles):
            self._add_device_type(profile, "Mesh node using wireless backhaul", 65, "802.11s mesh or vendor mesh topology evidence")
            self._add_device_type(profile, "Access point", 25, "Mesh topology evidence belongs to AP infrastructure")
        if profile.wds_peers:
            self._add_device_type(profile, "Mesh node with Ethernet backhaul", 25, "WDS/four-address backhaul relationship observed")
            self._add_device_type(profile, "Wireless repeater", 35, "Four-address wireless distribution/backhaul clue")
        if profile.neighbor_bssids or profile.rnr_bssids or profile.mobility_domains:
            self._add_device_type(profile, "Access point", 35, "Neighbor report/RNR/mobility-domain AP ecosystem clue")
        if "wireless client" in profile.role_hints:
            for dtype in ["Laptop", "Smartphone", "Tablet"]:
                self._add_device_type(profile, dtype, 18, "Wireless client behavior without stronger device-specific clues")
        if "wired/upstream/local LAN source" in profile.role_hints:
            for dtype in ["Router", "Server", "Desktop PC"]:
                self._add_device_type(profile, dtype, 15, "Wired/upstream local LAN source behavior")

        rules: list[tuple[str, int, list[str], str]] = [
            ("Network printer", 55, ["_ipp._tcp", "_printer", "ipp", "9100/tcp open", "631/tcp open", "515/tcp open", "printer", "brother", "canon", "epson", "laserjet", "officejet"], "Printing protocol/name/vendor clue"),
            ("NAS", 45, ["synology", "qnap", "truenas", "freenas", "nas", "afp", "nfs", "smb", "445/tcp open", "548/tcp open", "2049/tcp open"], "Storage/SMB/NAS clue"),
            ("Server", 35, ["22/tcp open", "80/tcp open", "443/tcp open", "8080/tcp open", "8443/tcp open", "linux", "ubuntu", "debian", "centos", "nginx", "apache"], "Server-like open service or software clue"),
            ("Desktop PC", 35, ["445/tcp open", "3389/tcp open", "netbios", "nbns", "workstation", "windows", "microsoft"], "Workstation/Windows/SMB clue"),
            ("VoIP phone", 60, ["sip", "5060", "5061", "polycom", "yealink", "grandstream", "cisco ip phone", "voip"], "VoIP protocol/vendor clue"),
            ("IP camera", 55, ["rtsp", "554/tcp open", "8554/tcp open", "onvif", "hikvision", "dahua", "axis", "camera", "doorbell"], "Camera streaming/vendor clue"),
            ("NVR/DVR", 55, ["nvr", "dvr", "hikvision", "dahua", "blueiris", "surveillance", "37777/tcp open", "8000/tcp open"], "Video recorder/surveillance clue"),
            ("Smart TV", 50, ["mediarenderer", "dlna", "dIAL", "roku", "samsungtv", "lg smart", "bravia", "vizio", "airplay", "_airplay._tcp"], "Media renderer/TV discovery clue"),
            ("Streaming stick", 55, ["googlecast", "chromecast", "roku", "firetv", "airplay", "_googlecast._tcp", "8008/tcp open", "8009/tcp open"], "Casting/streaming discovery clue"),
            ("Game console", 45, ["xbox", "playstation", "nintendo", "ps5", "ps4", "xboxone"], "Game-console hostname/vendor clue"),
            ("Router", 45, ["router", "gateway", "internetgatewaydevice", "dns server", "dhcp server", "53/udp response", "67/udp response"], "Gateway/DNS/DHCP behavior clue"),
            ("Firewall", 35, ["firewall", "pfsense", "opnsense", "fortinet", "sonicwall", "palo alto"], "Firewall vendor/name clue"),
            ("Switch", 35, ["switch", "lldp", "cdp", "procurve", "aruba", "catalyst"], "Switch/vendor/discovery clue"),
            ("Raspberry Pi / SBC", 55, ["raspberry", "raspberry pi", "rpi", "raspbian", "octopi"], "SBC hostname/vendor clue"),
            ("Smart speaker", 50, ["alexa", "echo", "sonos", "homepod", "google home", "speaker"], "Smart speaker discovery/name clue"),
            ("Smart display", 45, ["nest hub", "echo show", "smart display", "googlecast"], "Smart display/casting clue"),
            ("Thermostat", 55, ["thermostat", "ecobee", "nest thermostat", "honeywell"], "Thermostat name/vendor clue"),
            ("Smart plug", 45, ["smartplug", "smart plug", "kasa", "tplink-smarthome", "wemo"], "Smart plug name/vendor clue"),
            ("Smart bulb", 45, ["hue", "lifx", "bulb", "lighting"], "Smart lighting discovery/name clue"),
            ("Smart hub/bridge", 45, ["bridge", "hub", "zigbee", "zwave", "hue bridge", "smartthings"], "Smart home bridge/hub clue"),
            ("Robot vacuum", 55, ["roomba", "irobot", "vacuum", "robovac"], "Robot vacuum name/vendor clue"),
            ("POS terminal", 45, ["pos", "verifone", "ingenico", "payment", "terminal"], "Payment/POS name/vendor clue"),
            ("Thin client", 40, ["thinclient", "wyse", "igel", "citrix"], "Thin-client name/vendor clue"),
            ("UPS network card", 45, ["ups", "apc", "tripplite", "eaton"], "UPS vendor/name clue"),
            ("Hypervisor host", 45, ["vmware", "esxi", "hyper-v", "proxmox", "xenserver"], "Hypervisor name/vendor clue"),
            ("Virtual machine", 40, ["vmware", "virtualbox", "qemu", "kvm", "parallels", "hyper-v"], "Virtualization OUI/name clue"),
            ("Media server", 45, ["plex", "jellyfin", "emby", "dlna", "mediaserver"], "Media server service/name clue"),
        ]
        for dtype, score, needles, evidence in rules:
            matches = [needle for needle in needles if needle.lower() in text or needle.lower() in services]
            if matches:
                self._add_device_type(profile, dtype, min(90, score + min(25, (len(matches) - 1) * 6)), f"{evidence}: {', '.join(matches[:5])}")

        if "Apple".lower() in vendor or any(x in text for x in ["iphone", "ipad", "macbook", "ios", "darwin"]):
            if any(x in text for x in ["iphone", "ios"]):
                self._add_device_type(profile, "Smartphone", 65, "Apple/iPhone/iOS clue")
            if any(x in text for x in ["ipad"]):
                self._add_device_type(profile, "Tablet", 65, "Apple/iPad clue")
            if any(x in text for x in ["macbook", "imac", "macos", "darwin"]):
                self._add_device_type(profile, "Laptop", 45, "Apple macOS clue")
        if any(x in text for x in ["android", "samsung", "pixel", "oneplus"]):
            self._add_device_type(profile, "Smartphone", 45, "Android/mobile vendor or hostname clue")
        if profile.discovery_protocols and not profile.device_type_scores:
            for dtype in ["Router", "Switch", "Access point"]:
                self._add_device_type(profile, dtype, 20, "Passive discovery protocol advertised infrastructure identity")
        if "TCP service responder" in profile.role_hints and not profile.device_type_scores:
            self._add_device_type(profile, "Server", 25, "Responds with open TCP service but lacks device-specific clues")
        if "scanner" in profile.role_hints:
            self._add_device_type(profile, "Desktop PC", 20, "Scan behavior often originates from an admin workstation")

    def _top_device_types(self, profile: DeviceProfile, limit: int = 10) -> list[tuple[str, int, list[str]]]:
        return [
            (dtype, score, profile.device_type_evidence.get(dtype, []))
            for dtype, score in sorted(profile.device_type_scores.items(), key=lambda item: (-item[1], item[0]))[:limit]
        ]

    def _build_device_type_rows(self) -> list[dict[str, str]]:
        rows: list[dict[str, str]] = []
        for candidate in self.result.sorted_candidates():
            profile = self.result.profile_for(candidate)
            top = self._top_device_types(profile, 10)
            if not top:
                continue
            best_type, best_score, best_evidence = top[0]
            rows.append(
                {
                    "Kind": candidate.kind,
                    "Value": candidate.value,
                    "Best Guess": best_type,
                    "Confidence": f"{best_score}%",
                    "Alternatives": ", ".join(f"{dtype} {score}%" for dtype, score, _ in top[1:5]),
                    "Top Evidence": "; ".join(best_evidence[:3]),
                }
            )
        return rows

    def _record_user_inputs(self) -> None:
        if self.ssid:
            self.result.add_candidate(
                "SSID",
                self.ssid,
                Evidence("User input", "SSID supplied by user; exact and partial SSID searches will be anchored to it.", 25),
                labels=["input"],
            )
        if self.mac:
            kind = "MAC" if self.mac_role == "Unknown" else self.mac_role
            self.result.add_candidate(
                kind,
                self.mac,
                Evidence("User input", f"MAC supplied by user with role set to {self.mac_role}.", 25),
                labels=["input"],
            )
        if self.ip:
            self.result.add_candidate(
                "IP",
                self.ip,
                Evidence("User input", "IP supplied by user; Ethernet/IP traffic searches will be anchored to it.", 25),
                labels=["input"],
            )

    def _base_filters(self) -> list[tuple[str, str, int]]:
        filters: list[tuple[str, str, int]] = []
        if self.ssid:
            ssid = escape_filter_string(self.ssid)
            filters.append((f'wlan.ssid == "{ssid}"', "exact SSID match", 55))
            filters.append((f'wlan.ssid contains "{ssid}"', "SSID contains user text", 35))
        if self.mac and is_mac(self.mac):
            filters.append((f"wlan.addr == {self.mac}", "exact MAC seen in wlan.addr", 50))
            filters.append((f"wlan.bssid == {self.mac}", "MAC appears as BSSID", 60))
            middle = bssid_middle_octets(self.mac)
            if middle:
                filters.append((f"wlan.addr[1:3] == {middle}", "middle octets match supplied MAC", 30))
        if not filters:
            filters.append(("(wlan.fc.type_subtype == 0x08 || wlan.fc.type_subtype == 0x05)", "no identifier supplied; listing beacon/probe-response APs", 10))
        return filters

    def _filter_or(self) -> str:
        return " || ".join(f"({item[0]})" for item in self._base_filters())

    def _discover_aps(self) -> None:
        fields = [
            "frame.number",
            "wlan.bssid",
            "wlan.ssid",
            "wlan.fc.type_subtype",
            "wlan.ds.current_channel",
            "wlan.ht.info.primarychannel",
            "wlan_radio.channel",
            "wlan_radio.frequency",
            "wlan_radio.signal_dbm",
            "radiotap.dbm_antsignal",
            "wlan.fixed.timestamp",
            "wps.manufacturer",
            "wps.model_name",
            "wps.model_number",
            "wps.serial_number",
            "wps.device_name",
        ]
        display_filter = self._filter_or()
        rows, messages = self.runner.fields(self.file_path, display_filter, fields)
        self.result.messages.extend(messages)
        for row in rows:
            bssid = normalize_mac(row.get("wlan.bssid", ""))
            ssid = decode_ssid(row.get("wlan.ssid", ""))
            if not bssid or is_noise_mac(bssid):
                continue

            reasons = self._matching_reasons(bssid, ssid)
            reason_text = "; ".join(reason for reason, _ in reasons) or "AP appeared in frames matching the broad search filter."
            score = max([score for _, score in reasons], default=20)
            ev = Evidence("AP discovery", reason_text, score, row, [self.runner.tshark_path, "-n", "-r", self.file_path, "-Y", display_filter])
            labels = ["candidate-ap"]
            if self.mac and bssid == self.mac:
                labels.append("exact-mac")
            if self.ssid and ssid == self.ssid:
                labels.append("exact-ssid")
            self.result.add_candidate("BSSID", bssid, ev, labels=labels, related=[ssid] if ssid else [])
            if ssid:
                self.result.add_candidate("SSID", ssid, ev, labels=["observed-ssid"], related=[bssid])
            profile = self._profile("BSSID", bssid)
            profile.bssids.add(bssid)
            profile.ssids.add(ssid)
            profile.set_if_empty("make", row.get("wps.manufacturer", ""))
            profile.set_if_empty("model", row.get("wps.model_name", "") or row.get("wps.model_number", ""))
            self._update_radio_profile(profile, row)
            ssid_profile = self._profile("SSID", ssid)
            ssid_profile.bssids.add(bssid)
            ssid_profile.ssids.add(ssid)
            self._update_radio_profile(ssid_profile, row)

            self.result.ap_observation_rows.append(
                {
                    "BSSID": bssid,
                    "SSID": ssid,
                    "Channel": row.get("wlan.ds.current_channel") or row.get("wlan.ht.info.primarychannel") or row.get("wlan_radio.channel", ""),
                    "HT Primary": row.get("wlan.ht.info.primarychannel", ""),
                    "Frequency": row.get("wlan_radio.frequency", ""),
                    "RSSI": row.get("radiotap.dbm_antsignal") or row.get("wlan_radio.signal_dbm", ""),
                    "Manufacturer": row.get("wps.manufacturer", ""),
                    "Model": row.get("wps.model_name", ""),
                    "Device": row.get("wps.device_name", ""),
                    "Why": reason_text,
                }
            )

    def _matching_reasons(self, bssid: str, ssid: str) -> list[tuple[str, int]]:
        reasons: list[tuple[str, int]] = []
        if self.ssid:
            if ssid == self.ssid:
                reasons.append(("SSID exactly matches user input", 65))
            elif self.ssid.lower() in ssid.lower():
                reasons.append(("SSID contains user input", 45))
        if self.mac and is_mac(self.mac):
            if bssid == self.mac:
                reasons.append(("BSSID exactly matches the supplied MAC", 75))
            middle = bssid_middle_octets(self.mac)
            if middle and bssid_middle_octets(bssid) == middle:
                reasons.append(("BSSID middle octets match supplied MAC", 35))
        return reasons

    def _candidate_bssids(self) -> list[str]:
        values = list(self._seed_bssids)
        values.extend(c.value for c in self.result.sorted_candidates() if c.kind == "BSSID" and is_mac(c.value) and c.value not in values)
        if self.mac and self.mac_role == "BSSID" and is_mac(self.mac) and self.mac not in values:
            values.append(self.mac)
        return values[:30]

    def _bssid_filter(self) -> str:
        bssids = self._candidate_bssids()
        if bssids:
            return " || ".join(f"wlan.bssid == {bssid}" for bssid in bssids)
        return self._filter_or()

    def _inspect_security_and_handshakes(self) -> None:
        display_filter = f"({self._bssid_filter()}) && (wlan.fc.type_subtype == 0x05 || wlan.fc.type_subtype == 0x08)"
        fields = ["wlan.bssid", "wlan.rsn.pcs.type", "wlan.rsn.akms.type", "wlan.rsn.capabilities.mfpr", "wlan.rsn.capabilities.mfpc"]
        rows, messages = self.runner.fields(self.file_path, display_filter, fields)
        self.result.messages.extend(messages)
        for row in rows:
            bssid = normalize_mac(row.get("wlan.bssid", ""))
            if is_noise_mac(bssid):
                continue
            cipher = decode_csv_values(row.get("wlan.rsn.pcs.type", ""), cipher_name)
            akm = decode_csv_values(row.get("wlan.rsn.akms.type", ""), akm_name)
            sec_row = {
                "BSSID": bssid,
                "Pairwise Cipher": cipher,
                "AKM": akm,
                "MFPR": row.get("wlan.rsn.capabilities.mfpr", ""),
                "MFPC": row.get("wlan.rsn.capabilities.mfpc", ""),
            }
            self.result.security_rows.append(sec_row)
            self.result.add_candidate(
                "BSSID",
                bssid,
                Evidence("Security inspection", f"Security parameters were advertised for this BSSID: {cipher or 'unknown cipher'} / {akm or 'unknown AKM'}.", 15, row),
                labels=["security-seen"],
            )
            profile = self._profile("BSSID", bssid)
            profile.set_if_empty("encryption", cipher)
            profile.set_if_empty("akm", akm)
            if row.get("wlan.rsn.capabilities.mfpr"):
                profile.warnings.add(f"MFP required: {row.get('wlan.rsn.capabilities.mfpr')}")
            if row.get("wlan.rsn.capabilities.mfpc"):
                profile.warnings.add(f"MFP capable: {row.get('wlan.rsn.capabilities.mfpc')}")

        hs_filter = f"({self._bssid_filter()}) && (eapol || wlan.rsn.ie.pmkid)"
        hs_fields = ["frame.number", "wlan.bssid", "wlan.sa", "wlan.da", "wlan_rsna_eapol.keydes.msgnr", "wlan.rsn.ie.pmkid", "wlan.rsn.ie.gtk_kde.gtk"]
        rows, messages = self.runner.fields(self.file_path, hs_filter, hs_fields)
        self.result.messages.extend(messages)
        for row in rows:
            bssid = normalize_mac(row.get("wlan.bssid", ""))
            if is_noise_mac(bssid):
                continue
            msg = row.get("wlan_rsna_eapol.keydes.msgnr", "")
            pmkid = row.get("wlan.rsn.ie.pmkid", "")
            gtk = clean_hex(row.get("wlan.rsn.ie.gtk_kde.gtk", ""))
            why = "PMKID observed" if pmkid else f"EAPOL handshake message {msg or 'observed'}"
            if gtk:
                why = f"{why}; GTK KDE decrypted"
            self.result.handshake_rows.append(
                {
                    "Frame": row.get("frame.number", ""),
                    "BSSID": bssid,
                    "Source": normalize_mac(row.get("wlan.sa", "")),
                    "Destination": normalize_mac(row.get("wlan.da", "")),
                    "EAPOL Msg": msg,
                    "PMKID": pmkid,
                    "GTK": gtk,
                    "Why": why,
                }
            )
            self.result.add_candidate("BSSID", bssid, Evidence("Handshake/PMKID", why, 25, row), labels=["handshake"])
            profile = self._profile("BSSID", bssid)
            if msg:
                profile.handshakes.add(f"EAPOL message {msg}")
            if pmkid:
                profile.pmkids.add(pmkid)
            if gtk:
                self.extracted_gtks.add(gtk)
                profile.services.add(f"GTK {gtk[:8]}...")

    def _classify_clients_and_upstream(self) -> None:
        display_filter = f"({self._bssid_filter()}) && wlan.fc.type == 2"
        fields = ["frame.number", "wlan.bssid", "wlan.ta", "wlan.ra", "wlan.sa", "wlan.da", "wlan.fc.ds", "wlan_radio.channel", "wlan_radio.frequency", "wlan_radio.signal_dbm", "radiotap.dbm_antsignal"]
        rows, messages = self.runner.fields(self.file_path, display_filter, fields)
        self.result.messages.extend(messages)
        known_bssids = set(self._candidate_bssids())
        wireless_seen: dict[tuple[str, str], dict[str, str]] = {}
        upstream_seen: dict[tuple[str, str], dict[str, str]] = {}

        for row in rows:
            bssid = normalize_mac(row.get("wlan.bssid", ""))
            ds = row.get("wlan.fc.ds", "")
            if is_noise_mac(bssid):
                continue
            if ds == "0x01":
                client = normalize_mac(row.get("wlan.ta", ""))
                upstream = normalize_mac(row.get("wlan.da", ""))
                if not is_noise_mac(client) and client not in known_bssids:
                    wireless_seen.setdefault((bssid, client), row)
                if not is_noise_mac(upstream) and upstream not in known_bssids:
                    upstream_seen.setdefault((bssid, upstream), row)
            elif ds == "0x02":
                client = normalize_mac(row.get("wlan.ra", ""))
                upstream = normalize_mac(row.get("wlan.sa", ""))
                if not is_noise_mac(client) and client not in known_bssids:
                    wireless_seen.setdefault((bssid, client), row)
                if not is_noise_mac(upstream) and upstream not in known_bssids:
                    upstream_seen.setdefault((bssid, upstream), row)

        wireless_clients = {client for _, client in wireless_seen}
        for (bssid, client), row in sorted(wireless_seen.items()):
            reason = "Station address appeared as transmitter to DS or receiver from DS for the target BSSID."
            self.result.client_rows.append({"BSSID": bssid, "MAC": client, "Role": "Wireless client", "Why": reason})
            self.result.add_candidate("Client", client, Evidence("Client classification", reason, 35, {"BSSID": bssid, "MAC": client}), labels=["wireless-client"], related=[bssid])
            profile = self._profile("Client", client)
            profile.bssids.add(bssid)
            profile.role_hints.add("wireless client")
            bssid_profile = self._profile("BSSID", bssid)
            profile.ssids.update(bssid_profile.ssids)
            if is_local_admin_mac(client):
                profile.warnings.add("Client MAC is locally administered; it may be randomized")
            self._update_radio_profile(profile, row)

        for (bssid, mac), row in sorted(upstream_seen.items()):
            if mac in wireless_clients:
                continue
            reason = "Address appeared on the distribution/network side and was not also seen as a wireless station."
            self.result.client_rows.append({"BSSID": bssid, "MAC": mac, "Role": "Wired/Upstream", "Why": reason})
            self.result.add_candidate("Wired/Upstream", mac, Evidence("Upstream classification", reason, 25, {"BSSID": bssid, "MAC": mac}), labels=["wired-or-upstream"], related=[bssid])
            profile = self._profile("Wired/Upstream", mac)
            profile.bssids.add(bssid)
            profile.role_hints.add("wired/upstream/local LAN source")
            bssid_profile = self._profile("BSSID", bssid)
            profile.ssids.update(bssid_profile.ssids)
            self._update_radio_profile(profile, row)

    def _inspect_topology(self) -> None:
        display_filter = self._topology_display_filter()
        fields = [
            "frame.number", "wlan.bssid", "wlan.sa", "wlan.da", "wlan.ta", "wlan.ra", "wlan.addr",
            "wlan.fc.type_subtype", "wlan.fc.tods", "wlan.fc.fromds", "wlan.fc.ds",
            "wlan.mesh.id", "wlan.mesh.config.cap.forwarding", "wlan.mesh.config.formation_info.num_peers",
            "wlan.mesh.formation_info.connect_to_as", "wlan.mesh.formation_info.connect_to_mesh_gate",
            "wlan.fixed.mesh_action", "wlan.fixed.mesh_addr4", "wlan.fixed.mesh_addr5", "wlan.fixed.mesh_addr6",
            "wlan.fixed.mesh_ttl", "wlan.fixed.metric", "wlan.fixed.rreqid", "wlan.fixed.selfprot_action",
            "wlan.fixed.category_code", "wlan.hwmp.orig_sta", "wlan.hwmp.targ_sta", "wlan.hwmp.metric",
            "wlan.hwmp.hopcount", "wlan.hwmp.ttl", "wlan.peering.local_id", "wlan.peering.peer_id",
            "wlan.peering.proto", "wlan.nreport.bssid", "wlan.nreport.channumber", "wlan.nreport.opeclass",
            "wlan.nreport.bssid.info.mobilitydomain", "wlan.rnr.bssid", "wlan.rnr.channel_number",
            "wlan.rnr.tbtt_info.bss_parameters.same_ssid", "wlan.rnr.tbtt_info.bss_parameters.multiple_bssid",
            "wlan.rnr.tbtt_info.bss_parameters.colocated_ap", "wlan.mobility_domain.mdid",
            "wlan.mobility_domain.ft_capab", "wlan.mobility_domain.ft_capab.ft_over_ds",
            "wlan.extreme_mesh.ie.mesh_id", "wlan.extreme_mesh.ie.mp_id", "wlan.extreme_mesh.ie.root",
            "wlan.extreme_mesh.ie.nh", "wlan.extreme_mesh.ie.htr", "wlan.extreme_mesh.ie.mtr",
            "wlan.extreme_mesh.ie.services.root", "wlan.marvell.ie.cap", "wlan.marvell.ie.metric_id",
            "wlan.marvell.ie.proto_id", "wlan.fixed.mrvl_mesh_action", "wlan.vs.aerohive.hostname",
            "wlan.vs.alcatel.apname", "wlan.vs.arista.ap_name", "wlan.vs.aruba.ap_name",
            "wlan.vs.cisco.apname_v2", "wlan.vs.extreme.ap_name", "wlan.vs.fortinet.system.ap_model",
            "wlan.vs.fortinet.system.ap_name", "wlan.vs.fortinet.system.ap_serial", "wlan.vs.mist.apname",
            "wlan.vs.ruckus.apname",
        ]
        rows, messages = self.runner.fields(self.file_path, display_filter, fields, occurrence="a", aggregator=",", quiet_missing=True)
        self.result.messages.extend(messages)
        seen_topology = False
        for row in rows:
            bssid = normalize_mac(row.get("wlan.bssid", ""))
            sa = normalize_mac(row.get("wlan.sa", ""))
            ta = normalize_mac(row.get("wlan.ta", ""))
            ra = normalize_mac(row.get("wlan.ra", ""))
            da = normalize_mac(row.get("wlan.da", ""))
            device = bssid if is_mac(bssid) and not is_noise_mac(bssid) else next((mac for mac in [ta, sa, ra, da] if is_mac(mac) and not is_noise_mac(mac)), "")
            if not device:
                continue

            mesh_ids = row_values(row, "wlan.mesh.id", "wlan.extreme_mesh.ie.mesh_id")
            mesh_fields = row_values(
                row,
                "wlan.mesh.config.cap.forwarding", "wlan.mesh.config.formation_info.num_peers",
                "wlan.mesh.formation_info.connect_to_as", "wlan.mesh.formation_info.connect_to_mesh_gate",
                "wlan.fixed.mesh_action", "wlan.fixed.mesh_addr4", "wlan.fixed.mesh_addr5",
                "wlan.fixed.mesh_addr6", "wlan.fixed.mesh_ttl", "wlan.fixed.rreqid",
                "wlan.fixed.selfprot_action",
            )
            hwmp_peers = [normalize_mac(value) for value in row_values(row, "wlan.hwmp.orig_sta", "wlan.hwmp.targ_sta") if is_mac(normalize_mac(value))]
            hwmp_values = row_values(row, "wlan.hwmp.metric", "wlan.hwmp.hopcount", "wlan.hwmp.ttl")
            peering_values = row_values(row, "wlan.peering.local_id", "wlan.peering.peer_id", "wlan.peering.proto")
            neighbor_bssids = [normalize_mac(value) for value in row_values(row, "wlan.nreport.bssid") if is_mac(normalize_mac(value))]
            rnr_bssids = [normalize_mac(value) for value in row_values(row, "wlan.rnr.bssid") if is_mac(normalize_mac(value))]
            mobility_domains = row_values(row, "wlan.mobility_domain.mdid", "wlan.nreport.bssid.info.mobilitydomain")
            vendor_ap_names = row_values(
                row,
                "wlan.vs.aerohive.hostname", "wlan.vs.alcatel.apname", "wlan.vs.arista.ap_name",
                "wlan.vs.aruba.ap_name", "wlan.vs.cisco.apname_v2", "wlan.vs.extreme.ap_name",
                "wlan.vs.fortinet.system.ap_model", "wlan.vs.fortinet.system.ap_name",
                "wlan.vs.fortinet.system.ap_serial", "wlan.vs.mist.apname", "wlan.vs.ruckus.apname",
            )
            vendor_mesh = row_values(
                row,
                "wlan.extreme_mesh.ie.mp_id", "wlan.extreme_mesh.ie.root", "wlan.extreme_mesh.ie.nh",
                "wlan.extreme_mesh.ie.htr", "wlan.extreme_mesh.ie.mtr", "wlan.extreme_mesh.ie.services.root",
                "wlan.marvell.ie.cap", "wlan.marvell.ie.metric_id", "wlan.marvell.ie.proto_id",
                "wlan.fixed.mrvl_mesh_action",
            )
            tods = row.get("wlan.fc.tods", "") in {"1", "True", "true"}
            fromds = row.get("wlan.fc.fromds", "") in {"1", "True", "true"}
            ds_status = row.get("wlan.fc.ds", "")
            wds_peers = [mac for mac in [ta, ra, sa, da] if is_mac(mac) and not is_noise_mac(mac) and mac != device]

            if mesh_ids or mesh_fields or hwmp_peers or hwmp_values or peering_values:
                seen_topology = True
                self._record_topology_clue(
                    device, "Confirmed 802.11s mesh", 70,
                    "802.11s mesh, HWMP, or mesh peering fields were observed.",
                    "Confirmed", row, sorted(set(mesh_ids + hwmp_peers + wds_peers)),
                    mesh_ids=mesh_ids, mesh_peers=hwmp_peers, hwmp_peers=hwmp_peers,
                    role_hint="802.11s mesh node",
                )
            if (tods and fromds) or ds_status in {"0x03", "3"}:
                seen_topology = True
                self._record_topology_clue(
                    device, "Probable wireless backhaul/WDS", 40,
                    "Four-address wireless distribution frame observed with both To DS and From DS set.",
                    "Probable", row, wds_peers, wds_peers=wds_peers,
                    role_hint="wireless backhaul or WDS participant",
                )
            if neighbor_bssids or rnr_bssids or mobility_domains:
                seen_topology = True
                self._record_topology_clue(
                    device, "Managed roaming / multi-AP ecosystem", 25,
                    "Neighbor report, reduced neighbor report, or mobility-domain fields reference related APs.",
                    "Related", row, sorted(set(neighbor_bssids + rnr_bssids + mobility_domains)),
                    neighbor_bssids=neighbor_bssids, rnr_bssids=rnr_bssids,
                    mobility_domains=mobility_domains, role_hint="managed roaming AP",
                )
            if vendor_mesh or vendor_ap_names:
                seen_topology = True
                self._record_topology_clue(
                    device, "Vendor topology clue", 30 if vendor_mesh else 15,
                    "Vendor-specific AP name, model, serial, or mesh IE was observed.",
                    "Vendor", row, sorted(set(vendor_ap_names + vendor_mesh + mesh_ids)),
                    vendor_ap_names=vendor_ap_names, vendor_mesh_clues=vendor_mesh,
                    mesh_ids=mesh_ids, role_hint="vendor-managed AP",
                )
        if seen_topology:
            self.result.messages.append("Topology analysis found mesh, roaming, WDS, RNR, or vendor AP relationship clues.")

    def _topology_display_filter(self) -> str:
        bssids = self._candidate_bssids()
        if not bssids:
            return self._filter_or()
        address_fields = ["wlan.bssid", "wlan.sa", "wlan.da", "wlan.ta", "wlan.ra"]
        clauses = [f"{field_name} == {bssid}" for bssid in bssids for field_name in address_fields]
        return " || ".join(f"({clause})" for clause in clauses)

    def _record_topology_clue(
        self,
        device: str,
        clue_type: str,
        score: int,
        reason: str,
        confidence: str,
        row: dict[str, str],
        related: Iterable[str] = (),
        mesh_ids: Iterable[str] = (),
        mesh_peers: Iterable[str] = (),
        hwmp_peers: Iterable[str] = (),
        neighbor_bssids: Iterable[str] = (),
        rnr_bssids: Iterable[str] = (),
        wds_peers: Iterable[str] = (),
        vendor_ap_names: Iterable[str] = (),
        vendor_mesh_clues: Iterable[str] = (),
        mobility_domains: Iterable[str] = (),
        role_hint: str = "",
    ) -> None:
        device = normalize_mac(device)
        if not is_mac(device) or is_noise_mac(device):
            return
        key_kind = "BSSID" if f"BSSID:{device}" in self.result.candidates or normalize_mac(row.get("wlan.bssid", "")) == device else "MAC"
        evidence_fields = {
            "device": device,
            "clue": clue_type,
            "mesh_ids": ",".join(sorted(set(mesh_ids))),
            "neighbors": ",".join(sorted(set(neighbor_bssids))),
            "rnr": ",".join(sorted(set(rnr_bssids))),
            "wds_peers": ",".join(sorted(set(wds_peers))),
            "hwmp_peers": ",".join(sorted(set(hwmp_peers))),
            "mobility_domains": ",".join(sorted(set(mobility_domains))),
            "vendor": ",".join(sorted(set(vendor_ap_names) | set(vendor_mesh_clues))),
        }
        candidate = self.result.add_candidate(
            key_kind,
            device,
            Evidence("Topology analysis", reason, score, evidence_fields),
            labels=["topology", clue_type.lower().replace(" ", "-").replace("/", "-")],
            related=list(related),
        )
        profile = self.result.profile_for(candidate)
        profile.merge_frame(row.get("frame.number", ""))
        profile.topology_roles.add(clue_type)
        if role_hint:
            profile.role_hints.add(role_hint)
        profile.mesh_ids.update(mesh_ids)
        profile.mesh_peers.update(mesh_peers)
        profile.hwmp_peers.update(hwmp_peers)
        profile.neighbor_bssids.update(neighbor_bssids)
        profile.rnr_bssids.update(rnr_bssids)
        profile.wds_peers.update(wds_peers)
        profile.vendor_ap_names.update(vendor_ap_names)
        profile.vendor_mesh_clues.update(vendor_mesh_clues)
        profile.mobility_domains.update(mobility_domains)
        if key_kind == "BSSID":
            profile.bssids.add(device)
        for mac in set(neighbor_bssids) | set(rnr_bssids) | set(wds_peers) | set(hwmp_peers):
            if is_mac(mac) and not is_noise_mac(mac):
                related_profile = self._profile("BSSID" if f"BSSID:{mac}" in self.result.candidates else "MAC", mac)
                related_profile.topology_roles.add(f"Referenced by {device}")
                related_profile.mesh_peers.add(device)
        self._merge_topology_row(
            {
                "Confidence": confidence,
                "Role Guess": clue_type,
                "Device": device,
                "Kind": key_kind,
                "Mesh ID": ", ".join(sorted(set(mesh_ids))),
                "Mesh Peers": ", ".join(sorted(set(mesh_peers) | set(hwmp_peers))),
                "WDS Peers": ", ".join(sorted(set(wds_peers))),
                "Neighbor BSSIDs": ", ".join(sorted(set(neighbor_bssids))),
                "RNR BSSIDs": ", ".join(sorted(set(rnr_bssids))),
                "Mobility Domain": ", ".join(sorted(set(mobility_domains))),
                "Vendor/AP Name": ", ".join(sorted(set(vendor_ap_names) | set(vendor_mesh_clues))),
                "First Frame": row.get("frame.number", ""),
                "Last Frame": row.get("frame.number", ""),
                "Sightings": "1",
                "Why": reason,
            }
        )

    def _merge_topology_row(self, new_row: dict[str, str]) -> None:
        existing = next((row for row in self.result.topology_rows if row.get("Device") == new_row.get("Device")), None)
        if not existing:
            self.result.topology_rows.append(new_row)
            return

        def merge_values(column: str, separator: str = ", ") -> None:
            values = split_multi(existing.get(column, ""))
            for value in split_multi(new_row.get(column, "")):
                if value and value not in values:
                    values.append(value)
            existing[column] = separator.join(sorted(values))

        confidence_rank = {"Confirmed": 4, "Probable": 3, "Related": 2, "Vendor": 1}
        if confidence_rank.get(new_row.get("Confidence", ""), 0) > confidence_rank.get(existing.get("Confidence", ""), 0):
            existing["Confidence"] = new_row.get("Confidence", "")
        existing["Kind"] = "BSSID" if "BSSID" in {existing.get("Kind"), new_row.get("Kind")} else existing.get("Kind", "") or new_row.get("Kind", "")
        for column in ["Role Guess", "Mesh ID", "Mesh Peers", "WDS Peers", "Neighbor BSSIDs", "RNR BSSIDs", "Mobility Domain", "Vendor/AP Name"]:
            merge_values(column)
        if new_row.get("Why") and new_row.get("Why") not in existing.get("Why", ""):
            existing["Why"] = " | ".join(part for part in [existing.get("Why", ""), new_row.get("Why", "")] if part)

        first = self._min_frame(existing.get("First Frame", ""), new_row.get("First Frame", ""))
        last = self._max_frame(existing.get("Last Frame", ""), new_row.get("Last Frame", ""))
        existing["First Frame"] = first
        existing["Last Frame"] = last
        try:
            existing["Sightings"] = str(int(existing.get("Sightings", "0") or "0") + 1)
        except ValueError:
            existing["Sightings"] = "1"

    def _min_frame(self, left: str, right: str) -> str:
        try:
            if not left:
                return right
            if not right:
                return left
            return str(min(int(left), int(right)))
        except ValueError:
            return left or right

    def _max_frame(self, left: str, right: str) -> str:
        try:
            if not left:
                return right
            if not right:
                return left
            return str(max(int(left), int(right)))
        except ValueError:
            return left or right

    def _inspect_discovery_protocols(self) -> None:
        fields = [
            "frame.number", "eth.src", "wlan.sa", "ip.src",
            "lldp.chassis.id.mac", "lldp.chassis.id.ip4", "lldp.tlv.system.name", "lldp.tlv.system.desc", "lldp.chassis.subtype",
            "lldp.mgn.addr.ip4", "lldp.mgn.addr.ip6", "lldp.port.id", "lldp.port.desc", "lldp.time_to_live",
            "lldp.tlv.system_cap.router", "lldp.tlv.system_cap.bridge", "lldp.tlv.system_cap.wlan_access_pt",
            "lldp.tlv.enable_system_cap.router", "lldp.tlv.enable_system_cap.bridge", "lldp.tlv.enable_system_cap.wlan_access_pt",
            "cdp.deviceid", "cdp.system_name", "cdp.ttl", "cdp.nrgyz.ip_address", "cdp.nrgyz.ipv6_address",
            "cdp.portid", "cdp.platform", "cdp.software_version", "cdp.model_number", "cdp.system_serial_number",
            "cdp.native_vlan", "cdp.voice_vlan", "cdp.capabilities.router", "cdp.capabilities.switch",
            "cdp.capabilities.voip_phone", "cdp.capabilities.igmp_capable",
            "mndp.identity", "mndp.softwareid", "mndp.uptime", "mndp.version", "mndp.platform", "mndp.board",
            "mndp.ipv4address", "mndp.ipv6address", "mndp.interfacename", "mndp.mac",
        ]
        rows, messages = self.runner.fields(self.file_path, "lldp || cdp || mndp", fields, occurrence="a", aggregator=",", quiet_missing=True)
        self.result.messages.extend(messages)
        if not rows:
            return
        for row in rows:
            protocol = "LLDP" if field_present(row, "lldp.chassis.subtype", "lldp.tlv.system.name", "lldp.tlv.system.desc", "lldp.mgn.addr.ip4") else "CDP" if field_present(row, "cdp.deviceid", "cdp.system_name", "cdp.portid") else "MNDP"
            mac = normalize_mac(first_row_value(row, "mndp.mac", "lldp.chassis.id.mac", "eth.src", "wlan.sa"))
            ip = normalize_ip(first_row_value(row, "mndp.ipv4address", "cdp.nrgyz.ip_address", "lldp.mgn.addr.ip4", "lldp.chassis.id.ip4", "ip.src"))
            hostname = first_row_value(row, "mndp.identity", "cdp.deviceid", "cdp.system_name", "lldp.tlv.system.name")
            platform = first_row_value(row, "mndp.platform", "mndp.board", "cdp.platform", "cdp.model_number")
            software = first_row_value(row, "mndp.version", "mndp.softwareid", "cdp.software_version", "lldp.tlv.system.desc")
            port = first_row_value(row, "mndp.interfacename", "cdp.portid", "lldp.port.id", "lldp.port.desc")
            uptime_ttl = first_row_value(row, "mndp.uptime", "cdp.ttl", "lldp.time_to_live")
            serial = first_row_value(row, "cdp.system_serial_number")
            vlans = row_values(row, "cdp.native_vlan", "cdp.voice_vlan")
            role_hints = self._discovery_role_hints(row, protocol, platform, software)
            if not any([is_mac(mac), is_ip(ip), hostname]):
                continue
            candidate_kind = "MAC" if is_mac(mac) and not is_noise_mac(mac) else "IP" if is_ip(ip) else "Hostname"
            candidate_value = mac if candidate_kind == "MAC" else ip if candidate_kind == "IP" else hostname
            related = [item for item in [ip, hostname, mac] if item and item != candidate_value]
            self.result.add_candidate(
                candidate_kind,
                candidate_value,
                Evidence(f"{protocol} discovery", f"{protocol} advertised device identity and management details.", 35, {"protocol": protocol, "mac": mac, "ip": ip, "hostname": hostname, "platform": platform, "software": software, "port": port}),
                labels=["discovery", protocol.lower()],
                related=related,
            )
            profiles: list[DeviceProfile] = []
            if is_mac(mac) and not is_noise_mac(mac):
                profiles.append(self._profile("MAC", mac))
            if is_ip(ip):
                profiles.append(self._profile("IP", ip))
            if hostname:
                profiles.append(self._profile("Hostname", hostname))
            for profile in profiles:
                self._merge_discovery_profile(profile, protocol, row.get("frame.number", ""), mac, ip, hostname, platform, software, port, uptime_ttl, serial, vlans, role_hints)
            self._merge_discovery_row(
                {
                    "Protocol": protocol,
                    "MAC": mac if is_mac(mac) else "",
                    "IP": ip if is_ip(ip) else "",
                    "Hostname/ID": hostname,
                    "Platform/Model": platform,
                    "Software/Firmware": software,
                    "Port/Interface": port,
                    "Uptime/TTL": uptime_ttl,
                    "Role Hints": ", ".join(sorted(role_hints)),
                    "Sightings": "1",
                    "First Frame": row.get("frame.number", ""),
                    "Last Frame": row.get("frame.number", ""),
                }
            )
        if self.result.discovery_rows:
            self.result.messages.append(f"Discovery protocol analysis found {len(self.result.discovery_rows)} advertised device identities.")

    def _discovery_role_hints(self, row: dict[str, str], protocol: str, platform: str, software: str) -> set[str]:
        text = f"{protocol} {platform} {software}".lower()
        hints: set[str] = {"passive discovery advertised device"}
        if row.get("lldp.tlv.system_cap.router") in {"1", "True", "true"} or row.get("lldp.tlv.enable_system_cap.router") in {"1", "True", "true"} or row.get("cdp.capabilities.router") in {"1", "True", "true"}:
            hints.add("router")
        if row.get("lldp.tlv.system_cap.bridge") in {"1", "True", "true"} or row.get("lldp.tlv.enable_system_cap.bridge") in {"1", "True", "true"} or row.get("cdp.capabilities.switch") in {"1", "True", "true"}:
            hints.add("switch/bridge")
        if row.get("lldp.tlv.system_cap.wlan_access_pt") in {"1", "True", "true"} or row.get("lldp.tlv.enable_system_cap.wlan_access_pt") in {"1", "True", "true"}:
            hints.add("access point")
        if row.get("cdp.capabilities.voip_phone") in {"1", "True", "true"}:
            hints.add("VoIP phone")
        if "routeros" in text or "mikrotik" in text or protocol == "MNDP":
            hints.add("MikroTik network device")
        if any(word in text for word in ["ap", "access point", "cap ax", "wap"]):
            hints.add("access point")
        if any(word in text for word in ["switch", "bridge", "catalyst"]):
            hints.add("switch/bridge")
        if "router" in text:
            hints.add("router")
        return hints

    def _merge_discovery_profile(self, profile: DeviceProfile, protocol: str, frame: str, mac: str, ip: str, hostname: str, platform: str, software: str, port: str, uptime_ttl: str, serial: str, vlans: Iterable[str], role_hints: Iterable[str]) -> None:
        profile.merge_frame(frame)
        profile.discovery_protocols.add(protocol)
        if is_mac(mac) and not is_noise_mac(mac):
            profile.mac = profile.mac or mac
        if is_ip(ip):
            profile.ips.add(ip)
            profile.management_ips.add(ip)
        if hostname:
            profile.hostnames.add(hostname)
        profile.set_if_empty("platform", platform)
        profile.set_if_empty("model", platform)
        profile.set_if_empty("software", software)
        profile.set_if_empty("firmware", software)
        profile.set_if_empty("serial", serial)
        profile.set_if_empty("uptime", uptime_ttl)
        if port:
            profile.port_ids.add(port)
            profile.interface_names.add(port)
        profile.vlans.update(value for value in vlans if value)
        profile.role_hints.update(hint for hint in role_hints if hint)

    def _merge_discovery_row(self, new_row: dict[str, str]) -> None:
        row_key = (new_row.get("Protocol", ""), new_row.get("MAC", ""), new_row.get("IP", ""), new_row.get("Hostname/ID", ""))
        existing = next((row for row in self.result.discovery_rows if (row.get("Protocol", ""), row.get("MAC", ""), row.get("IP", ""), row.get("Hostname/ID", "")) == row_key), None)
        if not existing:
            self.result.discovery_rows.append(new_row)
            return
        for column in ["Platform/Model", "Software/Firmware", "Port/Interface", "Uptime/TTL", "Role Hints"]:
            values = split_multi(existing.get(column, ""))
            for value in split_multi(new_row.get(column, "")):
                if value and value not in values:
                    values.append(value)
            existing[column] = ", ".join(sorted(values))
        existing["First Frame"] = self._min_frame(existing.get("First Frame", ""), new_row.get("First Frame", ""))
        existing["Last Frame"] = self._max_frame(existing.get("Last Frame", ""), new_row.get("Last Frame", ""))
        existing["Sightings"] = str(int(existing.get("Sightings", "0") or "0") + 1)

    def _decrypt_options(self) -> list[str]:
        opts: list[str] = []
        if self.password and self.ssid:
            opts.extend(["-o", "wlan.enable_decryption:TRUE", "-o", f'uat:80211_keys:"wpa-pwd","{self.password}:{self.ssid}"'])
        keys = []
        if self.temporal_key:
            keys.append(self.temporal_key)
        keys.extend(sorted(self.extracted_gtks))
        for key in keys:
            if "-o" not in opts:
                opts.extend(["-o", "wlan.enable_decryption:TRUE"])
            opts.extend(["-o", f'uat:80211_keys:"tk","{key}"'])
        return opts

    def _extract_gtks(self) -> None:
        if not (self.password and self.ssid):
            return
        decrypt = ["-o", "wlan.enable_decryption:TRUE", "-o", f'uat:80211_keys:"wpa-pwd","{self.password}:{self.ssid}"']
        display_filter = "wlan_rsna_eapol.keydes.msgnr == 3"
        fields = ["wlan.bssid", "wlan.sa", "wlan.da", "wlan.rsn.ie.gtk_kde.gtk", "wlan.rsn.ie.gtk.key", "wlan_rsna_eapol.keydes.data", "wlan_rsna_eapol.keydes.data_len"]
        rows, messages = self.runner.fields(self.file_path, display_filter, fields, decrypt=decrypt)
        self.result.messages.extend(messages)
        for row in rows:
            src = normalize_mac(row.get("wlan.sa", ""))
            dst = normalize_mac(row.get("wlan.da", ""))
            bssid = normalize_mac(row.get("wlan.bssid", ""))
            gtks = set()
            gtk_kde = clean_hex(row.get("wlan.rsn.ie.gtk_kde.gtk", ""))
            if gtk_kde:
                gtks.add(gtk_kde)
            direct_gtk = clean_hex(row.get("wlan.rsn.ie.gtk.key", ""))
            if direct_gtk:
                gtks.add(direct_gtk)
            gtks.update(extract_gtks_from_key_data(row.get("wlan_rsna_eapol.keydes.data", "")))
            for gtk in sorted(gtks):
                if gtk in self.extracted_gtks:
                    continue
                self.extracted_gtks.add(gtk)
                self.result.messages.append(f"Extracted GTK from EAPOL message 3 for {bssid or 'unknown BSSID'}: {gtk[:8]}... ({src} -> {dst})")
        if self.password and self.ssid and not self.extracted_gtks:
            self.result.messages.append("SSID/password decryption was attempted, but no GTK KDE was parsed from EAPOL message 3 key data.")

    def _inspect_decrypted_traffic(self) -> None:
        decrypt = self._decrypt_options()
        if not decrypt:
            return
        display_filter = f"({self._bssid_filter()}) && (ip || arp || ipv6)"
        fields = ["frame.number", "frame.protocols", "wlan.bssid", "wlan.sa", "wlan.da", "ip.src", "ip.dst", "ipv6.src", "ipv6.dst", "arp.src.proto_ipv4", "arp.dst.proto_ipv4"]
        rows, messages = self.runner.fields(self.file_path, display_filter, fields, decrypt=decrypt, quiet_missing=True)
        self.result.messages.extend(messages)
        for row in rows:
            protocol = infer_protocol(row)
            bssid = normalize_mac(row.get("wlan.bssid", ""))
            src_ip = row.get("ip.src") or row.get("ipv6.src") or row.get("arp.src.proto_ipv4", "")
            dst_ip = row.get("ip.dst") or row.get("ipv6.dst") or row.get("arp.dst.proto_ipv4", "")
            src_mac = normalize_mac(row.get("wlan.sa", ""))
            dst_mac = normalize_mac(row.get("wlan.da", ""))
            self.result.decrypted_rows.append(
                {
                    "Frame": row.get("frame.number", ""),
                    "Protocol": protocol,
                    "BSSID": bssid,
                    "Source MAC": src_mac,
                    "Destination MAC": dst_mac,
                    "Source IP": src_ip,
                    "Destination IP": dst_ip,
                }
            )
            for mac, label, ip in [(src_mac, "decrypted-source", src_ip), (dst_mac, "decrypted-destination", dst_ip)]:
                if is_noise_mac(mac):
                    continue
                reason = f"MAC appeared in decrypted {protocol or 'traffic'} traffic"
                if ip:
                    reason += f" with IP {ip}"
                self.result.add_candidate("MAC", mac, Evidence("Decrypted traffic", reason, 20, row), labels=[label], related=[bssid, ip])
                profile = self._profile("MAC", mac)
                profile.bssids.add(bssid)
                if protocol in {"ARP", "DHCP"} and is_local_identity_ip(ip) and ip != "0.0.0.0":
                    profile.ips.add(ip)
                if protocol:
                    profile.protocols.add(protocol)
                self._update_radio_profile(profile, row)
                for linked_profile in self._profiles_for_mac(mac):
                    if protocol in {"ARP", "DHCP"} and is_local_identity_ip(ip) and ip != "0.0.0.0":
                        linked_profile.ips.add(ip)
                    if protocol:
                        linked_profile.protocols.add(protocol)
                    if bssid and not is_noise_mac(bssid):
                        linked_profile.bssids.add(bssid)

    def _inspect_ip_traffic(self, decrypt: list[str] | None = None, source_label: str = "cleartext") -> None:
        display_filter = "ip || arp || ipv6"
        fields = [
            "frame.number",
            "frame.protocols",
            "eth.src",
            "eth.dst",
            "wlan.sa",
            "wlan.da",
            "wlan.bssid",
            "ip.src",
            "ip.dst",
            "arp.src.hw_mac",
            "arp.dst.hw_mac",
            "arp.src.proto_ipv4",
            "arp.dst.proto_ipv4",
            "arp.opcode",
            "dhcp.ip.your",
            "bootp.ip.your",
            "dhcp.ip.server",
            "bootp.ip.server",
            "dhcp.hw.mac_addr",
            "bootp.hw.mac_addr",
            "dhcp.option.hostname",
            "bootp.option.hostname",
            "dhcp.fqdn.name",
            "dhcp.option.dhcp_server_id",
            "bootp.option.dhcp_server_id",
            "dhcp.option.domain_name_server",
            "bootp.option.domain_name_server",
            "dhcp.option.subnet_mask",
            "bootp.option.subnet_mask",
            "dhcp.option.router",
            "bootp.option.router",
            "dhcp.option.requested_ip_address",
            "bootp.option.requested_ip_address",
            "dhcp.option.vendor_class_id",
            "bootp.option.vendor_class_id",
            "dhcp.option.request_list_item",
            "bootp.option.request_list_item",
            "bootp.option.parameter_request_list",
            "dhcp.option.user_class",
            "bootp.option.user_class",
            "dns.qry.name",
            "dns.resp.name",
            "dns.ptr.domain_name",
            "dns.srv.instance",
            "dns.srv.name",
            "dns.srv.service",
            "dns.srv.proto",
            "dns.srv.target",
            "dns.srv.port",
            "dns.a",
            "dns.aaaa",
            "nbns.name",
            "http.user_agent",
            "http.server",
            "http.host",
            "http.request.uri",
            "http.request.full_uri",
            "http.cookie_pair",
            "http.authorization",
            "http.proxy_authorization",
            "http.authbasic",
            "http.www_authenticate",
            "tls.handshake.extensions_server_name",
            "tls.handshake.ja3",
            "tcp.srcport",
            "tcp.dstport",
            "tcp.flags.syn",
            "tcp.flags.ack",
            "tcp.flags.reset",
            "udp.srcport",
            "udp.dstport",
        ]
        rows, messages = self.runner.fields(self.file_path, display_filter, fields, decrypt=decrypt, occurrence="a", aggregator=",", quiet_missing=True)
        self.result.messages.extend(messages)
        if not rows:
            if decrypt:
                self.result.messages.append("Decryption options were supplied, but no decrypted IP/ARP/name traffic was found.")
            return
        if decrypt:
            self.result.messages.append(f"Decrypted IP/name analysis found {len(rows)} matching frames.")
        else:
            self.result.messages.append(f"Cleartext IP/name analysis found {len(rows)} matching frames.")

        stats_by_ip: dict[str, IPHostStats] = {}
        conversation_counter: Counter[tuple[str, str, str, str, str, str, str]] = Counter()

        def stats(ip: str) -> IPHostStats:
            ip = normalize_ip(ip)
            stats_by_ip.setdefault(ip, IPHostStats(ip=ip))
            return stats_by_ip[ip]

        for row in rows:
            protocol = infer_protocol(row)
            frame = row.get("frame.number", "")
            dhcp_client_mac = normalize_mac(first_row_value(row, "dhcp.hw.mac_addr", "bootp.hw.mac_addr"))
            src_mac = normalize_mac(row.get("eth.src") or row.get("wlan.sa") or row.get("arp.src.hw_mac") or dhcp_client_mac)
            dst_mac = normalize_mac(row.get("eth.dst") or row.get("wlan.da") or row.get("arp.dst.hw_mac", ""))
            src_ip = normalize_ip(row.get("ip.src") or row.get("arp.src.proto_ipv4", ""))
            assigned_ip = normalize_ip(first_row_value(row, "dhcp.ip.your", "bootp.ip.your"))
            dst_ip = normalize_ip(row.get("ip.dst") or row.get("arp.dst.proto_ipv4") or assigned_ip)
            bssid = normalize_mac(row.get("wlan.bssid", ""))
            src_port = first_row_value(row, "tcp.srcport", "udp.srcport")
            dst_port = first_row_value(row, "tcp.dstport", "udp.dstport")
            udp_src_ports = row_values(row, "udp.srcport")
            syn = row.get("tcp.flags.syn") in {"1", "True", "true"}
            ack = row.get("tcp.flags.ack") in {"1", "True", "true"}
            rst = row.get("tcp.flags.reset") in {"1", "True", "true"}
            arp_opcode = row.get("arp.opcode", "")
            dhcp_hostnames = clean_hostnames(row_values(row, "dhcp.option.hostname", "bootp.option.hostname", "dhcp.fqdn.name"))
            dhcp_servers = [normalize_ip(value) for value in row_values(row, "dhcp.option.dhcp_server_id", "bootp.option.dhcp_server_id", "dhcp.ip.server", "bootp.ip.server") if is_ip(normalize_ip(value))]
            dhcp_dns_servers = [normalize_ip(value) for value in row_values(row, "dhcp.option.domain_name_server", "bootp.option.domain_name_server") if is_ip(normalize_ip(value))]
            dhcp_routers = [normalize_ip(value) for value in row_values(row, "dhcp.option.router", "bootp.option.router") if is_ip(normalize_ip(value))]
            dhcp_requested_ips = [normalize_ip(value) for value in row_values(row, "dhcp.option.requested_ip_address", "bootp.option.requested_ip_address") if is_ip(normalize_ip(value))]
            dhcp_subnet_masks = row_values(row, "dhcp.option.subnet_mask", "bootp.option.subnet_mask")
            dns_queries, reverse_dns_queries, dns_service_names = split_dns_question_names(row_values(row, "dns.qry.name"))
            ptr_hostnames: list[str] = []
            for ptr_name in row_values(row, "dns.ptr.domain_name"):
                name = clean_dns_name(ptr_name)
                if not name:
                    continue
                if is_reverse_dns_name(name):
                    if name not in reverse_dns_queries:
                        reverse_dns_queries.append(name)
                elif is_service_discovery_name(name):
                    if name not in dns_service_names:
                        dns_service_names.append(name)
                elif name not in ptr_hostnames:
                    ptr_hostnames.append(name)
            nbns_names = clean_nbns_names(row_values(row, "nbns.name"))
            dns_response_hostnames = clean_hostnames(row_values(row, "dns.resp.name", "dns.srv.target") + ptr_hostnames)
            service_names = row_values(row, "dns.srv.instance", "dns.srv.name")
            dns_answer_ips = [normalize_ip(value) for value in row_values(row, "dns.a", "dns.aaaa") if is_ip(normalize_ip(value))]
            http_hosts = row_values(row, "http.host")
            http_uris = row_values(row, "http.request.full_uri")
            tls_sni = row_values(row, "tls.handshake.extensions_server_name")
            host = first_row_value(row, "http.host")
            uri = first_row_value(row, "http.request.full_uri", "http.request.uri")
            for realm in row_values(row, "http.www_authenticate"):
                self._mark_http_auth_realm(src_ip, dst_ip, host, realm)
            for field_name in ["http.authorization", "http.proxy_authorization", "http.cookie_pair", "http.authbasic"]:
                for value in row_values(row, field_name):
                    for item in self._decode_http_credential_value(value, field_name):
                        self._record_http_credential(row, source_label, field_name, value, item, src_ip, dst_ip, src_mac, host, uri)

            if is_ip(src_ip):
                src_stats = stats(src_ip)
                src_stats.source_frames += 1
                src_stats.merge_frame(frame)
                if protocol:
                    src_stats.protocols[protocol] += 1
                if src_mac and not is_noise_mac(src_mac):
                    src_stats.unicast_source_frames += 1
                    src_stats.macs.add(src_mac)
                if row.get("arp.src.proto_ipv4") and protocol == "ARP" and arp_opcode == "2":
                    src_stats.arp_replies += 1
                if syn and not ack and is_ip(dst_ip):
                    src_stats.scanned_targets.add(dst_ip)
                    src_stats.tcp_syn_sent.add(dst_port)
                if syn and ack and src_port:
                    src_stats.tcp_synack_ports.add(src_port)
                if rst and src_port:
                    src_stats.tcp_rst_ports.add(src_port)
                for udp_src_port in udp_src_ports:
                    if udp_src_port in {"53", "67", "68", "123", "1900", "5353", "5355", "137"} or service_names:
                        src_stats.udp_response_ports.add(udp_src_port)
                if protocol == "DNS":
                    src_stats.dns_queries.update(dns_queries)
                    src_stats.reverse_dns_queries.update(reverse_dns_queries)
                    src_stats.service_discovery_names.update(dns_service_names)
                    src_stats.service_discovery_names.update(service_names)
                    src_stats.services.update(service_names)
                    if src_ip in dns_answer_ips:
                        src_stats.hostnames.update(dns_response_hostnames)
                src_stats.nbns_names.update(nbns_names)
                src_stats.http_hosts.update(http_hosts)
                src_stats.http_uris.update(http_uris)
                src_stats.hostnames.update(dhcp_hostnames)
                src_stats.dhcp_servers.update(dhcp_servers)
                src_stats.dhcp_routers.update(dhcp_routers)
                src_stats.dhcp_dns_servers.update(dhcp_dns_servers)
                src_stats.dhcp_subnet_masks.update(dhcp_subnet_masks)
                src_stats.dhcp_requested_ips.update(dhcp_requested_ips)
                for value in row_values(row, "dhcp.option.vendor_class_id", "bootp.option.vendor_class_id", "dhcp.option.user_class", "bootp.option.user_class"):
                    src_stats.dhcp_vendor_classes.add(value)
                for value in row_values(row, "dhcp.option.request_list_item", "bootp.option.request_list_item", "bootp.option.parameter_request_list"):
                    src_stats.dhcp_parameter_lists.add(value)
                src_stats.http_user_agents.update(row_values(row, "http.user_agent"))
                src_stats.http_servers.update(row_values(row, "http.server"))
                src_stats.tls_sni.update(tls_sni)
                src_stats.tls_ja3.update(row_values(row, "tls.handshake.ja3"))
                if row.get("http.server") and src_port:
                    src_stats.tcp_synack_ports.add(src_port)

            if is_ip(dst_ip):
                dst_stats = stats(dst_ip)
                dst_stats.destination_frames += 1
                dst_stats.merge_frame(frame)
                if protocol:
                    dst_stats.protocols[protocol] += 1
                if dst_mac and not is_noise_mac(dst_mac):
                    dst_stats.macs.add(dst_mac)
                if protocol == "ARP" and arp_opcode == "1":
                    dst_stats.arp_requests_for += 1
                if syn and not ack and is_ip(src_ip):
                    dst_stats.scanned_by.add(src_ip)
                if assigned_ip and dst_ip == assigned_ip:
                    dst_stats.dhcp_leases.add(assigned_ip)
                    dst_stats.hostnames.update(dhcp_hostnames)
                    if dhcp_client_mac and not is_noise_mac(dhcp_client_mac):
                        dst_stats.macs.add(dhcp_client_mac)
                dst_stats.http_servers.update(row_values(row, "http.server"))
                dst_stats.tls_sni.update(tls_sni)
                dst_stats.tls_ja3.update(row_values(row, "tls.handshake.ja3"))

            for option_ip in dhcp_servers:
                option_stats = stats(option_ip)
                option_stats.dhcp_leases.update(ip for ip in [assigned_ip, src_ip, dst_ip] if is_ip(ip) and ip != option_ip)
                option_stats.protocols["DHCP"] += 1
            for option_ip in dhcp_routers:
                option_stats = stats(option_ip)
                option_stats.dhcp_routers.update(ip for ip in [assigned_ip, src_ip, dst_ip] if is_ip(ip) and ip != option_ip)
                option_stats.protocols["DHCP"] += 1
            for option_ip in dhcp_dns_servers:
                option_stats = stats(option_ip)
                option_stats.dhcp_dns_servers.update(ip for ip in [assigned_ip, src_ip, dst_ip] if is_ip(ip) and ip != option_ip)
                option_stats.protocols["DHCP"] += 1
            for answer_ip in dns_answer_ips:
                answer_stats = stats(answer_ip)
                answer_stats.hostnames.update(dns_response_hostnames)
                answer_stats.protocols["DNS"] += 1

            if is_ip(src_ip) and is_ip(dst_ip):
                if self._is_meaningful_peer(src_ip, dst_ip, protocol, syn, ack, rst):
                    stats(src_ip).peers[dst_ip] += 1
                    stats(dst_ip).peers[src_ip] += 1
                    conversation_counter[(src_ip, dst_ip, src_mac if is_mac(src_mac) else "", dst_mac if is_mac(dst_mac) else "", protocol, src_port, dst_port)] += 1

        self._emit_ip_candidates(stats_by_ip)
        self._emit_ip_conversations(conversation_counter, stats_by_ip)
        self._emit_scan_rows(stats_by_ip)
        self._emit_service_rows(stats_by_ip)
        if self.result.credential_rows:
            self.result.messages.append(f"HTTP credential analysis found {len(self.result.credential_rows)} sensitive credential indicator(s).")

    def _is_meaningful_peer(self, src_ip: str, dst_ip: str, protocol: str, syn: bool, ack: bool, rst: bool) -> bool:
        if ip_scope(dst_ip) in {"multicast", "special"} or ip_scope(src_ip) in {"multicast", "special"}:
            return False
        if syn and not ack and not rst:
            return False
        return bool(protocol)

    def _ip_evidence_level(self, host: IPHostStats) -> str:
        scope = ip_scope(host.ip)
        if scope in {"multicast", "special", "loopback"} or host.ip.endswith(".0") or host.ip == "255.255.255.255":
            return "Special"
        if scope == "external/global":
            return "External"
        if host.arp_replies or host.tcp_synack_ports or host.hostnames or host.unicast_source_frames or host.dhcp_routers or host.dhcp_dns_servers or host.dhcp_leases:
            return "Confirmed"
        if host.source_frames >= 2 or host.macs:
            return "Probable"
        if host.scanned_by and not host.source_frames:
            return "Probed"
        return "Weak"

    def _emit_ip_candidates(self, stats_by_ip: dict[str, IPHostStats]) -> None:
        for host in stats_by_ip.values():
            level = self._ip_evidence_level(host)
            if level in {"Probed", "Weak", "Special"} and host.ip != self.ip:
                continue
            labels = ["ip-device", level.lower()]
            related = sorted(host.macs)[:3]
            if self.ip and host.ip == self.ip:
                related.append("user-input")
            candidate = self.result.add_candidate(
                "IP",
                host.ip,
                Evidence("IP host classification", f"{level} IP host based on aggregated traffic evidence.", self._ip_score(host, level), {"ip": host.ip, "level": level}),
                labels=labels,
                related=related,
            )
            profile = self._profile("IP", candidate.value)
            profile.merge_frame(host.first_frame)
            profile.first_seen = host.first_frame or profile.first_seen
            profile.last_seen = host.last_frame or profile.last_seen
            profile.frame_count = max(profile.frame_count, host.total_frames)
            profile.ips.add(host.ip)
            profile.role_hints.add(level)
            profile.role_hints.add(ip_scope(host.ip))
            profile.protocols.update(host.protocols.keys())
            profile.hostnames.update(host.hostnames)
            profile.dns_queries.update(host.dns_queries)
            profile.reverse_dns_queries.update(host.reverse_dns_queries)
            profile.service_discovery_names.update(host.service_discovery_names)
            profile.nbns_names.update(host.nbns_names)
            profile.http_hosts.update(host.http_hosts)
            profile.http_uris.update(host.http_uris)
            profile.services.update(host.services)
            profile.dhcp_vendor_classes.update(host.dhcp_vendor_classes)
            profile.dhcp_parameter_lists.update(host.dhcp_parameter_lists)
            profile.dhcp_servers.update(host.dhcp_servers)
            profile.dhcp_routers.update(host.dhcp_routers)
            profile.dhcp_dns_servers.update(host.dhcp_dns_servers)
            profile.dhcp_subnet_masks.update(host.dhcp_subnet_masks)
            profile.dhcp_requested_ips.update(host.dhcp_requested_ips)
            profile.dhcp_requested_ips.update(host.dhcp_leases)
            profile.http_user_agents.update(host.http_user_agents)
            profile.http_servers.update(host.http_servers)
            profile.tls_sni.update(host.tls_sni)
            profile.tls_ja3.update(host.tls_ja3)
            profile.peers.update(peer for peer, _ in host.peers.most_common(20))
            if host.macs:
                mac = sorted(host.macs)[0]
                profile.mac = profile.mac or mac
                profile.vendor = profile.vendor or oui_prefix(mac)
                if is_local_admin_mac(mac):
                    profile.warnings.add("Linked MAC is locally administered; it may be randomized")
                for mac_profile in self._profiles_for_mac(mac):
                    if self._host_ip_belongs_to_mac(host, mac):
                        mac_profile.ips.add(host.ip)
                    mac_profile.protocols.update(host.protocols.keys())
                    mac_profile.hostnames.update(host.hostnames)
                    mac_profile.dns_queries.update(host.dns_queries)
                    mac_profile.reverse_dns_queries.update(host.reverse_dns_queries)
                    mac_profile.service_discovery_names.update(host.service_discovery_names)
                    mac_profile.nbns_names.update(host.nbns_names)
                    mac_profile.http_hosts.update(host.http_hosts)
                    mac_profile.http_uris.update(host.http_uris)
                    mac_profile.services.update(host.services)
                    mac_profile.dhcp_vendor_classes.update(host.dhcp_vendor_classes)
                    mac_profile.dhcp_parameter_lists.update(host.dhcp_parameter_lists)
                    mac_profile.dhcp_servers.update(host.dhcp_servers)
                    mac_profile.dhcp_routers.update(host.dhcp_routers)
                    mac_profile.dhcp_dns_servers.update(host.dhcp_dns_servers)
                    mac_profile.dhcp_subnet_masks.update(host.dhcp_subnet_masks)
                    mac_profile.dhcp_requested_ips.update(host.dhcp_requested_ips)
                    mac_profile.dhcp_requested_ips.update(host.dhcp_leases)
                    mac_profile.http_user_agents.update(host.http_user_agents)
                    mac_profile.http_servers.update(host.http_servers)
                    mac_profile.tls_sni.update(host.tls_sni)
                    mac_profile.tls_ja3.update(host.tls_ja3)
            if host.tcp_synack_ports:
                profile.services.update(f"{port}/tcp open" for port in sorted(host.tcp_synack_ports, key=self._sort_number_text))
                profile.role_hints.add("TCP service responder")
            if host.tcp_rst_ports:
                profile.services.update(f"{port}/tcp closed" for port in sorted(host.tcp_rst_ports, key=self._sort_number_text)[:20])
            if host.udp_response_ports:
                profile.services.update(f"{port}/udp response" for port in sorted(host.udp_response_ports, key=self._sort_number_text))
            self._add_ip_role_hints(profile, host)
            for hostname in host.hostnames:
                self.result.add_candidate(
                    "Hostname",
                    hostname,
                    Evidence("Hostname observation", f"Hostname was observed for IP {host.ip}.", 20, {"ip": host.ip, "hostname": hostname}),
                    labels=["hostname"],
                    related=[host.ip, profile.mac],
                )

    def _host_ip_belongs_to_mac(self, host: IPHostStats, mac: str) -> bool:
        if not is_local_identity_ip(host.ip) or host.ip == "0.0.0.0":
            return False
        if host.arp_replies or host.dhcp_leases or host.dhcp_routers or host.dhcp_dns_servers:
            return True
        if f"BSSID:{normalize_mac(mac)}" in self.result.profiles or f"BSSID:{normalize_mac(mac)}" in self.result.candidates:
            return False
        return bool(host.unicast_source_frames or host.tcp_synack_ports)

    def _ip_score(self, host: IPHostStats, level: str) -> int:
        scores = {"Confirmed": 90, "Probable": 55, "External": 25, "Special": 10, "Probed": 5, "Weak": 10}
        score = scores.get(level, 10)
        if host.tcp_synack_ports:
            score += min(25, 10 + len(host.tcp_synack_ports) * 3)
        if host.hostnames:
            score += 20
        if host.arp_replies:
            score += 20
        if host.dhcp_routers or host.dhcp_dns_servers or host.dhcp_leases:
            score += 20
        return min(score, 160)

    def _add_ip_role_hints(self, profile: DeviceProfile, host: IPHostStats) -> None:
        ports = set(host.tcp_synack_ports)
        if "53" in ports or "DNS" in host.protocols:
            profile.role_hints.add("DNS server/responder")
        if {"67", "547"} & ports or "DHCP" in " ".join(host.protocols.keys()).upper():
            profile.role_hints.add("DHCP participant")
        if host.dhcp_leases:
            profile.role_hints.add("DHCP server")
        if host.dhcp_routers:
            profile.role_hints.add("router/gateway from DHCP option")
        if host.dhcp_dns_servers:
            profile.role_hints.add("DNS server from DHCP option")
        if {"80", "8080", "443"} & ports:
            profile.role_hints.add("web service")
        if {"445", "139"} & ports:
            profile.role_hints.add("Windows/SMB service")
        if len(host.peers) >= 5 and ip_scope(host.ip) == "local/private":
            profile.role_hints.add("central local host or gateway candidate")
        if len(host.scanned_targets) >= 20:
            profile.role_hints.add("scanner")

    def _emit_ip_conversations(self, conversation_counter: Counter, stats_by_ip: dict[str, IPHostStats]) -> None:
        for (src_ip, dst_ip, src_mac, dst_mac, protocol, src_port, dst_port), count in conversation_counter.most_common(500):
            if not self._conversation_should_show(src_ip, dst_ip, stats_by_ip):
                continue
            self.result.conversation_rows.append(
                {
                    "Source IP": src_ip,
                    "Destination IP": dst_ip,
                    "Source MAC": src_mac,
                    "Destination MAC": dst_mac,
                    "Protocol": protocol,
                    "Source Port": src_port,
                    "Destination Port": dst_port,
                    "Frames": str(count),
                }
            )

    def _conversation_should_show(self, src_ip: str, dst_ip: str, stats_by_ip: dict[str, IPHostStats]) -> bool:
        src_level = self._ip_evidence_level(stats_by_ip.get(src_ip, IPHostStats(src_ip)))
        dst_level = self._ip_evidence_level(stats_by_ip.get(dst_ip, IPHostStats(dst_ip)))
        if "Special" in {src_level, dst_level}:
            return False
        return src_level in {"Confirmed", "Probable", "External"} or dst_level in {"Confirmed", "Probable", "External"}

    def _emit_scan_rows(self, stats_by_ip: dict[str, IPHostStats]) -> None:
        for host in stats_by_ip.values():
            if len(host.scanned_targets) < 10:
                continue
            responsive = [target for target in host.scanned_targets if stats_by_ip.get(target) and self._ip_evidence_level(stats_by_ip[target]) in {"Confirmed", "Probable"}]
            self.result.scan_rows.append(
                {
                    "Scanner": host.ip,
                    "Targets": str(len(host.scanned_targets)),
                    "Responsive": str(len(responsive)),
                    "Target Sample": ", ".join(sorted(host.scanned_targets, key=self._sort_number_text)[:12]),
                    "Open Ports Seen": ", ".join(sorted({port for target in responsive for port in stats_by_ip[target].tcp_synack_ports}, key=self._sort_number_text)),
                }
            )

    def _emit_service_rows(self, stats_by_ip: dict[str, IPHostStats]) -> None:
        for host in stats_by_ip.values():
            level = self._ip_evidence_level(host)
            if level not in {"Confirmed", "Probable", "External"}:
                continue
            for port in sorted(host.tcp_synack_ports, key=self._sort_number_text):
                row = {"IP": host.ip, "Port": port, "Proto": "tcp", "State": "open", "Service Hint": self._service_hint(port, "tcp")}
                self.result.service_rows.append(row)
                self.result.open_service_rows.append(row)
            for port in sorted(host.tcp_rst_ports, key=self._sort_number_text)[:20]:
                row = {"IP": host.ip, "Port": port, "Proto": "tcp", "State": "closed", "Service Hint": self._service_hint(port, "tcp")}
                self.result.service_rows.append(row)
                self.result.closed_service_rows.append(row)
            for port in sorted(host.udp_response_ports, key=self._sort_number_text):
                row = {"IP": host.ip, "Port": port, "Proto": "udp", "State": "response", "Service Hint": self._service_hint(port, "udp")}
                self.result.service_rows.append(row)
                self.result.open_service_rows.append(row)
            for service in sorted(host.services)[:20]:
                row = {"IP": host.ip, "Port": "", "Proto": "discovery", "State": "advertised", "Service Hint": service}
                self.result.service_rows.append(row)
                self.result.closed_service_rows.append(row)

    def _inspect_http_services(self, decrypt: list[str] | None = None, source_label: str = "cleartext") -> None:
        response_fields = ["frame.number", "ip.src", "tcp.srcport", "http.response.code", "http.request_in", "http.server"]
        confirming_filter = self._http_confirming_code_filter()
        response_rows, messages = self.runner.fields(
            self.file_path,
            f"({confirming_filter}) && http.request_in",
            response_fields,
            decrypt=decrypt,
            occurrence="a",
            aggregator=",",
            quiet_missing=True,
            two_pass=True,
        )
        self.result.messages.extend(messages)
        request_frames: dict[str, list[dict[str, str]]] = {}
        for row in response_rows:
            code = first_row_value(row, "http.response.code")
            if not self._http_code_confirms_open(code):
                continue
            for request_frame in row_values(row, "http.request_in"):
                if request_frame.isdigit():
                    request_frames.setdefault(request_frame, []).append(row)
        if not request_frames:
            return
        frame_ids = sorted(request_frames, key=self._sort_number_text)
        recorded_services: set[tuple[str, str, str]] = set()
        uri_sample_counts: Counter[tuple[str, str, str]] = Counter()
        for chunk_start in range(0, len(frame_ids), 80):
            chunk = frame_ids[chunk_start : chunk_start + 80]
            if len(chunk) == 1:
                request_filter = f"frame.number == {chunk[0]}"
            else:
                request_filter = "(" + " || ".join(f"frame.number == {frame_id}" for frame_id in chunk) + ")"
            request_fields = ["frame.number", "ip.src", "ip.dst", "tcp.dstport", "http.host", "http.request.uri", "http.request.full_uri"]
            request_rows, request_messages = self.runner.fields(
                self.file_path,
                request_filter,
                request_fields,
                decrypt=decrypt,
                occurrence="a",
                aggregator=",",
                quiet_missing=True,
                two_pass=True,
            )
            self.result.messages.extend(request_messages)
            for request in request_rows:
                frame = request.get("frame.number", "")
                server_ip = normalize_ip(request.get("ip.dst", ""))
                server_port = first_row_value(request, "tcp.dstport")
                host = first_row_value(request, "http.host")
                uri = first_row_value(request, "http.request.full_uri", "http.request.uri")
                response_code = first_row_value(request_frames.get(frame, [{}])[0], "http.response.code")
                server_header = first_row_value(request_frames.get(frame, [{}])[0], "http.server")
                service_key = (server_ip, server_port, source_label)
                if not (is_ip(server_ip) and server_port):
                    continue
                if uri_sample_counts[service_key] < 20:
                    uri_sample_counts[service_key] += 1
                    self._record_http_uri_sample(server_ip, server_port, host, uri, response_code, frame, server_header, source_label)
                if service_key not in recorded_services:
                    recorded_services.add(service_key)
                    self._record_http_service(server_ip, server_port, host, uri, response_code, frame, server_header, source_label)

    def _record_http_service(self, server_ip: str, port: str, host: str, uri: str, response_code: str, frame: str, server_header: str, source_label: str) -> None:
        hint_parts = ["HTTP"]
        if response_code:
            hint_parts.append(f"{response_code} response")
        if server_header:
            hint_parts.append(server_header)
        service_hint = " - ".join(hint_parts)
        row = {"IP": server_ip, "Port": port, "Proto": "tcp", "State": "open", "Service Hint": service_hint}
        self._upsert_service_row(row, open_row=True)
        candidate = self.result.add_candidate(
            "IP",
            server_ip,
            Evidence("HTTP service correlation", f"HTTP {response_code or ''} response confirms port {port} is serving HTTP.", 25, {"ip": server_ip, "port": port, "response_code": response_code, "source": source_label}),
            labels=["ip-device", "http-service", source_label],
            related=[host],
        )
        profile = self.result.profile_for(candidate)
        profile.ips.add(server_ip)
        profile.protocols.add("HTTP")
        profile.services.add(f"{port}/tcp open HTTP")
        if host:
            profile.hostnames.add(host)
            profile.http_hosts.add(host)
        if uri:
            profile.http_uris.add(uri)
        if server_header:
            profile.http_servers.add(server_header)
        profile.role_hints.add("web service")

    def _record_http_uri_sample(self, server_ip: str, port: str, host: str, uri: str, response_code: str, frame: str, server_header: str, source_label: str) -> None:
        row = {
            "IP": server_ip,
            "Port": port,
            "Host": host,
            "Status": response_code,
            "URI": uri,
            "Server": server_header,
            "Source": source_label,
            "Frame": frame,
        }
        key = tuple(row.get(column, "") for column in ["IP", "Port", "Host", "Status", "URI", "Source"])
        existing_keys = {
            tuple(existing.get(column, "") for column in ["IP", "Port", "Host", "Status", "URI", "Source"])
            for existing in self.result.http_uri_rows
        }
        if key not in existing_keys:
            self.result.http_uri_rows.append(row)

    def _http_code_confirms_open(self, code: str) -> bool:
        try:
            numeric = int(code)
        except (TypeError, ValueError):
            return False
        return numeric in self._http_confirming_codes()

    def _http_confirming_codes(self) -> set[int]:
        return {200, 201, 202, 204, 206, 301, 302, 303, 307, 308}

    def _http_confirming_code_filter(self) -> str:
        return " || ".join(f"http.response.code == {code}" for code in sorted(self._http_confirming_codes()))

    def _upsert_service_row(self, row: dict[str, str], open_row: bool = False) -> None:
        def same_service(existing: dict[str, str]) -> bool:
            return all(existing.get(key) == row.get(key) for key in ["IP", "Port", "Proto", "State"])

        updated = False
        for table in [self.result.service_rows, self.result.open_service_rows if open_row else []]:
            for existing in table:
                if same_service(existing):
                    new_hint = row.get("Service Hint", "")
                    old_hint = existing.get("Service Hint", "")
                    if new_hint and new_hint != old_hint:
                        if old_hint and old_hint in new_hint:
                            existing["Service Hint"] = new_hint
                        elif new_hint not in old_hint:
                            existing["Service Hint"] = " | ".join(part for part in [old_hint, new_hint] if part)
                    updated = True
        if not updated:
            self.result.service_rows.append(dict(row))
            if open_row:
                self.result.open_service_rows.append(dict(row))

    def _mark_http_auth_realm(self, src_ip: str, dst_ip: str, host: str, realm: str) -> None:
        for ip in [src_ip, dst_ip]:
            if is_ip(ip):
                profile = self._profile("IP", ip)
                profile.http_auth_realms.add(realm)
                if host:
                    profile.http_hosts.add(host)

    def _decode_http_credential_value(self, value: str, field_name: str) -> list[dict[str, str]]:
        decoded = unquote(value or "")
        outputs: list[dict[str, str]] = []
        candidates: list[tuple[str, str]] = []
        if field_name == "http.authbasic" and decoded:
            candidates.append(("HTTP Basic", decoded))
        for match in re.finditer(r"(?i)\bBasic\s+([A-Za-z0-9+/=_-]+)", decoded):
            candidates.append(("HTTP Basic", match.group(1)))
        for kind, token in candidates:
            token = token.strip().rstrip(",;")
            credential = token
            if ":" not in credential:
                try:
                    credential = base64.b64decode(token + "=" * (-len(token) % 4), validate=False).decode("utf-8", errors="replace")
                except Exception:
                    continue
            if ":" not in credential:
                continue
            username, secret = credential.split(":", 1)
            if not username or not secret:
                continue
            outputs.append({"type": kind, "username": username, "secret": secret})
        return outputs

    def _record_http_credential(self, row: dict[str, str], source_label: str, field_name: str, raw_value: str, item: dict[str, str], src_ip: str, dst_ip: str, src_mac: str, host: str, uri: str) -> None:
        candidate_value = src_ip if is_ip(src_ip) else src_mac if is_mac(src_mac) else host
        candidate_kind = "IP" if is_ip(candidate_value) else "MAC" if is_mac(candidate_value) else "Hostname"
        if not candidate_value:
            return
        reason = f"Sensitive HTTP credential material was observed in {field_name}; value was URL-decoded and Basic auth was base64-decoded."
        self.result.add_candidate(
            candidate_kind,
            candidate_value,
            Evidence("HTTP credential indicator", reason, 30, {"frame": row.get("frame.number", ""), "field": field_name, "host": host, "dst_ip": dst_ip, "username": item.get("username", "")}),
            labels=["http-credential", source_label],
            related=[dst_ip, host, src_mac],
        )
        for kind, value in [("IP", src_ip), ("IP", dst_ip), ("MAC", src_mac)]:
            if (kind == "IP" and is_ip(value)) or (kind == "MAC" and is_mac(value) and not is_noise_mac(value)):
                profile = self._profile(kind, value)
                profile.credential_indicators.add(f"{item.get('type', 'HTTP credential')} username={item.get('username', '')}")
                profile.warnings.add("Sensitive HTTP credential material observed in cleartext/decrypted traffic")
                if host:
                    profile.http_hosts.add(host)
        self.result.credential_rows.append(
            {
                "Source": src_ip,
                "Destination": dst_ip,
                "Source MAC": src_mac if is_mac(src_mac) else "",
                "Host": host,
                "Type": item.get("type", ""),
                "Username": item.get("username", ""),
                "Secret/Hash": item.get("secret", ""),
                "Field": field_name,
                "Frame": row.get("frame.number", ""),
                "URI": uri,
            }
        )

    def _service_hint(self, port: str, proto: str) -> str:
        names = {
            ("22", "tcp"): "SSH",
            ("53", "tcp"): "DNS",
            ("53", "udp"): "DNS",
            ("67", "udp"): "DHCP server",
            ("68", "udp"): "DHCP client",
            ("80", "tcp"): "HTTP",
            ("137", "udp"): "NetBIOS name",
            ("139", "tcp"): "NetBIOS",
            ("443", "tcp"): "HTTPS",
            ("445", "tcp"): "SMB",
            ("515", "tcp"): "LPD printer",
            ("554", "tcp"): "RTSP",
            ("631", "tcp"): "IPP printer",
            ("1900", "udp"): "SSDP",
            ("5000", "tcp"): "UPnP/web service",
            ("5060", "tcp"): "SIP",
            ("5060", "udp"): "SIP",
            ("5061", "tcp"): "SIP TLS",
            ("5353", "udp"): "mDNS",
            ("5355", "udp"): "LLMNR",
            ("3389", "tcp"): "RDP",
            ("8008", "tcp"): "Chromecast HTTP",
            ("8009", "tcp"): "Chromecast control",
            ("8080", "tcp"): "HTTP alt",
            ("8443", "tcp"): "HTTPS alt",
            ("9100", "tcp"): "JetDirect printer",
        }
        return names.get((port, proto), "")

    def _summarize_ip_devices(self) -> list[dict[str, str]]:
        rows: list[dict[str, str]] = []
        for candidate in self.result.sorted_candidates():
            if candidate.kind != "IP":
                continue
            profile = self.result.profile_for(candidate)
            level = next((label.title() for label in candidate.labels if label in {"confirmed", "probable", "probed", "external", "special", "weak"}), "")
            rows.append(
                {
                    "IP": candidate.value,
                    "Evidence": level,
                    "Scope": ip_scope(candidate.value),
                    "MAC": profile.mac,
                    "Hostnames": ", ".join(sorted(profile.hostnames)),
                    "Role Hints": ", ".join(sorted(hint for hint in profile.role_hints if hint)),
                    "DHCP Server": ", ".join(sorted(profile.dhcp_servers, key=str)),
                    "Router": ", ".join(sorted(profile.dhcp_routers, key=str)),
                    "DNS Servers": ", ".join(sorted(profile.dhcp_dns_servers, key=str)),
                    "Open TCP": ", ".join(sorted((item.split("/", 1)[0] for item in profile.services if "/tcp open" in item), key=self._sort_number_text)),
                    "Protocols": ", ".join(sorted(profile.protocols)),
                    "Peers": str(len(profile.peers)),
                    "DNS Queries": str(len(profile.dns_queries)),
                    "First Frame": profile.first_seen,
                    "Last Frame": profile.last_seen,
                    "Sightings": str(profile.frame_count),
                }
            )
        return rows


def render_candidate_detail(candidate: Candidate | None) -> str:
    if not candidate:
        return "Select a row to see why it was identified as related."
    total_sightings = sum(ev.count for ev in candidate.evidence)
    categories: dict[str, int] = {}
    for ev in candidate.evidence:
        categories[ev.source] = categories.get(ev.source, 0) + ev.score
    lines = [
        f"{candidate.kind}: {candidate.value}",
        f"Confidence score: {candidate.confidence} ({confidence_badge(candidate.confidence)})",
        f"Distinct evidence items: {len(candidate.evidence)}",
        f"Repeated sightings: {total_sightings} observations, not score-weighted",
        f"Labels: {', '.join(sorted(candidate.labels)) or '-'}",
        f"Related identifiers: {', '.join(sorted(candidate.related)) or '-'}",
        "",
        "Score summary:",
        *[f"- {source}: +{score}" for source, score in sorted(categories.items())],
        "",
        "Why this is related:",
    ]
    for index, ev in enumerate(candidate.evidence, 1):
        repeat_text = f", seen {ev.count} times" if ev.count > 1 else ""
        lines.append(f"{index}. {ev.source} (+{ev.score}{repeat_text})")
        lines.append(f"   {ev.reason}")
        if ev.fields:
            compact_fields = ", ".join(f"{k}={v}" for k, v in ev.fields.items() if v)
            if compact_fields:
                lines.append(f"   Fields: {compact_fields}")
    return "\n".join(lines)


def render_device_profile(candidate: Candidate | None, result: AnalysisResult | None) -> str:
    if not candidate or not result:
        return "Select a row to see device information."
    profile = result.profiles.get(candidate.key, DeviceProfile(key=candidate.key, role=candidate.kind))
    if not profile.frequency and profile.channel:
        profile.frequency = channel_to_frequency(profile.channel)
    missing = []
    for label, value in [
        ("Frequency", profile.frequency),
        ("RSSI", profile.strongest_rssi),
        ("Uptime", profile.uptime),
        ("Firmware", profile.firmware),
    ]:
        if not value:
            missing.append(label)
    lines = [
        f"{candidate.kind}: {candidate.value}",
        f"Confidence: {confidence_badge(candidate.confidence)} ({candidate.confidence})",
        "",
        "Inferred Device Types",
    ]
    top_types = [
        (dtype, score, profile.device_type_evidence.get(dtype, []))
        for dtype, score in sorted(profile.device_type_scores.items(), key=lambda item: (-item[1], item[0]))[:10]
    ]
    if top_types:
        for index, (dtype, score, evidence) in enumerate(top_types, 1):
            lines.append(f"{index}. {dtype}: {score}%")
            for clue in evidence[:3]:
                lines.append(f"   - {clue}")
    else:
        lines.append("- Not enough device-specific evidence.")
    lines.extend([
        "",
        "Identity",
        f"- Role: {profile.role or candidate.kind}",
        f"- MAC: {profile.mac or (candidate.value if is_mac(candidate.value) else '-')}",
        f"- IP(s): {', '.join(sorted(profile.ips)) or (candidate.value if candidate.kind == 'IP' else '-')}",
        f"- Hostname(s): {', '.join(sorted(profile.hostnames)) or '-'}",
        f"- OUI vendor/prefix: {profile.vendor or '-'}",
        f"- DHCP vendor/user class: {', '.join(sorted(profile.dhcp_vendor_classes)) or '-'}",
        f"- DHCP parameter list(s): {', '.join(sorted(profile.dhcp_parameter_lists)) or '-'}",
        f"- Discovery protocol(s): {', '.join(sorted(profile.discovery_protocols)) or '-'}",
        f"- Management IP(s): {', '.join(sorted(profile.management_ips, key=str)) or '-'}",
        f"- SSID(s): {', '.join(sorted(profile.ssids)) or '-'}",
        f"- BSSID(s): {', '.join(sorted(profile.bssids)) or '-'}",
        f"- Role hints: {', '.join(sorted(hint for hint in profile.role_hints if hint)) or '-'}",
        "",
        "Network Configuration",
        f"- DHCP server(s): {', '.join(sorted(profile.dhcp_servers, key=str)) or '-'}",
        f"- Router/gateway option(s): {', '.join(sorted(profile.dhcp_routers, key=str)) or '-'}",
        f"- DNS server option(s): {', '.join(sorted(profile.dhcp_dns_servers, key=str)) or '-'}",
        f"- Subnet mask(s): {', '.join(sorted(profile.dhcp_subnet_masks)) or '-'}",
        f"- Requested/leased IP(s): {', '.join(sorted(profile.dhcp_requested_ips, key=str)) or '-'}",
        "",
        "Mesh / Topology",
        f"- Topology role(s): {', '.join(sorted(profile.topology_roles)) or '-'}",
        f"- Mesh ID(s): {', '.join(sorted(profile.mesh_ids)) or '-'}",
        f"- Mesh peer(s): {', '.join(sorted(profile.mesh_peers)) or '-'}",
        f"- HWMP peer(s): {', '.join(sorted(profile.hwmp_peers)) or '-'}",
        f"- WDS/backhaul peer(s): {', '.join(sorted(profile.wds_peers)) or '-'}",
        f"- Neighbor report BSSID(s): {', '.join(sorted(profile.neighbor_bssids)) or '-'}",
        f"- RNR BSSID(s): {', '.join(sorted(profile.rnr_bssids)) or '-'}",
        f"- Mobility domain(s): {', '.join(sorted(profile.mobility_domains)) or '-'}",
        f"- Vendor AP name/model/serial: {', '.join(sorted(profile.vendor_ap_names)) or '-'}",
        f"- Vendor mesh clue(s): {', '.join(sorted(profile.vendor_mesh_clues)) or '-'}",
        "",
        "Device",
        f"- Make: {profile.make or '-'}",
        f"- Model: {profile.model or '-'}",
        f"- Platform: {profile.platform or '-'}",
        f"- Software: {profile.software or '-'}",
        f"- Firmware: {profile.firmware or '-'}",
        f"- Serial: {profile.serial or '-'}",
        f"- Port/interface: {', '.join(sorted(profile.port_ids | profile.interface_names)) or '-'}",
        f"- VLAN(s): {', '.join(sorted(profile.vlans)) or '-'}",
        "",
        "Radio",
        f"- Channel: {profile.channel or '-'}",
        f"- All observed channels: {', '.join(sorted(profile.channels, key=lambda item: int(item) if item.isdigit() else 9999)) or '-'}",
        f"- Band: {profile.band or frequency_to_band(profile.frequency, profile.channel) or '-'}",
        f"- Frequency: {profile.frequency or '-'}",
        f"- All observed frequencies: {', '.join(sorted(profile.frequencies)) or '-'}",
        f"- Strongest RSSI: {profile.strongest_rssi or '-'}",
        f"- Average RSSI: {profile.average_rssi or '-'}",
        f"- First frame: {profile.first_seen or '-'}",
        f"- Last frame: {profile.last_seen or '-'}",
        f"- Profile frame sightings: {profile.frame_count or '-'}",
        "",
        "Security",
        f"- Encryption: {profile.encryption or '-'}",
        f"- AKM: {profile.akm or '-'}",
        f"- EAPOL: {', '.join(sorted(profile.handshakes)) or '-'}",
        f"- PMKID: {', '.join(sorted(profile.pmkids)) or '-'}",
        "",
        "Decrypted Traffic",
        f"- IPs: {', '.join(sorted(profile.ips)) or '-'}",
        f"- Protocols: {', '.join(sorted(profile.protocols)) or '-'}",
        f"- Peers: {', '.join(sorted(profile.peers)) or '-'}",
        f"- DNS queries: {', '.join(sorted(profile.dns_queries)) or '-'}",
        f"- Reverse DNS queries: {', '.join(sorted(profile.reverse_dns_queries)) or '-'}",
        f"- Service discovery names: {', '.join(sorted(profile.service_discovery_names)) or '-'}",
        f"- NBNS/LLMNR names: {', '.join(sorted(profile.nbns_names)) or '-'}",
        f"- HTTP hosts: {', '.join(sorted(profile.http_hosts)) or '-'}",
        f"- HTTP URIs: {', '.join(sorted(profile.http_uris)) or '-'}",
        f"- HTTP user agents: {', '.join(sorted(profile.http_user_agents)) or '-'}",
        f"- HTTP servers: {', '.join(sorted(profile.http_servers)) or '-'}",
        f"- HTTP auth realms: {', '.join(sorted(profile.http_auth_realms)) or '-'}",
        f"- Credential indicators: {', '.join(sorted(profile.credential_indicators)) or '-'}",
        f"- TLS SNI: {', '.join(sorted(profile.tls_sni)) or '-'}",
        f"- TLS JA3: {', '.join(sorted(profile.tls_ja3)) or '-'}",
        f"- Services: {', '.join(sorted(profile.services)) or '-'}",
    ])
    warnings = set(profile.warnings)
    for item in missing:
        warnings.add(f"{item} unavailable in collected capture fields")
    if warnings:
        lines.extend(["", "Warnings", *[f"- {warning}" for warning in sorted(warnings)]])
    return "\n".join(lines)


def render_device_graph(candidate: Candidate | None, result: AnalysisResult | None) -> str:
    if not candidate or not result:
        return "Select a row to see related identifiers."
    profile = result.profiles.get(candidate.key, DeviceProfile(key=candidate.key, role=candidate.kind))
    lines = [f"{candidate.kind} {candidate.value}"]
    related = sorted(candidate.related)
    for bssid in sorted(profile.bssids):
        lines.append(f"  -> BSSID {bssid}")
        for row in result.client_rows:
            if row.get("BSSID") == bssid:
                lines.append(f"       -> {row.get('Role', 'Device')} {row.get('MAC', '')}")
    for ssid in sorted(profile.ssids):
        lines.append(f"  -> SSID {ssid}")
    for ip in sorted(profile.ips):
        lines.append(f"  -> IP {ip}")
    for host in sorted(profile.hostnames):
        lines.append(f"  -> Hostname {host}")
    for peer in sorted(profile.peers):
        lines.append(f"  -> Talks with {peer}")
    for peer in sorted(profile.mesh_peers | profile.hwmp_peers):
        lines.append(f"  -> Mesh peer {peer}")
    for peer in sorted(profile.wds_peers):
        lines.append(f"  -> WDS/backhaul peer {peer}")
    for bssid in sorted(profile.neighbor_bssids):
        lines.append(f"  -> Neighbor report BSSID {bssid}")
    for bssid in sorted(profile.rnr_bssids):
        lines.append(f"  -> RNR BSSID {bssid}")
    for mesh_id in sorted(profile.mesh_ids):
        lines.append(f"  -> Mesh ID {mesh_id}")
    for item in related:
        if item and item not in profile.bssids and item not in profile.ssids:
            lines.append(f"  -> Related {item}")
    if len(lines) == 1:
        lines.append("  -> No additional relationships discovered yet.")
    return "\n".join(lines)


def render_traffic_detail(candidate: Candidate | None, result: AnalysisResult | None) -> str:
    if not candidate or not result:
        return "Select a row to see traffic details."
    profile = result.profiles.get(candidate.key, DeviceProfile(key=candidate.key, role=candidate.kind))
    identifiers = set(profile.ips)
    if candidate.kind == "IP":
        identifiers.add(candidate.value)
    conversations = [
        row
        for row in result.conversation_rows
        if row.get("Source IP") in identifiers or row.get("Destination IP") in identifiers
    ]
    lines = [
        f"{candidate.kind}: {candidate.value}",
        "",
        "Traffic Summary",
        f"- Protocols: {', '.join(sorted(profile.protocols)) or '-'}",
        f"- Peers: {', '.join(sorted(profile.peers)) or '-'}",
        f"- DNS queries: {', '.join(sorted(profile.dns_queries)) or '-'}",
        f"- Reverse DNS queries: {', '.join(sorted(profile.reverse_dns_queries)) or '-'}",
        f"- Service discovery names: {', '.join(sorted(profile.service_discovery_names)) or '-'}",
        f"- NBNS/LLMNR names: {', '.join(sorted(profile.nbns_names)) or '-'}",
        f"- HTTP hosts: {', '.join(sorted(profile.http_hosts)) or '-'}",
        f"- HTTP URIs: {', '.join(sorted(profile.http_uris)) or '-'}",
        f"- Hostnames: {', '.join(sorted(profile.hostnames)) or '-'}",
        f"- Role hints: {', '.join(sorted(hint for hint in profile.role_hints if hint)) or '-'}",
        "",
        "Conversations",
    ]
    if not conversations:
        lines.append("- No IP conversations tied to this selection.")
    else:
        for row in conversations[:40]:
            lines.append(
                f"- {row.get('Frames', '0')} frames: {row.get('Source IP', '-')}:{row.get('Source Port', '')} -> "
                f"{row.get('Destination IP', '-')}:{row.get('Destination Port', '')} {row.get('Protocol', '')}"
            )
        if len(conversations) > 40:
            lines.append(f"- ... {len(conversations) - 40} more summarized conversations omitted from this view")
    return "\n".join(lines)


def run_cli(args: argparse.Namespace) -> int:
    result = APAnalyzer(
        file_path=args.file,
        ssid=args.ssid or "",
        mac=args.mac or "",
        ip=args.ip or "",
        mac_role=args.mac_role,
        password=args.password or "",
        temporal_key=args.tk or "",
        analysis_level=args.analysis_level,
        tshark_path=args.tshark,
    ).analyze()
    if args.json:
        result.export_json(Path(args.json))
    if args.markdown:
        result.export_markdown(Path(args.markdown))
    print(f"Candidates: {len(result.candidates)}")
    for message in result.messages:
        print(f"Message: {message}")
    for candidate in result.sorted_candidates()[:20]:
        print(f"{candidate.confidence:>3}  {candidate.kind:<14} {candidate.value}")
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Terminal GUI AP/network capture analyzer")
    parser.add_argument("--file", "-f", default="", help="Capture file path")
    parser.add_argument("--ssid", default="", help="Known SSID or SSID fragment")
    parser.add_argument("--mac", default="", help="Known MAC/BSSID/client address")
    parser.add_argument("--ip", default="", help="Known IPv4/IPv6 address")
    parser.add_argument("--mac-role", default="Unknown", choices=["Unknown", "BSSID", "Client", "Wired/Upstream", "MAC"])
    parser.add_argument("--password", default="", help="WPA password/PSK for decryption")
    parser.add_argument("--tk", default="", help="Temporal key or GTK for decryption")
    parser.add_argument("--analysis-level", default="deep", choices=["basic", "moderate", "deep"], help="Analysis depth to run")
    parser.add_argument("--tshark", default="tshark", help="tshark executable path")
    parser.add_argument("--cli", action="store_true", help="Run once without the terminal GUI")
    parser.add_argument("--json", default="", help="Export JSON report path")
    parser.add_argument("--markdown", "--text", dest="markdown", default="", help="Export Markdown report path")
    return parser


def main() -> int:
    args = build_parser().parse_args()
    if args.cli:
        return run_cli(args)

    try:
        from textual import on, work
        from textual.app import App, ComposeResult
        from textual.containers import Horizontal, Vertical, VerticalScroll
        from textual.screen import ModalScreen
        from textual.widgets import Button, DataTable, DirectoryTree, Footer, Header, Input, Label, Select, Static, TabbedContent, TabPane
    except (ImportError, ModuleNotFoundError) as exc:
        try:
            from importlib.metadata import version

            textual_version = version("textual")
        except Exception:
            textual_version = "not installed"
        print("The terminal GUI requires a modern Textual release.")
        print(f"Detected Textual: {textual_version}")
        print(f"Import error: {exc}")
        print()
        print("Ubuntu's apt package can be very old. Install the Python package instead:")
        print("  python3 -m pip install --user --upgrade 'textual>=0.86.0'")
        print()
        print("Or use an isolated environment:")
        print("  python3 -m venv ~/.venvs/ap-analyzer")
        print("  ~/.venvs/ap-analyzer/bin/python -m pip install 'textual>=0.86.0'")
        print("  ~/.venvs/ap-analyzer/bin/python /opt/xbin/ap_analyzer.py")
        print()
        print("You can still run the non-GUI mode with --cli after tshark is installed.")
        return 2

    class FilePicker(ModalScreen[str]):
        DEFAULT_CSS = """
        FilePicker {
            align: center middle;
        }
        #picker-panel {
            width: 80%;
            height: 80%;
            border: solid $accent;
            background: $surface;
        }
        """

        def __init__(self, start_path: str) -> None:
            super().__init__()
            path = Path(start_path or os.getcwd()).expanduser()
            self.start_path = str(path.parent if path.is_file() else path)

        def compose(self) -> ComposeResult:
            with Vertical(id="picker-panel"):
                yield Label("Choose a capture file")
                yield Input(value=self.start_path, id="picked-path")
                yield DirectoryTree(self.start_path, id="tree")
                with Horizontal():
                    yield Button("Use Selected", id="use-file", variant="primary")
                    yield Button("Cancel", id="cancel")

        @on(DirectoryTree.FileSelected)
        def file_selected(self, event: DirectoryTree.FileSelected) -> None:
            self.query_one("#picked-path", Input).value = str(event.path)

        @on(Button.Pressed, "#use-file")
        def use_file(self) -> None:
            self.dismiss(self.query_one("#picked-path", Input).value)

        @on(Button.Pressed, "#cancel")
        def cancel(self) -> None:
            self.dismiss("")

    class APAnalyzerApp(App):
        CSS = """
        Screen {
            layout: vertical;
        }
        #inputs {
            height: auto;
            padding: 1;
            border: solid $primary;
        }
        #input-row-a, #input-row-b, #actions {
            height: auto;
        }
        Input {
            width: 1fr;
        }
        Select {
            width: 24;
        }
        Button {
            margin-right: 1;
        }
        #body {
            height: 1fr;
        }
        #tabs {
            width: 2fr;
        }
        #detail {
            width: 1fr;
            border: solid $accent;
        }
        #evidence-scroll, #profile-scroll, #graph-scroll, #traffic-scroll {
            height: 1fr;
            overflow-y: auto;
        }
        #evidence-detail, #profile-detail, #graph-detail, #traffic-detail {
            padding: 1;
        }
        DataTable {
            height: 1fr;
        }
        #status {
            height: 3;
            padding: 0 1;
        }
        """
        BINDINGS = [
            ("q", "quit", "Quit"),
            ("ctrl+r", "analyze", "Analyze"),
            ("ctrl+s", "export_report", "Export"),
            ("ctrl+c", "copy_detail", "Copy Detail"),
        ]

        def __init__(self, initial_args: argparse.Namespace) -> None:
            super().__init__()
            self.initial_args = initial_args
            self.current_result: AnalysisResult | None = None
            self.candidate_by_key: dict[str, Candidate] = {}
            self.sort_state: dict[str, tuple[str, bool]] = {}
            self.selected_candidate: Candidate | None = None
            self.selected_detail_text: str = ""

        def compose(self) -> ComposeResult:
            yield Header()
            with Vertical(id="inputs"):
                with Horizontal(id="input-row-a"):
                    yield Input(value=self.initial_args.file, placeholder="Capture file path", id="file")
                    yield Button("Browse", id="browse")
                    yield Input(value=self.initial_args.ssid, placeholder="SSID or SSID fragment", id="ssid")
                with Horizontal(id="input-row-b"):
                    yield Input(value=self.initial_args.mac, placeholder="MAC/BSSID/client address", id="mac")
                    yield Select(
                        [("Unknown", "Unknown"), ("BSSID/AP", "BSSID"), ("Client", "Client"), ("Wired/Upstream", "Wired/Upstream"), ("Generic MAC", "MAC")],
                        value=self.initial_args.mac_role,
                        id="mac-role",
                    )
                    yield Input(value=self.initial_args.ip, placeholder="IPv4 / IPv6 address", id="ip")
                    yield Input(value=self.initial_args.password, placeholder="Password / PSK", password=True, id="password")
                    yield Input(value=self.initial_args.tk, placeholder="Temporal key / GTK", password=True, id="tk")
                    yield Select(
                        [("Basic", "basic"), ("Moderate", "moderate"), ("Deep", "deep")],
                        value=self.initial_args.analysis_level,
                        id="analysis-level",
                    )
                with Horizontal(id="actions"):
                    yield Button("Analyze", id="analyze", variant="primary")
                    yield Button("Export Report", id="export")
                    yield Button("Copy Detail", id="copy-detail")
                    yield Button("Export Selected", id="export-selected")
                    yield Button("Clear", id="clear")
                    yield Select(
                        [
                            ("All APs", "all"),
                            ("High confidence", "high"),
                            ("Hide empty SSIDs", "hide-empty"),
                            ("With handshakes", "handshakes"),
                            ("Primary/exact only", "primary"),
                            ("Same BSSID family", "family"),
                        ],
                        value="all",
                        id="ap-filter",
                    )
                    yield Select(
                        [
                            ("Confirmed/probable local IPs", "local"),
                            ("All IPs", "all"),
                            ("Confirmed only", "confirmed"),
                            ("Show probed targets", "probed"),
                            ("External IPs", "external"),
                            ("Special/broadcast", "special"),
                        ],
                        value="local",
                        id="ip-filter",
                    )
            with Horizontal(id="body"):
                with TabbedContent(id="tabs"):
                    with TabPane("Candidates", id="candidates-tab"):
                        yield DataTable(id="candidates")
                    with TabPane("APs", id="aps-tab"):
                        yield DataTable(id="aps")
                    with TabPane("AP Observations", id="ap-observations-tab"):
                        yield DataTable(id="ap-observations")
                    with TabPane("SSID Groups", id="ssid-groups-tab"):
                        yield DataTable(id="ssid-groups")
                    with TabPane("Topology", id="topology-tab"):
                        yield DataTable(id="topology")
                    with TabPane("Discovery", id="discovery-tab"):
                        yield DataTable(id="discovery")
                    with TabPane("Clients", id="clients-tab"):
                        yield DataTable(id="clients")
                    with TabPane("IP Devices", id="ip-devices-tab"):
                        yield DataTable(id="ip-devices")
                    with TabPane("Conversations", id="conversations-tab"):
                        yield DataTable(id="conversations")
                    with TabPane("Scans", id="scans-tab"):
                        yield DataTable(id="scans")
                    with TabPane("Open Services", id="open-services-tab"):
                        yield DataTable(id="open-services")
                    with TabPane("HTTP URIs", id="http-uris-tab"):
                        yield DataTable(id="http-uris")
                    with TabPane("Closed/Other Services", id="closed-services-tab"):
                        yield DataTable(id="closed-services")
                    with TabPane("Device Types", id="device-types-tab"):
                        yield DataTable(id="device-types")
                    with TabPane("Security", id="security-tab"):
                        yield DataTable(id="security")
                    with TabPane("Handshakes", id="handshakes-tab"):
                        yield DataTable(id="handshakes")
                    with TabPane("Decrypted", id="decrypted-tab"):
                        yield DataTable(id="decrypted")
                    with TabPane("Credentials", id="credentials-tab"):
                        yield DataTable(id="credentials")
                    with TabPane("Messages", id="messages-tab"):
                        yield Static("No messages yet.", id="messages")
                with TabbedContent(id="detail"):
                    with TabPane("Evidence", id="evidence-pane"):
                        with VerticalScroll(id="evidence-scroll"):
                            yield Static("Select a row to see why it was identified as related.", id="evidence-detail")
                    with TabPane("Profile", id="profile-pane"):
                        with VerticalScroll(id="profile-scroll"):
                            yield Static("Select a row to see device information.", id="profile-detail")
                    with TabPane("Graph", id="graph-pane"):
                        with VerticalScroll(id="graph-scroll"):
                            yield Static("Select a row to see related identifiers.", id="graph-detail")
                    with TabPane("Traffic", id="traffic-pane"):
                        with VerticalScroll(id="traffic-scroll"):
                            yield Static("Select a row to see traffic details.", id="traffic-detail")
            yield Static("Ready. Enter whatever identifiers you have, then click Analyze.", id="status")
            yield Footer()

        def on_mount(self) -> None:
            self._setup_tables()

        def _setup_tables(self) -> None:
            table_specs = {
                "candidates": ["Score", "Kind", "Value", "Labels", "Related"],
                "aps": ["Rank", "BSSID", "SSIDs", "Channel", "All Channels", "Band", "Frequency", "All Freqs", "Best RSSI", "Avg RSSI", "Security", "Handshakes", "Sightings", "First Frame", "Last Frame", "Manufacturer", "Model", "Why"],
                "ap-observations": ["BSSID", "SSID", "Channel", "HT Primary", "Frequency", "RSSI", "Manufacturer", "Model", "Device", "Why"],
                "ssid-groups": ["SSID", "BSSIDs", "Bands", "Channels", "Best RSSI", "AP Count", "Ranks"],
                "topology": ["Confidence", "Role Guess", "Device", "Kind", "Mesh ID", "Mesh Peers", "WDS Peers", "Neighbor BSSIDs", "RNR BSSIDs", "Mobility Domain", "Vendor/AP Name", "Sightings", "First Frame", "Last Frame", "Why"],
                "discovery": ["Protocol", "MAC", "IP", "Hostname/ID", "Platform/Model", "Software/Firmware", "Port/Interface", "Uptime/TTL", "Role Hints", "Sightings", "First Frame", "Last Frame"],
                "clients": ["BSSID", "MAC", "Role", "Why"],
                "ip-devices": ["IP", "Evidence", "Scope", "MAC", "Hostnames", "Role Hints", "DHCP Server", "Router", "DNS Servers", "Open TCP", "Protocols", "Peers", "DNS Queries", "First Frame", "Last Frame", "Sightings"],
                "conversations": ["Source IP", "Destination IP", "Source MAC", "Destination MAC", "Protocol", "Source Port", "Destination Port", "Frames"],
                "scans": ["Scanner", "Targets", "Responsive", "Target Sample", "Open Ports Seen"],
                "open-services": ["IP", "Port", "Proto", "State", "Service Hint"],
                "http-uris": ["IP", "Port", "Host", "Status", "URI", "Server", "Source", "Frame"],
                "closed-services": ["IP", "Port", "Proto", "State", "Service Hint"],
                "device-types": ["Kind", "Value", "Best Guess", "Confidence", "Alternatives", "Top Evidence"],
                "security": ["BSSID", "Pairwise Cipher", "AKM", "MFPR", "MFPC"],
                "handshakes": ["Frame", "BSSID", "Source", "Destination", "EAPOL Msg", "PMKID", "GTK", "Why"],
                "decrypted": ["Frame", "Protocol", "BSSID", "Source MAC", "Destination MAC", "Source IP", "Destination IP"],
                "credentials": ["Source", "Destination", "Source MAC", "Host", "Type", "Username", "Secret/Hash", "Field", "Frame", "URI"],
            }
            for table_id, columns in table_specs.items():
                table = self.query_one(f"#{table_id}", DataTable)
                table.cursor_type = "row"
                table.zebra_stripes = True
                table.clear(columns=True)
                table.add_columns(*columns)

        @on(Button.Pressed, "#browse")
        def browse(self) -> None:
            file_input = self.query_one("#file", Input)
            self.push_screen(FilePicker(file_input.value or os.getcwd()), self._set_file)

        def _set_file(self, value: str) -> None:
            if value:
                self.query_one("#file", Input).value = value

        @on(Button.Pressed, "#analyze")
        def analyze_button(self) -> None:
            self.action_analyze()

        def action_analyze(self) -> None:
            self.query_one("#status", Static).update("Analyzing capture with tshark...")
            self._clear_tables()
            params = {
                "file_path": self.query_one("#file", Input).value,
                "ssid": self.query_one("#ssid", Input).value,
                "mac": self.query_one("#mac", Input).value,
                "ip": self.query_one("#ip", Input).value,
                "mac_role": str(self.query_one("#mac-role", Select).value),
                "password": self.query_one("#password", Input).value,
                "temporal_key": self.query_one("#tk", Input).value,
                "analysis_level": str(self.query_one("#analysis-level", Select).value),
                "tshark_path": self.initial_args.tshark,
            }
            self.run_analysis(params)

        @work(thread=True)
        def run_analysis(self, params: dict[str, str]) -> None:
            analyzer = APAnalyzer(**params)
            result = analyzer.analyze()
            self.call_from_thread(self.show_result, result)

        def show_result(self, result: AnalysisResult) -> None:
            self.current_result = result
            self.candidate_by_key = {candidate.key: candidate for candidate in result.sorted_candidates()}
            self._fill_candidates(result)
            self._fill_rows("aps", self._filtered_ap_rows(result.ap_rows))
            self._fill_rows("ap-observations", result.ap_observation_rows)
            self._fill_rows("ssid-groups", result.ssid_group_rows)
            self._fill_rows("topology", result.topology_rows)
            self._fill_rows("discovery", result.discovery_rows)
            self._fill_rows("clients", result.client_rows)
            self._fill_rows("ip-devices", self._filtered_ip_rows(result.ip_device_rows))
            self._fill_rows("conversations", result.conversation_rows)
            self._fill_rows("scans", result.scan_rows)
            self._fill_rows("open-services", result.open_service_rows)
            self._fill_rows("http-uris", result.http_uri_rows)
            self._fill_rows("closed-services", result.closed_service_rows)
            self._fill_rows("device-types", result.device_type_rows)
            self._fill_rows("security", result.security_rows)
            self._fill_rows("handshakes", result.handshake_rows)
            self._fill_rows("decrypted", result.decrypted_rows)
            self._fill_rows("credentials", result.credential_rows)
            self.query_one("#messages", Static).update("\n".join(result.messages) if result.messages else "No messages.")
            self.query_one("#status", Static).update(f"Done. {len(result.candidates)} identifiers found. Select any row for Evidence, Profile, and Graph.")

        def _clear_tables(self) -> None:
            for table_id in ["candidates", "aps", "ap-observations", "ssid-groups", "topology", "discovery", "clients", "ip-devices", "conversations", "scans", "open-services", "http-uris", "closed-services", "device-types", "security", "handshakes", "decrypted", "credentials"]:
                self.query_one(f"#{table_id}", DataTable).clear()
            self.query_one("#messages", Static).update("Working...")
            self.query_one("#evidence-detail", Static).update("Select a row to see why it was identified as related.")
            self.query_one("#profile-detail", Static).update("Select a row to see device information.")
            self.query_one("#graph-detail", Static).update("Select a row to see related identifiers.")
            self.query_one("#traffic-detail", Static).update("Select a row to see traffic details.")

        def _fill_candidates(self, result: AnalysisResult) -> None:
            table = self.query_one("#candidates", DataTable)
            table.clear()
            for candidate in result.sorted_candidates():
                table.add_row(
                    str(candidate.confidence),
                    candidate.kind,
                    candidate.value,
                    ", ".join(sorted(candidate.labels)),
                    ", ".join(sorted(candidate.related)),
                    key=candidate.key,
                )

        def _fill_rows(self, table_id: str, rows: list[dict[str, str]]) -> None:
            table = self.query_one(f"#{table_id}", DataTable)
            table.clear()
            columns = [str(column.label) for column in table.columns.values()]
            for index, row in enumerate(rows):
                candidate_key = self._candidate_key_from_row(row)
                table.add_row(*(row.get(column, "") for column in columns), key=f"{candidate_key}|{table_id}|{index}")

        def _candidate_key_from_row(self, row: dict[str, str]) -> str:
            if row.get("Kind") and row.get("Value"):
                key = f"{row.get('Kind')}:{normalize_ip(row.get('Value', '')) if row.get('Kind') == 'IP' else normalize_mac(row.get('Value', '')) if row.get('Kind') in {'BSSID', 'Client', 'Wired/Upstream', 'MAC'} else row.get('Value')}"
                if key in self.candidate_by_key:
                    return key
            if row.get("Kind") and row.get("Device"):
                kind = row.get("Kind", "")
                key = f"{kind}:{normalize_mac(row.get('Device', '')) if kind in {'BSSID', 'Client', 'Wired/Upstream', 'MAC'} else row.get('Device', '')}"
                if key in self.candidate_by_key:
                    return key
            for kind, field_name in [("MAC", "MAC"), ("IP", "IP"), ("Hostname", "Hostname/ID"), ("IP", "Source"), ("MAC", "Source MAC"), ("IP", "Destination"), ("Hostname", "Host")]:
                value = row.get(field_name, "")
                key = f"{kind}:{normalize_mac(value) if kind == 'MAC' else normalize_ip(value) if kind == 'IP' else value}"
                if key in self.candidate_by_key:
                    return key
            for kind, field_name in [("BSSID", "BSSID"), ("Client", "MAC"), ("Wired/Upstream", "MAC"), ("MAC", "Source MAC"), ("MAC", "Destination MAC"), ("IP", "IP"), ("IP", "Source IP"), ("IP", "Destination IP"), ("IP", "Scanner"), ("SSID", "SSID")]:
                value = row.get(field_name, "")
                key = f"{kind}:{normalize_mac(value) if kind in {'BSSID', 'Client', 'Wired/Upstream', 'MAC'} else normalize_ip(value) if kind == 'IP' else value}"
                if key in self.candidate_by_key:
                    return key
            bssids = [part.strip() for part in row.get("BSSIDs", "").split(",") if part.strip()]
            for bssid in bssids:
                key = f"BSSID:{normalize_mac(bssid)}"
                if key in self.candidate_by_key:
                    return key
            return ""

        def _filtered_ap_rows(self, rows: list[dict[str, str]]) -> list[dict[str, str]]:
            mode = str(self.query_one("#ap-filter", Select).value)
            mac = normalize_mac(self.query_one("#mac", Input).value)
            middle = bssid_middle_octets(mac) if is_mac(mac) else ""
            filtered: list[dict[str, str]] = []
            for row in rows:
                if mode == "high" and row.get("Rank") not in {"Primary", "Related"}:
                    continue
                ssid_parts = [part.strip() for part in row.get("SSIDs", "").split(",") if part.strip()]
                has_named_ssid = any(part not in {"-", "<EMPTY SSID>"} for part in ssid_parts)
                if mode == "hide-empty" and not has_named_ssid:
                    continue
                if mode == "handshakes" and row.get("Handshakes", "-") == "-":
                    continue
                if mode == "primary" and row.get("Rank") != "Primary":
                    continue
                if mode == "family" and middle and bssid_middle_octets(row.get("BSSID", "")) != middle:
                    continue
                filtered.append(row)
            return filtered

        @on(Select.Changed, "#ap-filter")
        def ap_filter_changed(self) -> None:
            if not self.current_result:
                return
            self._fill_rows("aps", self._filtered_ap_rows(self.current_result.ap_rows))
            self.query_one("#status", Static).update(f"AP filter: {self.query_one('#ap-filter', Select).value}")

        def _filtered_ip_rows(self, rows: list[dict[str, str]]) -> list[dict[str, str]]:
            mode = str(self.query_one("#ip-filter", Select).value)
            filtered: list[dict[str, str]] = []
            for row in rows:
                evidence = row.get("Evidence", "")
                scope = row.get("Scope", "")
                if mode == "local" and not (evidence in {"Confirmed", "Probable"} and scope == "local/private"):
                    continue
                if mode == "confirmed" and evidence != "Confirmed":
                    continue
                if mode == "probed" and evidence != "Probed":
                    continue
                if mode == "external" and evidence != "External":
                    continue
                if mode == "special" and evidence != "Special":
                    continue
                filtered.append(row)
            return filtered

        @on(Select.Changed, "#ip-filter")
        def ip_filter_changed(self) -> None:
            if not self.current_result:
                return
            self._fill_rows("ip-devices", self._filtered_ip_rows(self.current_result.ip_device_rows))
            self.query_one("#status", Static).update(f"IP filter: {self.query_one('#ip-filter', Select).value}")

        @on(DataTable.RowSelected)
        def row_selected(self, event: DataTable.RowSelected) -> None:
            key = str(event.row_key.value).split("|", 1)[0]
            candidate = self.candidate_by_key.get(key)
            self.selected_candidate = candidate
            self.query_one("#evidence-detail", Static).update(render_candidate_detail(candidate))
            self.query_one("#profile-detail", Static).update(render_device_profile(candidate, self.current_result))
            self.query_one("#graph-detail", Static).update(render_device_graph(candidate, self.current_result))
            self.query_one("#traffic-detail", Static).update(render_traffic_detail(candidate, self.current_result))
            self.selected_detail_text = self._selected_detail_bundle(candidate)

        def _selected_detail_bundle(self, candidate: Candidate | None) -> str:
            return "\n\n".join(
                [
                    "Evidence\n" + render_candidate_detail(candidate),
                    "Profile\n" + render_device_profile(candidate, self.current_result),
                    "Graph\n" + render_device_graph(candidate, self.current_result),
                    "Traffic\n" + render_traffic_detail(candidate, self.current_result),
                ]
            )

        @on(DataTable.HeaderSelected)
        def header_selected(self, event: DataTable.HeaderSelected) -> None:
            table = event.data_table
            table_id = table.id or "table"
            label = str(event.label)
            previous_label, previous_reverse = self.sort_state.get(table_id, ("", False))
            reverse = not previous_reverse if previous_label == label else False
            self.sort_state[table_id] = (label, reverse)
            table.sort(event.column_key, key=self._sort_key_for(label), reverse=reverse)
            direction = "descending" if reverse else "ascending"
            self.query_one("#status", Static).update(f"Sorted {table_id} by {label} {direction}")

        def _sort_key_for(self, label: str):
            numeric_labels = {
                "Score",
                "Channel",
                "HT Primary",
                "Frequency",
                "Best RSSI",
                "Avg RSSI",
                "RSSI",
                "Sightings",
                "First Frame",
                "Last Frame",
                "AP Count",
                "Frames",
                "Targets",
                "Responsive",
                "Port",
                "Frame",
            }
            rank_order = {"Primary": 0, "Related": 1, "Possible": 2, "Weak": 3}

            def key(value):
                text = str(value)
                if label == "Rank":
                    return rank_order.get(text, 9)
                if label in numeric_labels:
                    match = re.search(r"-?\d+(?:\.\d+)?", text)
                    return float(match.group(0)) if match else float("inf")
                return text.lower()

            return key

        @on(Button.Pressed, "#export")
        def export_button(self) -> None:
            self.action_export_report()

        def action_export_report(self) -> None:
            if not self.current_result:
                self.query_one("#status", Static).update("Nothing to export yet. Run Analyze first.")
                return
            stamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            base = Path.cwd() / f"ap_analysis_{stamp}"
            self.current_result.export_markdown(base.with_suffix(".md"))
            self.current_result.export_json(base.with_suffix(".json"))
            self.query_one("#status", Static).update(f"Exported {base.with_suffix('.md').name} and {base.with_suffix('.json').name}")

        @on(Button.Pressed, "#copy-detail")
        def copy_detail_button(self) -> None:
            self.action_copy_detail()

        def action_copy_detail(self) -> None:
            if not self.selected_detail_text:
                self.query_one("#status", Static).update("Select a device or row before copying detail.")
                return
            path = Path.cwd() / "last_selected_device.md"
            if self.current_result and self.selected_candidate:
                self.current_result.export_selected_markdown(self.selected_candidate, path)
            else:
                path.write_text(self.selected_detail_text, encoding="utf-8")
            copied = self._copy_to_clipboard(self.selected_detail_text)
            suffix = "Copied to clipboard" if copied else "Clipboard tool unavailable"
            self.query_one("#status", Static).update(f"{suffix}; wrote {path.name}")

        def _copy_to_clipboard(self, text: str) -> bool:
            commands = [["clip"]] if os.name == "nt" else [["wl-copy"], ["xclip", "-selection", "clipboard"], ["xsel", "--clipboard", "--input"]]
            for command in commands:
                if shutil.which(command[0]):
                    try:
                        subprocess.run(command, input=text, text=True, check=True)
                        return True
                    except Exception:
                        continue
            return False

        @on(Button.Pressed, "#export-selected")
        def export_selected_button(self) -> None:
            self.action_export_selected()

        def action_export_selected(self) -> None:
            if not self.selected_candidate or not self.selected_detail_text:
                self.query_one("#status", Static).update("Select a device or row before exporting selected detail.")
                return
            stamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            safe_value = re.sub(r"[^A-Za-z0-9_.-]+", "_", self.selected_candidate.value)
            path = Path.cwd() / f"selected_{self.selected_candidate.kind}_{safe_value}_{stamp}.md"
            self.current_result.export_selected_markdown(self.selected_candidate, path)
            self.query_one("#status", Static).update(f"Exported selected detail to {path.name}")

        @on(Button.Pressed, "#clear")
        def clear_button(self) -> None:
            for input_id in ["ssid", "mac", "ip", "password", "tk"]:
                self.query_one(f"#{input_id}", Input).value = ""
            self._clear_tables()
            self.query_one("#status", Static).update("Inputs cleared.")

    APAnalyzerApp(args).run()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
