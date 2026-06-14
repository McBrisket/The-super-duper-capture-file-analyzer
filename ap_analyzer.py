#!/usr/bin/env python3
"""
Terminal GUI for correlating AP/network identifiers in 802.11 captures.

The app keeps every discovered identifier tied to evidence, so selecting a
candidate in the UI explains why it was considered related to the user input.
"""

from __future__ import annotations

import argparse
import csv
import json
import os
import ipaddress
import re
import shutil
import subprocess
import sys
from collections import Counter
from dataclasses import asdict, dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Iterable


MAC_RE = re.compile(r"^(?:[0-9a-fA-F]{2}:){5}[0-9a-fA-F]{2}$")
BAD_MAC_PREFIXES = ("ff:ff:ff:ff:ff:ff", "33:33:", "01:00:", "01:80:c2:")
LOCAL_MULTICAST_IPS = ("224.", "239.", "255.255.255.255")


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
    tls_sni: set[str] = field(default_factory=set)
    tls_ja3: set[str] = field(default_factory=set)
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
            "messages": self.messages,
            "candidates": [clean_candidate(c) for c in self.sorted_candidates()],
            "profiles": {key: clean_profile(profile) for key, profile in self.profiles.items()},
            "ap_rows": self.ap_rows,
            "ap_observation_rows": self.ap_observation_rows,
            "ssid_group_rows": self.ssid_group_rows,
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

    def export_text(self, path: Path) -> None:
        lines = [f"AP analysis report - {self.started_at}", ""]
        if self.messages:
            lines.extend(["Messages:", *[f"- {msg}" for msg in self.messages], ""])
        lines.append("Candidates:")
        for candidate in self.sorted_candidates():
            labels = ", ".join(sorted(candidate.labels)) or "-"
            related = ", ".join(sorted(candidate.related)) or "-"
            lines.append(f"- {candidate.kind} {candidate.value} score={candidate.confidence} labels={labels} related={related}")
            for ev in candidate.evidence:
                repeat_text = f", seen {ev.count} times" if ev.count > 1 else ""
                lines.append(f"  * {ev.source}: {ev.reason} (+{ev.score}{repeat_text})")
            profile = self.profile_for(candidate)
            lines.append(f"  Profile: role={profile.role or '-'} mac={profile.mac or '-'} ssid={', '.join(sorted(profile.ssids)) or '-'} channel={profile.channel or '-'} security={profile.encryption or '-'}")
        for title, rows in [
            ("AP rows", self.ap_rows),
            ("AP observations", self.ap_observation_rows),
            ("SSID groups", self.ssid_group_rows),
            ("Client rows", self.client_rows),
            ("IP devices", self.ip_device_rows),
            ("Conversations", self.conversation_rows),
            ("Scans", self.scan_rows),
            ("Services", self.service_rows),
            ("Open services", self.open_service_rows),
            ("Closed/other services", self.closed_service_rows),
            ("Device types", self.device_type_rows),
            ("Security rows", self.security_rows),
            ("Handshake rows", self.handshake_rows),
            ("Decrypted rows", self.decrypted_rows),
        ]:
            lines.extend(["", f"{title}:"])
            if rows:
                fieldnames = sorted({key for row in rows for key in row})
                lines.append("\t".join(fieldnames))
                for row in rows:
                    lines.append("\t".join(row.get(name, "") for name in fieldnames))
            else:
                lines.append("(none)")
        path.write_text("\n".join(lines) + "\n", encoding="utf-8")


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
        tshark_path: str = "tshark",
    ) -> None:
        self.file_path = str(Path(file_path).expanduser())
        self.ssid = ssid.strip()
        self.mac = normalize_mac(mac)
        self.ip = normalize_ip(ip)
        self.mac_role = mac_role
        self.password = password
        self.temporal_key = temporal_key.strip()
        self.extracted_gtks: set[str] = set()
        self.runner = TsharkRunner(tshark_path)
        self.result = AnalysisResult()

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

        if has_wlan:
            self._discover_aps()
            self._inspect_security_and_handshakes()
            self._classify_clients_and_upstream()
            self._extract_gtks()
            self._inspect_decrypted_traffic()
        else:
            self.result.messages.append("No wlan.bssid field found; skipping monitor-mode wireless AP/client analysis.")
        if has_ip:
            self._inspect_ip_traffic()
            decrypt = self._decrypt_options() if has_wlan else []
            if decrypt:
                key_sources = []
                if self.password and self.ssid:
                    key_sources.append("SSID/password")
                if self.temporal_key:
                    key_sources.append("manual TK/GTK")
                if self.extracted_gtks:
                    key_sources.append(f"{len(self.extracted_gtks)} extracted GTK(s)")
                self.result.messages.append(f"Running decrypted IP/name analysis using: {', '.join(key_sources)}.")
                self._inspect_ip_traffic(decrypt=decrypt, source_label="decrypted")
        else:
            self.result.messages.append("No IPv4/ARP fields found; skipping IP device analysis.")
        self.result.ap_observation_rows = uniq_rows(self.result.ap_observation_rows)
        self.result.ap_rows = self._summarize_ap_rows()
        self.result.ssid_group_rows = self._build_ssid_groups()
        self.result.client_rows = uniq_rows(self.result.client_rows)
        self.result.ip_device_rows = self._summarize_ip_devices()
        self.result.conversation_rows = uniq_rows(self.result.conversation_rows)
        self.result.scan_rows = uniq_rows(self.result.scan_rows)
        self.result.service_rows = uniq_rows(self.result.service_rows)
        self.result.open_service_rows = uniq_rows(self.result.open_service_rows)
        self.result.closed_service_rows = uniq_rows(self.result.closed_service_rows)
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
            profile.mac,
            " ".join(profile.hostnames),
            " ".join(profile.dns_queries),
            " ".join(profile.services),
            " ".join(profile.protocols),
            " ".join(profile.role_hints),
            " ".join(profile.dhcp_vendor_classes),
            " ".join(profile.dhcp_servers),
            " ".join(profile.dhcp_routers),
            " ".join(profile.dhcp_dns_servers),
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
        values = [c.value for c in self.result.sorted_candidates() if c.kind == "BSSID" and is_mac(c.value)]
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
                if ip:
                    profile.ips.add(ip)
                if protocol:
                    profile.protocols.add(protocol)
                self._update_radio_profile(profile, row)
                for linked_profile in self._profiles_for_mac(mac):
                    if ip:
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
            "http.request.full_uri",
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
            dhcp_hostnames = row_values(row, "dhcp.option.hostname", "bootp.option.hostname", "dhcp.fqdn.name")
            dhcp_servers = [normalize_ip(value) for value in row_values(row, "dhcp.option.dhcp_server_id", "bootp.option.dhcp_server_id", "dhcp.ip.server", "bootp.ip.server") if is_ip(normalize_ip(value))]
            dhcp_dns_servers = [normalize_ip(value) for value in row_values(row, "dhcp.option.domain_name_server", "bootp.option.domain_name_server") if is_ip(normalize_ip(value))]
            dhcp_routers = [normalize_ip(value) for value in row_values(row, "dhcp.option.router", "bootp.option.router") if is_ip(normalize_ip(value))]
            dhcp_requested_ips = [normalize_ip(value) for value in row_values(row, "dhcp.option.requested_ip_address", "bootp.option.requested_ip_address") if is_ip(normalize_ip(value))]
            dhcp_subnet_masks = row_values(row, "dhcp.option.subnet_mask", "bootp.option.subnet_mask")
            dns_queries = row_values(row, "dns.qry.name", "dns.ptr.domain_name", "nbns.name")
            dns_answers = row_values(row, "dns.resp.name", "dns.srv.instance", "dns.srv.name", "dns.srv.target")
            service_names = row_values(row, "dns.srv.instance", "dns.srv.name", "dns.ptr.domain_name")
            dns_answer_ips = [normalize_ip(value) for value in row_values(row, "dns.a", "dns.aaaa") if is_ip(normalize_ip(value))]
            http_values = row_values(row, "http.host", "http.request.full_uri")
            tls_sni = row_values(row, "tls.handshake.extensions_server_name")

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
                    src_stats.hostnames.update(name for name in dns_answers if name and not is_ip(name))
                    src_stats.services.update(service_names)
                src_stats.dns_queries.update(http_values)
                src_stats.dns_queries.update(tls_sni)
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
                answer_stats.hostnames.update(dns_answers)
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
                    mac_profile.ips.add(host.ip)
                    mac_profile.protocols.update(host.protocols.keys())
                    mac_profile.hostnames.update(host.hostnames)
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
        "Device",
        f"- Make: {profile.make or '-'}",
        f"- Model: {profile.model or '-'}",
        f"- Firmware: {profile.firmware or '-'}",
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
        f"- DNS/name queries: {', '.join(sorted(profile.dns_queries)) or '-'}",
        f"- HTTP user agents: {', '.join(sorted(profile.http_user_agents)) or '-'}",
        f"- HTTP servers: {', '.join(sorted(profile.http_servers)) or '-'}",
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
        f"- DNS/name queries: {', '.join(sorted(profile.dns_queries)) or '-'}",
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
        tshark_path=args.tshark,
    ).analyze()
    if args.json:
        result.export_json(Path(args.json))
    if args.text:
        result.export_text(Path(args.text))
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
    parser.add_argument("--tshark", default="tshark", help="tshark executable path")
    parser.add_argument("--cli", action="store_true", help="Run once without the terminal GUI")
    parser.add_argument("--json", default="", help="Export JSON report path")
    parser.add_argument("--text", default="", help="Export text report path")
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
                "clients": ["BSSID", "MAC", "Role", "Why"],
                "ip-devices": ["IP", "Evidence", "Scope", "MAC", "Hostnames", "Role Hints", "DHCP Server", "Router", "DNS Servers", "Open TCP", "Protocols", "Peers", "DNS Queries", "First Frame", "Last Frame", "Sightings"],
                "conversations": ["Source IP", "Destination IP", "Source MAC", "Destination MAC", "Protocol", "Source Port", "Destination Port", "Frames"],
                "scans": ["Scanner", "Targets", "Responsive", "Target Sample", "Open Ports Seen"],
                "open-services": ["IP", "Port", "Proto", "State", "Service Hint"],
                "closed-services": ["IP", "Port", "Proto", "State", "Service Hint"],
                "device-types": ["Kind", "Value", "Best Guess", "Confidence", "Alternatives", "Top Evidence"],
                "security": ["BSSID", "Pairwise Cipher", "AKM", "MFPR", "MFPC"],
                "handshakes": ["Frame", "BSSID", "Source", "Destination", "EAPOL Msg", "PMKID", "GTK", "Why"],
                "decrypted": ["Frame", "Protocol", "BSSID", "Source MAC", "Destination MAC", "Source IP", "Destination IP"],
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
            self._fill_rows("clients", result.client_rows)
            self._fill_rows("ip-devices", self._filtered_ip_rows(result.ip_device_rows))
            self._fill_rows("conversations", result.conversation_rows)
            self._fill_rows("scans", result.scan_rows)
            self._fill_rows("open-services", result.open_service_rows)
            self._fill_rows("closed-services", result.closed_service_rows)
            self._fill_rows("device-types", result.device_type_rows)
            self._fill_rows("security", result.security_rows)
            self._fill_rows("handshakes", result.handshake_rows)
            self._fill_rows("decrypted", result.decrypted_rows)
            self.query_one("#messages", Static).update("\n".join(result.messages) if result.messages else "No messages.")
            self.query_one("#status", Static).update(f"Done. {len(result.candidates)} identifiers found. Select any row for Evidence, Profile, and Graph.")

        def _clear_tables(self) -> None:
            for table_id in ["candidates", "aps", "ap-observations", "ssid-groups", "clients", "ip-devices", "conversations", "scans", "open-services", "closed-services", "device-types", "security", "handshakes", "decrypted"]:
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
            self.current_result.export_text(base.with_suffix(".txt"))
            self.current_result.export_json(base.with_suffix(".json"))
            self.query_one("#status", Static).update(f"Exported {base.with_suffix('.txt').name} and {base.with_suffix('.json').name}")

        @on(Button.Pressed, "#copy-detail")
        def copy_detail_button(self) -> None:
            self.action_copy_detail()

        def action_copy_detail(self) -> None:
            if not self.selected_detail_text:
                self.query_one("#status", Static).update("Select a device or row before copying detail.")
                return
            path = Path.cwd() / "last_selected_device.txt"
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
            path = Path.cwd() / f"selected_{self.selected_candidate.kind}_{safe_value}_{stamp}.txt"
            path.write_text(self.selected_detail_text, encoding="utf-8")
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
