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
class AnalysisResult:
    candidates: dict[str, Candidate] = field(default_factory=dict)
    profiles: dict[str, DeviceProfile] = field(default_factory=dict)
    ap_rows: list[dict[str, str]] = field(default_factory=list)
    ap_observation_rows: list[dict[str, str]] = field(default_factory=list)
    ssid_group_rows: list[dict[str, str]] = field(default_factory=list)
    client_rows: list[dict[str, str]] = field(default_factory=list)
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
        value = normalize_mac(value) if kind in {"BSSID", "Client", "Wired/Upstream", "MAC"} else value
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
        elif kind == "SSID":
            profile.ssids.add(value)
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

    def fields(
        self,
        file_path: str,
        display_filter: str,
        fields: list[str],
        decrypt: list[str] | None = None,
    ) -> tuple[list[dict[str, str]], list[str]]:
        messages: list[str] = []
        valid_fields = self.valid_fields()
        query_fields = fields
        if valid_fields:
            query_fields = [field_name for field_name in fields if field_name in valid_fields]
            missing_fields = [field_name for field_name in fields if field_name not in valid_fields]
            if missing_fields:
                messages.append(f"tshark does not expose these optional fields: {', '.join(missing_fields)}")
        command = [self.tshark_path, "-n", "-r", file_path]
        command.extend(decrypt or [])
        command.extend(["-Y", display_filter, "-T", "fields", "-E", "separator=\t", "-E", "occurrence=f"])
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
        mac_role: str = "Unknown",
        password: str = "",
        temporal_key: str = "",
        tshark_path: str = "tshark",
    ) -> None:
        self.file_path = str(Path(file_path).expanduser())
        self.ssid = ssid.strip()
        self.mac = normalize_mac(mac)
        self.mac_role = mac_role
        self.password = password
        self.temporal_key = temporal_key.strip()
        self.runner = TsharkRunner(tshark_path)
        self.result = AnalysisResult()

    def _profile(self, kind: str, value: str) -> DeviceProfile:
        value = normalize_mac(value) if kind in {"BSSID", "Client", "Wired/Upstream", "MAC"} else value
        key = f"{kind}:{value}"
        profile = self.result.profiles.setdefault(key, DeviceProfile(key=key, role=kind))
        profile.role = kind
        if kind in {"BSSID", "Client", "Wired/Upstream", "MAC"}:
            profile.mac = value
            profile.vendor = profile.vendor or oui_prefix(value)
        elif kind == "SSID":
            profile.ssids.add(value)
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

    def analyze(self) -> AnalysisResult:
        self._record_user_inputs()
        if not Path(self.file_path).exists():
            self.result.messages.append(f"Capture file not found: {self.file_path}")
            return self.result
        if not self.runner.exists():
            self.result.messages.append("tshark was not found on PATH. Install Wireshark/tshark or enter a full tshark path.")
            return self.result

        self._discover_aps()
        self._inspect_security_and_handshakes()
        self._classify_clients_and_upstream()
        self._inspect_decrypted_traffic()
        self.result.ap_observation_rows = uniq_rows(self.result.ap_observation_rows)
        self.result.ap_rows = self._summarize_ap_rows()
        self.result.ssid_group_rows = self._build_ssid_groups()
        self.result.client_rows = uniq_rows(self.result.client_rows)
        self.result.security_rows = uniq_rows(self.result.security_rows)
        self.result.handshake_rows = uniq_rows(self.result.handshake_rows)
        self.result.decrypted_rows = uniq_rows(self.result.decrypted_rows)
        self._finalize_profiles()
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
        hs_fields = ["frame.number", "wlan.bssid", "wlan.sa", "wlan.da", "wlan_rsna_eapol.keydes.msgnr", "wlan.rsn.ie.pmkid"]
        rows, messages = self.runner.fields(self.file_path, hs_filter, hs_fields)
        self.result.messages.extend(messages)
        for row in rows:
            bssid = normalize_mac(row.get("wlan.bssid", ""))
            if is_noise_mac(bssid):
                continue
            msg = row.get("wlan_rsna_eapol.keydes.msgnr", "")
            pmkid = row.get("wlan.rsn.ie.pmkid", "")
            why = "PMKID observed" if pmkid else f"EAPOL handshake message {msg or 'observed'}"
            self.result.handshake_rows.append(
                {
                    "Frame": row.get("frame.number", ""),
                    "BSSID": bssid,
                    "Source": normalize_mac(row.get("wlan.sa", "")),
                    "Destination": normalize_mac(row.get("wlan.da", "")),
                    "EAPOL Msg": msg,
                    "PMKID": pmkid,
                    "Why": why,
                }
            )
            self.result.add_candidate("BSSID", bssid, Evidence("Handshake/PMKID", why, 25, row), labels=["handshake"])
            profile = self._profile("BSSID", bssid)
            if msg:
                profile.handshakes.add(f"EAPOL message {msg}")
            if pmkid:
                profile.pmkids.add(pmkid)

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
            self._update_radio_profile(profile, row)

        for (bssid, mac), row in sorted(upstream_seen.items()):
            if mac in wireless_clients:
                continue
            reason = "Address appeared on the distribution/network side and was not also seen as a wireless station."
            self.result.client_rows.append({"BSSID": bssid, "MAC": mac, "Role": "Wired/Upstream", "Why": reason})
            self.result.add_candidate("Wired/Upstream", mac, Evidence("Upstream classification", reason, 25, {"BSSID": bssid, "MAC": mac}), labels=["wired-or-upstream"], related=[bssid])
            profile = self._profile("Wired/Upstream", mac)
            profile.bssids.add(bssid)
            self._update_radio_profile(profile, row)

    def _decrypt_options(self) -> list[str]:
        opts: list[str] = []
        if self.password and self.ssid:
            opts.extend(["-o", "wlan.enable_decryption:TRUE", "-o", f'uat:80211_keys:"wpa-pwd","{self.password}:{self.ssid}"'])
        if self.temporal_key:
            if "-o" not in opts:
                opts.extend(["-o", "wlan.enable_decryption:TRUE"])
            opts.extend(["-o", f'uat:80211_keys:"tk","{self.temporal_key}"'])
        return opts

    def _inspect_decrypted_traffic(self) -> None:
        decrypt = self._decrypt_options()
        if not decrypt:
            return
        display_filter = f"({self._bssid_filter()}) && (ip || arp || ipv6)"
        fields = ["frame.number", "_ws.col.Protocol", "wlan.bssid", "wlan.sa", "wlan.da", "ip.src", "ip.dst", "ipv6.src", "ipv6.dst", "arp.src.proto_ipv4", "arp.dst.proto_ipv4"]
        rows, messages = self.runner.fields(self.file_path, display_filter, fields, decrypt=decrypt)
        self.result.messages.extend(messages)
        for row in rows:
            bssid = normalize_mac(row.get("wlan.bssid", ""))
            src_ip = row.get("ip.src") or row.get("ipv6.src") or row.get("arp.src.proto_ipv4", "")
            dst_ip = row.get("ip.dst") or row.get("ipv6.dst") or row.get("arp.dst.proto_ipv4", "")
            src_mac = normalize_mac(row.get("wlan.sa", ""))
            dst_mac = normalize_mac(row.get("wlan.da", ""))
            self.result.decrypted_rows.append(
                {
                    "Frame": row.get("frame.number", ""),
                    "Protocol": row.get("_ws.col.Protocol", ""),
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
                reason = f"MAC appeared in decrypted {row.get('_ws.col.Protocol', 'traffic')} traffic"
                if ip:
                    reason += f" with IP {ip}"
                self.result.add_candidate("MAC", mac, Evidence("Decrypted traffic", reason, 20, row), labels=[label], related=[bssid, ip])
                profile = self._profile("MAC", mac)
                profile.bssids.add(bssid)
                if ip:
                    profile.ips.add(ip)
                if row.get("_ws.col.Protocol", ""):
                    profile.protocols.add(row.get("_ws.col.Protocol", ""))
                self._update_radio_profile(profile, row)


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
        "Identity",
        f"- Role: {profile.role or candidate.kind}",
        f"- MAC: {profile.mac or (candidate.value if is_mac(candidate.value) else '-')}",
        f"- OUI vendor/prefix: {profile.vendor or '-'}",
        f"- SSID(s): {', '.join(sorted(profile.ssids)) or '-'}",
        f"- BSSID(s): {', '.join(sorted(profile.bssids)) or '-'}",
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
    ]
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
    for item in related:
        if item and item not in profile.bssids and item not in profile.ssids:
            lines.append(f"  -> Related {item}")
    if len(lines) == 1:
        lines.append("  -> No additional relationships discovered yet.")
    return "\n".join(lines)


def run_cli(args: argparse.Namespace) -> int:
    result = APAnalyzer(
        file_path=args.file,
        ssid=args.ssid or "",
        mac=args.mac or "",
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
    parser.add_argument("--mac-role", default="Unknown", choices=["Unknown", "BSSID", "Client", "Wired/Upstream", "MAC"])
    parser.add_argument("--password", default="", help="WPA password/PSK for decryption")
    parser.add_argument("--tk", default="", help="Temporal key for decryption")
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
        from textual.containers import Horizontal, Vertical
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
        #evidence-detail, #profile-detail, #graph-detail {
            padding: 1;
            overflow-y: auto;
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
        ]

        def __init__(self, initial_args: argparse.Namespace) -> None:
            super().__init__()
            self.initial_args = initial_args
            self.current_result: AnalysisResult | None = None
            self.candidate_by_key: dict[str, Candidate] = {}
            self.sort_state: dict[str, tuple[str, bool]] = {}

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
                    yield Input(value=self.initial_args.password, placeholder="Password / PSK", password=True, id="password")
                    yield Input(value=self.initial_args.tk, placeholder="Temporal key / TK", password=True, id="tk")
                with Horizontal(id="actions"):
                    yield Button("Analyze", id="analyze", variant="primary")
                    yield Button("Export Report", id="export")
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
                        yield Static("Select a row to see why it was identified as related.", id="evidence-detail")
                    with TabPane("Profile", id="profile-pane"):
                        yield Static("Select a row to see device information.", id="profile-detail")
                    with TabPane("Graph", id="graph-pane"):
                        yield Static("Select a row to see related identifiers.", id="graph-detail")
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
                "security": ["BSSID", "Pairwise Cipher", "AKM", "MFPR", "MFPC"],
                "handshakes": ["Frame", "BSSID", "Source", "Destination", "EAPOL Msg", "PMKID", "Why"],
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
            self._fill_rows("security", result.security_rows)
            self._fill_rows("handshakes", result.handshake_rows)
            self._fill_rows("decrypted", result.decrypted_rows)
            self.query_one("#messages", Static).update("\n".join(result.messages) if result.messages else "No messages.")
            self.query_one("#status", Static).update(f"Done. {len(result.candidates)} identifiers found. Select any row for Evidence, Profile, and Graph.")

        def _clear_tables(self) -> None:
            for table_id in ["candidates", "aps", "ap-observations", "ssid-groups", "clients", "security", "handshakes", "decrypted"]:
                self.query_one(f"#{table_id}", DataTable).clear()
            self.query_one("#messages", Static).update("Working...")
            self.query_one("#evidence-detail", Static).update("Select a row to see why it was identified as related.")
            self.query_one("#profile-detail", Static).update("Select a row to see device information.")
            self.query_one("#graph-detail", Static).update("Select a row to see related identifiers.")

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
            for kind, field_name in [("BSSID", "BSSID"), ("Client", "MAC"), ("Wired/Upstream", "MAC"), ("MAC", "Source MAC"), ("MAC", "Destination MAC"), ("SSID", "SSID")]:
                value = row.get(field_name, "")
                key = f"{kind}:{normalize_mac(value) if kind != 'SSID' else value}"
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

        @on(DataTable.RowSelected)
        def row_selected(self, event: DataTable.RowSelected) -> None:
            key = str(event.row_key.value).split("|", 1)[0]
            candidate = self.candidate_by_key.get(key)
            self.query_one("#evidence-detail", Static).update(render_candidate_detail(candidate))
            self.query_one("#profile-detail", Static).update(render_device_profile(candidate, self.current_result))
            self.query_one("#graph-detail", Static).update(render_device_graph(candidate, self.current_result))

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

        @on(Button.Pressed, "#clear")
        def clear_button(self) -> None:
            for input_id in ["ssid", "mac", "password", "tk"]:
                self.query_one(f"#{input_id}", Input).value = ""
            self._clear_tables()
            self.query_one("#status", Static).update("Inputs cleared.")

    APAnalyzerApp(args).run()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
