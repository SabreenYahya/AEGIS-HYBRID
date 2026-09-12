"""
Multi-source log parser: reads Cowrie and Suricata logs and normalizes
them into a single list of UnifiedEvent objects, deduplicated and
timestamp-sorted.

Behavioral mapping and severity scoring are keyword-based heuristics,
not a machine-learned classifier — see docs/PROJECT_STATUS.md for the
accuracy caveats that implies.
"""

import json
import logging
import os
from datetime import datetime
from typing import List, Optional

from config import settings
from core.event_schema import UnifiedEvent, normalize_ip

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("aegis.parser")

_NOISE_PREFIXES = ("127.", "0.", "169.254.")

_FLOW_INDICATORS = (
    "network_flow", "stream", "handshake", "synack", "established",
    "tcp flow", "udp flow", "icmp", "session", "connection established",
)
_SCAN_INDICATORS = (
    "nmap", "masscan", "scan", "port scan", "sweep", "recon",
    "reconnaissance", "host discovery", "ping sweep",
)
_ACCESS_INDICATORS = ("ssh", "login", "authentication", "brute", "password")
_EXPLOIT_INDICATORS = ("rce", "overflow", "shell", "payload", "injection", "exploit")
_PERSISTENCE_INDICATORS = ("cron", "wget", "curl", "backdoor", "persistence")
_EXFIL_INDICATORS = ("dns tunnel", "leak", "exfiltration")

_SEVERITY_BASE = {
    "RECON": 2, "SCAN": 3, "ACCESS": 5,
    "EXPLOIT": 8, "PERSISTENCE": 9, "EXFILTRATION": 10,
}
_CRITICAL_KEYWORDS = (
    "meterpreter", "cobalt strike", "trojan", "shell",
    "reverse tcp", "rce", "botnet",
)


def parse_timestamp(ts) -> Optional[datetime]:
    if not ts:
        return None
    try:
        return datetime.fromisoformat(str(ts).replace("Z", "+00:00"))
    except (ValueError, TypeError):
        return None


def is_noise_ip(ip: str) -> bool:
    return not ip or any(ip.startswith(p) for p in _NOISE_PREFIXES)


def map_behavior(event_type: str, signature: str) -> str:
    sig = str(signature).lower()
    et = str(event_type).lower().strip()

    if et.startswith("flow") or any(x in sig for x in _FLOW_INDICATORS):
        return "FLOW"
    if any(x in sig for x in _SCAN_INDICATORS):
        return "SCAN"
    if any(x in sig for x in _ACCESS_INDICATORS):
        return "ACCESS"
    if any(x in sig for x in _EXPLOIT_INDICATORS):
        return "EXPLOIT"
    if any(x in sig for x in _PERSISTENCE_INDICATORS):
        return "PERSISTENCE"
    if any(x in sig for x in _EXFIL_INDICATORS):
        return "EXFILTRATION"
    return "UNKNOWN"


def calculate_severity(stage: str, signature: str) -> int:
    sig = str(signature).lower()
    base = _SEVERITY_BASE.get(str(stage).upper(), 3)
    if any(k in sig for k in _CRITICAL_KEYWORDS):
        base += 2
    return int(min(base, 10))


def _build_event(
    timestamp, src_ip, event_type, stage, signature,
    dest_ip, dest_port, protocol, command="", source="unknown",
) -> UnifiedEvent:
    return UnifiedEvent(
        timestamp=timestamp,
        src_ip=src_ip,
        event_type=event_type,
        stage=stage,
        severity=calculate_severity(stage, signature),
        signature=signature,
        dest_ip=dest_ip,
        dest_port=dest_port,
        protocol=protocol,
        command=command,
        source=source,
    )


def _parse_cowrie(path: str, seen: set, counters: dict) -> List[UnifiedEvent]:
    events: List[UnifiedEvent] = []
    if not os.path.exists(path):
        logger.info("Cowrie log not found at %s — skipping", path)
        return events

    logger.info("Parsing Cowrie log: %s", path)
    with open(path, "r", encoding="utf-8", errors="ignore") as f:
        for line in f:
            try:
                raw = json.loads(line)
                ts = parse_timestamp(raw.get("timestamp"))
                src = normalize_ip(raw.get("src_ip"))

                if not ts or not src or is_noise_ip(src):
                    counters["dropped"] += 1
                    continue

                signature = str(raw.get("eventid", "unknown"))
                stage = map_behavior("cowrie", signature)

                event = _build_event(
                    timestamp=ts,
                    src_ip=src,
                    event_type="cowrie",
                    stage=stage,
                    signature=signature,
                    dest_ip=raw.get("dst_ip", "10.0.0.5"),
                    dest_port=int(raw.get("dst_port") or 22),
                    protocol="TCP",
                    command=raw.get("input", ""),
                    source="cowrie_attack_log",
                )

                fingerprint = (str(ts), src, signature)
                if fingerprint in seen:
                    counters["duplicates"] += 1
                    continue
                seen.add(fingerprint)
                events.append(event)

            except (json.JSONDecodeError, ValueError, TypeError):
                counters["malformed"] += 1

    return events


def _parse_suricata(path: str, seen: set, counters: dict) -> List[UnifiedEvent]:
    events: List[UnifiedEvent] = []
    if not os.path.exists(path):
        logger.info("Suricata log not found at %s — skipping", path)
        return events

    logger.info("Parsing Suricata log: %s", path)
    with open(path, "r", encoding="utf-8", errors="ignore") as f:
        for line in f:
            try:
                raw = json.loads(line)
                event_type = raw.get("event_type")
                if event_type not in ("alert", "flow"):
                    continue

                ts = parse_timestamp(raw.get("timestamp"))
                src = normalize_ip(raw.get("src_ip") or raw.get("source_ip"))

                if not ts or not src or is_noise_ip(src):
                    counters["dropped"] += 1
                    continue

                alert = raw.get("alert", {})
                signature = str(alert.get("signature", "network_flow"))
                stage = map_behavior(event_type, signature)
                protocol = str(raw.get("proto", "TCP")).upper()

                event = _build_event(
                    timestamp=ts,
                    src_ip=src,
                    event_type=event_type,
                    stage=stage,
                    signature=signature,
                    dest_ip=raw.get("dest_ip", "0.0.0.0"),
                    dest_port=int(raw.get("dest_port") or 0),
                    protocol=protocol,
                    source="suricata_log",
                )

                fingerprint = (str(ts), src, signature)
                if fingerprint in seen:
                    counters["duplicates"] += 1
                    continue
                seen.add(fingerprint)
                events.append(event)

            except (json.JSONDecodeError, ValueError, TypeError):
                counters["malformed"] += 1

    return events


def load_events(
    cowrie_path: str = None,
    suricata_path: str = None,
) -> List[UnifiedEvent]:
    """
    Load, normalize, deduplicate, and time-sort events from both sources.
    Paths default to config.settings (env-driven) if not overridden —
    handy for unit tests that point at fixture files.
    """
    cowrie_path = cowrie_path or settings.COWRIE_LOG_PATH
    suricata_path = suricata_path or settings.SURICATA_LOG_PATH

    logger.info("Starting log fusion...")
    seen: set = set()
    counters = {"dropped": 0, "malformed": 0, "duplicates": 0}

    events = _parse_cowrie(cowrie_path, seen, counters)
    events += _parse_suricata(suricata_path, seen, counters)

    events = [e for e in events if e.timestamp is not None]
    events.sort(key=lambda e: e.timestamp)

    logger.info(
        "Fusion complete: %d events | dropped=%d malformed=%d duplicates=%d",
        len(events), counters["dropped"], counters["malformed"], counters["duplicates"],
    )
    return events
