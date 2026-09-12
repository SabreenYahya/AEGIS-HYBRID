"""
Unified event schema shared by every telemetry source (Cowrie, Suricata).

This is the data contract that core/parser.py produces and everything
downstream (session builder, feature engine, fusion engine) depends on.
"""

import ipaddress
from dataclasses import asdict, dataclass
from datetime import datetime
from typing import Any, Dict

# Lockheed Martin Cyber Kill Chain stage weights, used by
# BehavioralSession to accumulate a running risk score.
STAGE_WEIGHTS = {
    "RECON": 1.0,
    "SCAN": 1.5,
    "BRUTE": 2.0,
    "ACCESS": 2.5,
    "LATERAL": 3.0,
    "EXPLOIT": 4.0,
    "PERSISTENCE": 5.0,
    "EXFILTRATION": 6.0,
}


def normalize_ip(ip: str) -> str:
    """Return a validated IP string, or '0.0.0.0' if the input is unusable."""
    if not ip:
        return "0.0.0.0"
    try:
        return str(ipaddress.ip_address(ip.strip()))
    except (ValueError, AttributeError):
        return "0.0.0.0"


@dataclass
class UnifiedEvent:
    timestamp: datetime

    src_ip: str
    dest_ip: str

    dest_port: int
    protocol: str

    event_type: str
    stage: str

    severity: int
    signature: str

    command: str = ""
    payload_len: int = 0

    # Which telemetry source produced this event. Used downstream for
    # dataset labeling — see ml/prepare_dataset.py.
    source: str = "unknown"

    def get_session_key(self) -> str:
        """
        Session grouping key.

        Intentionally excludes dest_port: including it would fragment a
        single attacker's activity into hundreds of near-empty sessions
        (one per port touched during a scan).
        """
        return f"{self.src_ip}_{self.dest_ip}_{self.protocol}"

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)
