"""
BehavioralSession: accumulates UnifiedEvent objects belonging to the same
source IP into a running behavioral profile (event counts, stage
sequence, inter-arrival timing, commands, network fan-out).

This is the object that core/feature_engine.py turns into a numeric
feature vector for the ML model.
"""

from collections import Counter
from statistics import mean

from core.event_schema import STAGE_WEIGHTS

_VALID_PROTOCOLS = {"TCP", "UDP", "ICMP"}


class BehavioralSession:
    def __init__(self, session_id: str, src_ip: str):
        self.session_id = str(session_id)
        self.src_ip = str(src_ip)

        self.start_time = None
        self.last_activity = None

        self.event_count = 0
        self.alert_count = 0
        self.flow_count = 0

        self.stages_sequence = []
        self.stage_counter = Counter()
        self.stage_transitions = 0
        self.last_stage = None

        self.inter_arrival_times = []

        self.risk_score = 0.0

        self.commands = []
        self.unique_commands = set()

        self.destinations = set()
        self.unique_ips = set()
        self.unique_ports = set()
        self.protocols = set()

        self.has_lateral_movement = False
        self.has_recon_behavior = False
        self.has_bruteforce_behavior = False
        self.has_exploitation_behavior = False

        # Which telemetry source this session's events came from.
        # Drives dataset labeling in ml/prepare_dataset.py.
        self.source = "unknown"
        self.has_alert = False

    def update(self, event) -> None:
        if event is None:
            return

        if self.start_time is None:
            self.start_time = event.timestamp

        if self.last_activity is not None:
            try:
                iat = (event.timestamp - self.last_activity).total_seconds()
                if 0 <= iat <= 86400:
                    self.inter_arrival_times.append(iat)
            except TypeError:
                pass
        self.last_activity = event.timestamp

        self.event_count += 1
        event_type = str(getattr(event, "event_type", "")).lower()
        if event_type == "alert":
            self.has_alert = True
            self.alert_count += 1
        if event_type == "flow":
            self.flow_count += 1

        stage = str(getattr(event, "stage", "UNKNOWN")).upper()
        self.stages_sequence.append(stage)
        self.stage_counter[stage] += 1
        if self.last_stage is not None and stage != self.last_stage:
            self.stage_transitions += 1
        self.last_stage = stage

        if stage in ("RECON", "SCAN"):
            self.has_recon_behavior = True
        if stage in ("BRUTE", "ACCESS"):
            self.has_bruteforce_behavior = True
        if stage in ("EXPLOIT", "PERSISTENCE"):
            self.has_exploitation_behavior = True

        try:
            severity = max(1, min(int(getattr(event, "severity", 1)), 10))
        except (TypeError, ValueError):
            severity = 1
        self.risk_score += (severity / 10.0) * STAGE_WEIGHTS.get(stage, 1.0)

        command = getattr(event, "command", None)
        if command:
            cmd = str(command).strip()
            if cmd:
                self.commands.append(cmd)
                self.unique_commands.add(cmd)

        dest_ip = getattr(event, "dest_ip", None)
        if dest_ip:
            self.destinations.add(dest_ip)
            self.unique_ips.add(dest_ip)

        dest_port = getattr(event, "dest_port", None)
        if dest_port is not None:
            try:
                self.unique_ports.add(int(dest_port))
            except (TypeError, ValueError):
                pass

        protocol = getattr(event, "protocol", None)
        if protocol:
            proto = str(protocol).upper()
            if proto in _VALID_PROTOCOLS:
                self.protocols.add(proto)

    # ---- derived properties used by core/feature_engine.py ----

    @property
    def duration(self) -> float:
        if not self.start_time or not self.last_activity:
            return 0.0
        return max((self.last_activity - self.start_time).total_seconds(), 0.0)

    @property
    def unique_stage_count(self) -> int:
        return len(self.stage_counter)

    @property
    def command_diversity(self) -> float:
        if not self.commands:
            return 0.0
        return len(self.unique_commands) / len(self.commands)

    @property
    def alert_ratio(self) -> float:
        if self.event_count == 0:
            return 0.0
        return self.alert_count / self.event_count

    @property
    def unique_ip_count(self) -> int:
        return len(self.unique_ips)

    @property
    def unique_port_count(self) -> int:
        return len(self.unique_ports)

    @property
    def avg_iat(self) -> float:
        return float(mean(self.inter_arrival_times)) if self.inter_arrival_times else 0.0

    @property
    def session_density(self) -> float:
        return self.event_count / max(self.duration, 1.0)

    @property
    def stage_progression_ratio(self) -> float:
        if self.event_count == 0:
            return 0.0
        return self.unique_stage_count / self.event_count

    def to_dict(self) -> dict:
        return {
            "session_id": self.session_id,
            "src_ip": self.src_ip,
            "event_count": self.event_count,
            "alert_count": self.alert_count,
            "flow_count": self.flow_count,
            "duration": round(self.duration, 4),
            "avg_iat": round(self.avg_iat, 4),
            "session_density": round(self.session_density, 4),
            "unique_stage_count": self.unique_stage_count,
            "stage_progression_ratio": round(self.stage_progression_ratio, 4),
            "risk_score": round(self.risk_score, 4),
            "command_diversity": round(self.command_diversity, 4),
            "unique_ip_count": self.unique_ip_count,
            "unique_port_count": self.unique_port_count,
            "protocol_count": len(self.protocols),
            "alert_ratio": round(self.alert_ratio, 4),
            "has_lateral_movement": int(self.has_lateral_movement),
            "has_recon_behavior": int(self.has_recon_behavior),
            "has_bruteforce_behavior": int(self.has_bruteforce_behavior),
            "has_exploitation_behavior": int(self.has_exploitation_behavior),
            "stage_transitions": self.stage_transitions,
        }
