"""
Turns a BehavioralSession into the fixed-length numeric feature vector
consumed by the XGBoost model (ml/train_model.py) and the fusion engine
(core/fusion_engine.py).

IMPORTANT: the feature keys/order here must exactly match
FEATURE_COLUMNS in ml/train_model.py. If you add or rename a feature,
update both files and retrain — see docs/PROJECT_STATUS.md for the
current known feature-schema-consistency caveats.
"""

import numpy as np
from collections import Counter


def _safe_float(x) -> float:
    try:
        if x is None:
            return 0.0
        x = float(x)
        return 0.0 if (np.isnan(x) or np.isinf(x)) else x
    except (TypeError, ValueError):
        return 0.0


def _safe_clip(x, max_val: float = 10.0) -> float:
    return float(np.clip(_safe_float(x), 0.0, max_val))


def _normalized_entropy(values) -> float:
    if not values or len(values) <= 1:
        return 0.0
    counts = Counter(values)
    probs = np.array(list(counts.values()), dtype=np.float64)
    probs /= (np.sum(probs) + 1e-9)
    entropy = -np.sum(probs * np.log2(probs + 1e-12))
    max_ent = np.log2(len(set(values)) + 1e-9)
    return _safe_float(entropy / max_ent) if max_ent > 0 else 0.0


def extract_features(session) -> dict:
    """Extract the feature vector for one BehavioralSession. Returns {}
    on any unexpected shape rather than raising, so a single malformed
    session cannot abort a batch pipeline run."""
    if session is None:
        return {}

    try:
        event_count = _safe_float(getattr(session, "event_count", 0))
        duration = max(_safe_float(getattr(session, "duration", 0)), 1.0)

        stages = [str(x).upper() for x in (getattr(session, "stages_sequence", []) or [])]
        unique_stages = len(set(stages))
        stage_ratio = unique_stages / (len(stages) + 1e-6)

        transitions = _safe_float(getattr(session, "stage_transitions", 0))
        transition_rate = transitions / (event_count + 1e-6)
        stage_entropy = _normalized_entropy(stages)

        base_risk = _safe_float(getattr(session, "risk_score", 0))
        risk_score = base_risk / (event_count + 1e-6)
        risk_density = base_risk / duration

        unique_ips = len(getattr(session, "unique_ips", set()))
        unique_ports = len(getattr(session, "unique_ports", set()))
        ip_diversity = unique_ips / (event_count + 1e-6)
        port_diversity = unique_ports / (event_count + 1e-6)

        commands = getattr(session, "commands", []) or []
        cmd_count = len(commands)
        unique_cmds = len(set(commands))
        command_diversity = unique_cmds / (cmd_count + 1e-6)

        iats = getattr(session, "inter_arrival_times", []) or []
        if len(iats) > 1:
            iat_mean = np.mean(iats)
            burst_ratio = np.std(iats) / (iat_mean + 1e-6)
        else:
            iat_mean = 0.0
            burst_ratio = 0.0

        destination_count = _safe_float(
            getattr(session, "destination_count", unique_ips)
        )

        features = {
            "event_count": np.log1p(event_count),
            "duration": np.log1p(duration),
            "event_rate": event_count / duration,
            "iat_mean": np.log1p(iat_mean),
            "burst_ratio": burst_ratio,
            "stage_entropy": stage_entropy,
            "stage_transitions": transition_rate,
            "unique_stages_count": float(unique_stages),
            "risk_score": _safe_clip(risk_score, 5.0),
            "risk_density": _safe_clip(risk_density, 5.0),
            "command_diversity": command_diversity,
            "command_count": np.log1p(cmd_count),
            "unique_ip_count": float(unique_ips),
            "unique_port_count": float(unique_ports),
            "destination_count": destination_count,
            "long_session_flag": float(duration > 1800),
            "multi_stage_flag": float(stage_ratio > 0.5),
            "lateral_movement_flag": float(ip_diversity > 0.05),
            "high_port_spread_flag": float(port_diversity > 0.05),
        }

        for key, value in features.items():
            if isinstance(value, (int, float, np.number)):
                features[key] = float(np.clip(value, 0.0, 10.0))

        return features

    except Exception:
        return {}
