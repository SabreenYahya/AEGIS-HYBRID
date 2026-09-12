"""
Reconstructs a per-session attack-stage timeline (RECON, BRUTE_FORCE,
INITIAL_ACCESS, COMMAND_EXECUTION, LATERAL_MOVEMENT, EXPLOIT) from the
session's feature vector, and derives a coarse APT-likelihood label
from that timeline.

Both functions are rule-based heuristics with hand-set thresholds —
"APT_CRITICAL" here means "matched several weighted heuristic
conditions," not a verified advanced-persistent-threat determination.
See docs/PROJECT_STATUS.md.
"""

import numpy as np
from collections import Counter


def _safe(v) -> float:
    try:
        return float(v)
    except (TypeError, ValueError):
        return 0.0


def build_timeline(session, feature_extractor_func) -> list:
    features = feature_extractor_func(session)
    if not features:
        return ["NORMAL"]

    event_count = _safe(features.get("event_count"))
    risk = _safe(features.get("risk_score"))
    burst = _safe(features.get("burst_ratio"))

    is_true_recon = (
        features.get("unique_port_count", 0) >= 5
        and features.get("high_port_spread_flag", 0) == 1
        and event_count < 200
    )
    recon_score = (
        0.6 * min(features.get("unique_port_count", 0) / 10.0, 1.0)
        + 0.4 * features.get("high_port_spread_flag", 0)
    ) if is_true_recon else 0.0

    stage_scores = {
        "RECON": recon_score,
        "BRUTE_FORCE": (
            0.5 * (event_count >= 3 and features.get("command_count", 0) == 0)
            + 0.5 * min(burst / 1.5, 1.0)
        ),
        "INITIAL_ACCESS": min(risk / 0.5, 1.0),
        "COMMAND_EXECUTION": min(features.get("command_count", 0) / 3.0, 1.0),
        "LATERAL_MOVEMENT": (
            0.6 * (features.get("unique_ip_count", 0) >= 2)
            + 0.4 * features.get("lateral_movement_flag", 0)
        ),
        "EXPLOIT": (
            0.6 * features.get("multi_stage_flag", 0)
            + 0.4 * min(features.get("risk_density", 0) / 0.6, 1.0)
        ),
    }

    timeline = []
    for stage, score in stage_scores.items():
        threshold = 0.55
        if event_count > 100:
            threshold -= 0.03
        if risk > 0.6:
            threshold -= 0.05
        if stage == "RECON":
            threshold = 0.7  # kept strict to avoid over-flagging routine scans
        if score >= threshold:
            timeline.append(stage)

    return timeline if timeline else ["NORMAL"]


def detect_apt_behavior(timeline: list) -> str:
    """Heuristic label, not a verified APT determination — see module
    docstring. Thresholds (5 / 8 / 12) were hand-tuned on the lab dataset."""
    if not timeline:
        return "NORMAL"

    weights = {
        "RECON": 1, "BRUTE_FORCE": 2, "INITIAL_ACCESS": 3,
        "COMMAND_EXECUTION": 3, "LATERAL_MOVEMENT": 4, "EXPLOIT": 4,
    }
    counter = Counter(timeline)

    score = sum(weights.get(stage, 0) * (1 + np.log1p(count)) for stage, count in counter.items())

    unique = len(counter)
    if unique >= 2:
        score += 1
    if unique >= 4:
        score += 2
    if "INITIAL_ACCESS" in counter and "RECON" in counter:
        score += 1.5
    if "LATERAL_MOVEMENT" in counter:
        score += 1.5
    if "EXPLOIT" in counter:
        score += 2

    if score >= 12:
        return "APT_CRITICAL"
    if score >= 8:
        return "APT_HIGH"
    if score >= 5:
        return "SUSPICIOUS"
    return "NORMAL"
