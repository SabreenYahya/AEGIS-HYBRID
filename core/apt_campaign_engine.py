"""
Groups scored sessions into "campaigns" using a correlation key built
from (src_ip, coarse risk bucket, unique-stage count, event-count
bucket, same-IP-as-previous-session flag) plus a hash of the stage
sequence.

This is a deterministic fingerprinting/clustering heuristic, not a
learned correlation model. "apt_score" and "CRITICAL APT" below are
weighted-heuristic outputs, not verified threat-intel classifications.
"""

import hashlib
import math
from collections import Counter, defaultdict

import numpy as np


def compute_normalized_entropy(values) -> float:
    if not values:
        return 0.0
    counts = Counter(values)
    total = len(values)
    unique = len(counts)
    if unique <= 1:
        return 0.0
    entropy = -sum((c / total) * math.log2(c / total) for c in counts.values())
    max_entropy = math.log2(unique + 1e-9)
    return float(np.clip(entropy / max_entropy, 0.0, 1.0))


def normalize_risk(r) -> float:
    try:
        r = float(r)
    except (TypeError, ValueError):
        return 0.0
    r = max(0.0, min(1.0, r))
    return float(1 / (1 + math.exp(-6 * (r - 0.5))))


def build_campaigns(sessions) -> dict:
    campaigns = defaultdict(list)
    sessions = sorted(sessions, key=lambda s: getattr(s, "start_time", None) or 0)

    for i, s in enumerate(sessions):
        risk = normalize_risk(getattr(s, "risk_score", 0))
        stages = getattr(s, "stages_sequence", []) or []
        src_ip = getattr(s, "src_ip", "unknown")
        event_count = int(getattr(s, "event_count", 0))
        unique_stages = len(set(stages))

        prev_same_ip = 0
        if i > 0 and getattr(sessions[i - 1], "src_ip", None) == src_ip:
            prev_same_ip = 1

        if risk >= 0.82:
            behavior = "APT"
        elif risk >= 0.68:
            behavior = "HIGH"
        elif risk >= 0.48:
            behavior = "MID"
        else:
            behavior = "LOW"

        correlation_key = (src_ip, behavior, unique_stages, event_count // 10, prev_same_ip)
        timeline_sig = hashlib.md5("-".join(stages[:8]).encode()).hexdigest()[:10]
        stage_sig = hashlib.md5("-".join(stages).encode()).hexdigest()[:8]

        raw_fp = f"{correlation_key}|{timeline_sig}|{stage_sig}"
        campaign_id = "CMP-" + hashlib.sha256(raw_fp.encode()).hexdigest()[:14]

        campaigns[campaign_id].append(s)

    return campaigns


def analyze_campaigns(campaigns: dict) -> list:
    report = []

    for cid, sessions in campaigns.items():
        risks, stages_all, event_sum = [], [], 0
        for s in sessions:
            risks.append(normalize_risk(getattr(s, "risk_score", 0)))
            stages_all.extend(getattr(s, "stages_sequence", []))
            event_sum += int(getattr(s, "event_count", 0))

        if not risks:
            continue

        avg_risk = float(np.mean(risks))
        max_risk = float(np.max(risks))
        unique_stages = len(set(stages_all))
        entropy = compute_normalized_entropy(stages_all)

        persistence = min(len(sessions) / 7.0, 1.0)
        intensity = min(event_sum / 450.0, 1.0)
        depth = min(unique_stages / 6.0, 1.0)

        transitions = sum(
            1 for i in range(len(stages_all) - 1) if stages_all[i] != stages_all[i + 1]
        )
        pattern_score = min(transitions / 10.0, 1.0)

        apt_score = float(np.clip(
            avg_risk * 0.30 + max_risk * 0.18 + persistence * 0.12
            + intensity * 0.10 + depth * 0.08 + entropy * 0.05 + pattern_score * 0.17,
            0.0, 1.0,
        ))

        if apt_score >= 0.80:
            severity = "CRITICAL APT"
        elif apt_score >= 0.65:
            severity = "HIGH RISK"
        elif apt_score >= 0.50:
            severity = "SUSPICIOUS"
        else:
            severity = "LOW"

        report.append({
            "campaign_id": cid,
            "sessions": len(sessions),
            "avg_risk": round(avg_risk, 4),
            "max_risk": round(max_risk, 4),
            "apt_score": round(apt_score, 4),
            "pattern_score": round(pattern_score, 4),
            "unique_stages": unique_stages,
            "event_volume": event_sum,
            "entropy": round(entropy, 4),
            "severity": severity,
        })

    return report


def campaign_kpis(report: list) -> dict:
    if not report:
        return {
            "total_campaigns": 0, "apt_campaigns": 0, "high_risk_campaigns": 0,
            "suspicious_campaigns": 0, "avg_campaign_risk": 0.0,
            "apt_rate": 0.0, "behavioral_consistency": 0.0,
        }

    total = len(report)
    apt = sum(c["apt_score"] >= 0.80 for c in report)
    high = sum(c["severity"] == "HIGH RISK" for c in report)
    sus = sum(c["severity"] == "SUSPICIOUS" for c in report)

    return {
        "total_campaigns": total,
        "apt_campaigns": apt,
        "high_risk_campaigns": high,
        "suspicious_campaigns": sus,
        "avg_campaign_risk": round(float(np.mean([c["apt_score"] for c in report])), 4),
        "apt_rate": round(apt / max(total, 1), 4),
        "behavioral_consistency": round(float(np.mean([c["pattern_score"] for c in report])), 4),
    }
