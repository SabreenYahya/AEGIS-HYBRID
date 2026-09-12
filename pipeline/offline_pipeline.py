"""
End-to-end offline/batch pipeline: load telemetry -> build sessions ->
extract features -> score (XGBoost + fusion) -> build attack timeline
-> APT-heuristic label -> campaign correlation -> write SOC output JSON.

This is the canonical, currently-wired detection path. Anything under
experimental/ (Isolation Forest, MITRE mapping, LLM investigation) is
NOT invoked from here — see docs/PROJECT_STATUS.md for integration status.
"""

import json
import logging
import os
from collections import OrderedDict
from datetime import UTC, datetime

import joblib
import numpy as np
import pandas as pd

from config import settings
from core.active_response import request_block
from core.apt_campaign_engine import build_campaigns, analyze_campaigns, campaign_kpis
from core.attack_timeline import build_timeline, detect_apt_behavior
from core.feature_engine import extract_features
from core.fusion_engine import FusionEngine
from core.parser import load_events
from core.session_builder import create_behavioral_sessions

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("aegis.pipeline")


def _load_model(path: str):
    model_data = joblib.load(path)
    return (
        model_data["model"],
        model_data["features"],
        float(model_data.get("threshold", 0.5)),
    )


def _ml_score(model, X) -> float:
    try:
        return float(np.clip(model.predict_proba(X)[0][1], 0.0, 1.0))
    except Exception as exc:  # noqa: BLE001 — a single bad row must not abort the batch
        logger.warning("ML scoring failed for one session: %s", exc)
        return 0.0


def _severity(score: float) -> str:
    if score >= 0.90:
        return "CRITICAL"
    if score >= 0.70:
        return "HIGH"
    if score >= 0.45:
        return "MEDIUM"
    return "LOW"


def _explain(features: dict, score: float) -> dict:
    reasons = []
    if features.get("high_port_spread_flag", 0):
        reasons.append("Port scanning detected")
    if features.get("multi_stage_flag", 0):
        reasons.append("Multi-stage attack pattern")
    if features.get("lateral_movement_flag", 0):
        reasons.append("Possible lateral movement")
    if not reasons:
        reasons.append("Anomalous behavior detected")
    return {"risk_score": round(score, 4), "reasons": reasons}


def run(model_path: str = None, threshold: float = None) -> dict:
    model_path = model_path or settings.MODEL_OUTPUT_PATH
    threshold = threshold if threshold is not None else settings.DETECTION_THRESHOLD

    model, feature_names, model_threshold = _load_model(model_path)
    logger.info("Model loaded: %d features, model_threshold=%.3f", len(feature_names), model_threshold)

    raw_events = load_events()
    sessions = create_behavioral_sessions(raw_events)
    logger.info("Sessions created: %d", len(sessions))

    fusion = FusionEngine()
    detections = []
    score_memory: OrderedDict = OrderedDict()
    campaign_sessions = []
    attack_timeline_log = []

    for s in sessions:
        features = extract_features(s)
        if not features:
            continue

        session_id = getattr(s, "session_id", "unknown")

        df = pd.DataFrame([features])
        for col in feature_names:
            if col not in df.columns:
                df[col] = 0.0
        X = df[feature_names].fillna(0)

        ml = _ml_score(model, X)
        fusion_score = fusion.calculate_hybrid_score(ml_score=ml, features=features)

        prev = score_memory.get(session_id)
        alpha = 0.3 if fusion_score > (prev or 0) else 0.15
        final_score = fusion_score if prev is None else (1 - alpha) * prev + alpha * fusion_score
        final_score = float(np.clip(final_score, 0.0, 1.0))
        score_memory[session_id] = final_score

        if final_score < threshold:
            continue

        ip = getattr(s, "src_ip", "unknown")
        sev = _severity(final_score)

        response_outcome = request_block(ip, sev)

        timeline = build_timeline(s, extract_features)
        apt_level = detect_apt_behavior(timeline)

        if features.get("high_port_spread_flag"):
            attack_timeline_log.append({
                "timestamp": datetime.now(UTC).isoformat(),
                "src_ip": ip, "stage": "RECON", "severity": sev,
            })
        if features.get("lateral_movement_flag"):
            attack_timeline_log.append({
                "timestamp": datetime.now(UTC).isoformat(),
                "src_ip": ip, "stage": "LATERAL_MOVEMENT", "severity": sev,
            })

        setattr(s, "risk_score", final_score)
        setattr(s, "stages_sequence", timeline)
        setattr(s, "apt_level", apt_level)
        campaign_sessions.append(s)

        detections.append({
            "timestamp": datetime.now(UTC).isoformat(),
            "src_ip": ip,
            "session_id": session_id,
            "ml_score": round(ml, 4),
            "fusion_score": round(fusion_score, 4),
            "threat_score": round(final_score, 4),
            "severity": sev,
            "attack_timeline": timeline,
            "apt_level": apt_level,
            "event_count": features.get("event_count", 0),
            # Explicit outcome string, not a boolean — see
            # core/active_response.py for the full set of possible values
            # ("disabled", "not_in_allowlist", "dry_run", "executed", ...).
            "active_response": response_outcome,
            "explanation": _explain(features, final_score),
        })

    campaign_map = build_campaigns(campaign_sessions)
    campaign_report = analyze_campaigns(campaign_map)
    campaign_summary = campaign_kpis(campaign_report)

    output = {
        "generated_at": datetime.now(UTC).isoformat(),
        "sessions": len(sessions),
        "detections": len(detections),
        "campaign_summary": campaign_summary,
        "detections_detail": detections,
        "active_response_enabled": settings.ENABLE_ACTIVE_RESPONSE,
        "active_response_dry_run": settings.ACTIVE_RESPONSE_DRY_RUN,
        "attack_timeline": attack_timeline_log,
    }

    out_path = settings.DASHBOARD_OUTPUT_PATH
    os.makedirs(os.path.dirname(out_path) or ".", exist_ok=True)
    with open(out_path, "w", encoding="utf-8") as f:
        json.dump(output, f, indent=2)

    logger.info("Pipeline complete: %d sessions, %d detections -> %s",
                len(sessions), len(detections), out_path)
    return output


if __name__ == "__main__":
    run()
