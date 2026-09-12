"""
Builds the labeled training dataset from raw telemetry.

Labeling strategy ("option_a"):
  - source == cowrie_attack_log  -> label 1 (attack)
  - source == suricata_log       -> label derived from alert_ratio
                                     (>=0.05 -> 1, <=0.01 -> 0, else skipped)
  - anything else                -> skipped

This is a heuristic/source-based labeling scheme, not ground-truth
ATT&CK-verified labeling. It also means the model partially learns to
distinguish *log source* rather than purely *behavior* — see
docs/PROJECT_STATUS.md ("label leakage" risk) before citing metrics
from this pipeline as behavior-only performance.
"""

import logging
import os

import numpy as np
import pandas as pd

from config import settings
from core.feature_engine import extract_features
from core.parser import load_events
from core.session_builder import create_behavioral_sessions

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("aegis.prepare_dataset")


def _safe(x) -> float:
    try:
        x = float(x)
        return 0.0 if (np.isnan(x) or np.isinf(x)) else x
    except (TypeError, ValueError):
        return 0.0


def build_dataset(labeling_strategy: str = "option_a", output_path: str = None) -> pd.DataFrame:
    output_path = output_path or settings.DATASET_OUTPUT_PATH

    logger.info("Building dataset (labeling_strategy=%s)", labeling_strategy)

    raw_events = load_events()
    sessions = create_behavioral_sessions(raw_events)
    logger.info("Sessions created: %d", len(sessions))

    rows = []
    for s in sessions:
        f = extract_features(s)
        if not f:
            continue

        row = {
            "event_count": _safe(f.get("event_count", 0)),
            "duration": _safe(f.get("duration", 0)),
            "event_rate": _safe(f.get("event_rate", 0)),
            "iat_mean": _safe(f.get("iat_mean", 0)),
            "burst_ratio": _safe(f.get("burst_ratio", 0)),
            "stage_entropy": _safe(f.get("stage_entropy", 0)),
            "stage_transitions": _safe(f.get("stage_transitions", 0)),
            "unique_stages_count": _safe(f.get("unique_stages_count", 0)),
            "risk_score": _safe(f.get("risk_score", 0)),
            "risk_density": _safe(f.get("risk_density", 0)),
            "command_count": _safe(f.get("command_count", 0)),
            "command_diversity": _safe(f.get("command_diversity", 0)),
            "unique_ip_count": _safe(f.get("unique_ip_count", 0)),
            "unique_port_count": _safe(f.get("unique_port_count", 0)),
            "destination_count": _safe(f.get("destination_count", 0)),
            "long_session_flag": _safe(f.get("long_session_flag", 0)),
            "multi_stage_flag": _safe(f.get("multi_stage_flag", 0)),
            "lateral_movement_flag": _safe(f.get("lateral_movement_flag", 0)),
            "high_port_spread_flag": _safe(f.get("high_port_spread_flag", 0)),
        }

        source = getattr(s, "source", "unknown")

        if labeling_strategy == "option_a":
            if source == "cowrie_attack_log":
                label = 1
            elif source == "suricata_log":
                alert_ratio = getattr(s, "alert_count", 0) / max(getattr(s, "event_count", 1), 1)
                if alert_ratio >= 0.05:
                    label = 1
                elif alert_ratio <= 0.01:
                    label = 0
                else:
                    continue  # ambiguous zone — excluded rather than guessed
            else:
                continue
        else:
            alert_ratio = getattr(s, "alert_count", 0) / max(getattr(s, "event_count", 1), 1)
            label = 1 if alert_ratio >= 0.05 else 0

        row["label"] = int(label)
        rows.append(row)

    df = pd.DataFrame(rows).fillna(0)

    if len(df) < 20:
        raise ValueError(f"Dataset too small to train on: {len(df)} rows")
    if df["label"].nunique() < 2:
        raise ValueError("Only one class present in the dataset — check telemetry sources")

    os.makedirs(os.path.dirname(output_path) or ".", exist_ok=True)
    df.to_csv(output_path, index=False)

    logger.info(
        "Dataset written to %s | shape=%s | attack=%d | normal=%d | ratio=%.4f",
        output_path, df.shape, int(df["label"].sum()),
        len(df) - int(df["label"].sum()), df["label"].mean(),
    )
    return df


if __name__ == "__main__":
    build_dataset()
