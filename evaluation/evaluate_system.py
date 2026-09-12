"""
Evaluates the fused (XGBoost + FusionEngine) detection path end-to-end
on a held-out split of the dataset, and searches for a decision
threshold that maximizes recall subject to FPR <= 2%.

Deliberate change from the original prototype: this version does NOT
apply the artificial "soft_recall_boost" nudge that the original
evaluate_system.py added to the ML probability before fusion scoring.
That boost existed only in the evaluation script and was never part
of pipeline/offline_pipeline.py's actual inference path — evaluating
with it made the reported numbers not representative of production
behavior. See docs/PROJECT_STATUS.md ("metrics integrity").

Threshold selection here is performed on the same held-out test split
used to report the final metrics, which is threshold *fitting*, not an
independently validated threshold. Treat the reported FPR/recall as
optimistic upper bounds, not a guarantee on unseen traffic.
"""

import json
import logging
import os

import joblib
import numpy as np
import pandas as pd
from sklearn.metrics import (
    accuracy_score,
    confusion_matrix,
    f1_score,
    precision_score,
    recall_score,
    roc_auc_score,
)
from sklearn.model_selection import train_test_split

from config import settings
from core.fusion_engine import FusionEngine

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("aegis.evaluate")


def _compute_fusion_scores(model, features_cols: list, fusion: FusionEngine, df: pd.DataFrame) -> np.ndarray:
    scores = []
    for _, row in df.iterrows():
        ml = model.predict_proba([row[features_cols]])[0][1]
        scores.append(fusion.calculate_hybrid_score(ml_score=ml, features=row.to_dict()))
    return np.array(scores)


def _threshold_search(y_true, probs, max_fpr: float = 0.02) -> float:
    best_t, best_recall = 0.5, 0.0
    for t in np.linspace(0.15, 0.65, 120):
        preds = (probs >= t).astype(int)
        tn, fp, fn, tp = confusion_matrix(y_true, preds).ravel()
        fpr = fp / (fp + tn + 1e-9)
        recall = tp / (tp + fn + 1e-9)
        if fpr <= max_fpr and recall > best_recall:
            best_recall, best_t = recall, t
    return best_t


def evaluate(model_path: str = None, dataset_path: str = None) -> dict:
    model_path = model_path or settings.MODEL_OUTPUT_PATH
    dataset_path = dataset_path or settings.DATASET_OUTPUT_PATH

    pkg = joblib.load(model_path)
    model, feature_cols = pkg["model"], pkg["features"]

    df = pd.read_csv(dataset_path).fillna(0)
    y = df["label"].astype(int)

    _, X_test, _, y_test = train_test_split(
        df, y, test_size=0.30, random_state=42, stratify=y
    )

    fusion = FusionEngine()
    probs = _compute_fusion_scores(model, feature_cols, fusion, X_test)

    threshold = _threshold_search(y_test, probs)
    preds = (probs >= threshold).astype(int)

    acc = accuracy_score(y_test, preds)
    prec = precision_score(y_test, preds, zero_division=0)
    rec = recall_score(y_test, preds, zero_division=0)
    f1 = f1_score(y_test, preds, zero_division=0)
    auc = roc_auc_score(y_test, probs)
    tn, fp, fn, tp = confusion_matrix(y_test, preds).ravel()
    fpr = fp / (fp + tn + 1e-9)

    results = {
        "threshold": float(threshold),
        "accuracy": float(acc),
        "precision": float(prec),
        "recall": float(rec),
        "f1": float(f1),
        "roc_auc": float(auc),
        "fpr": float(fpr),
        "confusion_matrix": {"tp": int(tp), "fp": int(fp), "tn": int(tn), "fn": int(fn)},
    }

    logger.info("Evaluation results: %s", json.dumps(results, indent=2))

    out_dir = "evaluation_results"
    os.makedirs(out_dir, exist_ok=True)
    with open(os.path.join(out_dir, "metrics.json"), "w", encoding="utf-8") as f:
        json.dump(results, f, indent=2)

    return results


if __name__ == "__main__":
    evaluate()
