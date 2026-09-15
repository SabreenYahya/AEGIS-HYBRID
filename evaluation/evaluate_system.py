"""Evaluate the fused detection path on the frozen test split.

The training workflow selects the threshold on the validation split. This
module reproduces the deterministic 60/20/20 partition and evaluates the
saved model on the untouched 20% test partition using the threshold persisted
in the model artifact.
"""

import json
import logging
import os

import joblib
import numpy as np
import pandas as pd
from sklearn.metrics import accuracy_score, confusion_matrix, f1_score, precision_score, recall_score, roc_auc_score
from sklearn.model_selection import train_test_split

from config import settings
from core.fusion_engine import FusionEngine

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("aegis.evaluate")
RANDOM_STATE = 42


def _compute_fusion_scores(model, feature_cols: list, fusion: FusionEngine, df: pd.DataFrame) -> np.ndarray:
    scores = []
    for _, row in df.iterrows():
        ml = model.predict_proba([row[feature_cols]])[0][1]
        scores.append(fusion.calculate_hybrid_score(ml_score=ml, features=row.to_dict()))
    return np.array(scores)


def _test_split(df: pd.DataFrame):
    y = df["label"].astype(int)
    train_val, test = train_test_split(
        df, test_size=0.20, random_state=RANDOM_STATE, stratify=y
    )
    return train_val, test


def evaluate(model_path: str = None, dataset_path: str = None) -> dict:
    model_path = model_path or settings.MODEL_OUTPUT_PATH
    dataset_path = dataset_path or settings.DATASET_OUTPUT_PATH

    pkg = joblib.load(model_path)
    model, feature_cols = pkg["model"], pkg["features"]
    threshold = float(pkg.get("threshold", 0.5))

    df = pd.read_csv(dataset_path).fillna(0)
    _, test_df = _test_split(df)
    y_test = test_df["label"].astype(int)

    fusion = FusionEngine()
    probs = _compute_fusion_scores(model, feature_cols, fusion, test_df)
    preds = (probs >= threshold).astype(int)

    acc = accuracy_score(y_test, preds)
    prec = precision_score(y_test, preds, zero_division=0)
    rec = recall_score(y_test, preds, zero_division=0)
    f1 = f1_score(y_test, preds, zero_division=0)
    auc = roc_auc_score(y_test, probs)
    tn, fp, fn, tp = confusion_matrix(y_test, preds).ravel()
    fpr = fp / (fp + tn + 1e-9)

    results = {
        "threshold": threshold,
        "accuracy": float(acc),
        "precision": float(prec),
        "recall": float(rec),
        "f1": float(f1),
        "roc_auc": float(auc),
        "fpr": float(fpr),
        "confusion_matrix": {"tp": int(tp), "fp": int(fp), "tn": int(tn), "fn": int(fn)},
        "split": {"test_fraction": 0.20, "random_state": RANDOM_STATE},
    }

    logger.info("Final test evaluation: %s", json.dumps(results, indent=2))
    out_dir = "evaluation_results"
    os.makedirs(out_dir, exist_ok=True)
    with open(os.path.join(out_dir, "metrics.json"), "w", encoding="utf-8") as f:
        json.dump(results, f, indent=2)
    return results


if __name__ == "__main__":
    evaluate()
