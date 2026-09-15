"""
Train the calibrated XGBoost classifier used by the canonical pipeline.

The dataset is split deterministically into 60% train, 20% validation,
and 20% test. The decision threshold is selected on validation data only;
the test split is reserved for an unbiased final estimate of this training
run.
"""

import logging
import os
import warnings

import joblib
import numpy as np
import pandas as pd
from sklearn.calibration import CalibratedClassifierCV
from sklearn.metrics import classification_report, confusion_matrix, f1_score, matthews_corrcoef, roc_auc_score
from sklearn.model_selection import train_test_split
from xgboost import XGBClassifier

from config import settings

warnings.filterwarnings("ignore")
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("aegis.train_model")

RANDOM_STATE = 42

FEATURE_COLUMNS = [
    "event_count", "duration", "event_rate",
    "iat_mean", "burst_ratio",
    "stage_entropy", "stage_transitions", "unique_stages_count",
    "risk_score", "risk_density",
    "command_diversity", "command_count",
    "unique_ip_count", "unique_port_count", "destination_count",
    "long_session_flag", "multi_stage_flag",
    "lateral_movement_flag", "high_port_spread_flag",
]


def _load_dataset(path: str) -> pd.DataFrame:
    if not os.path.exists(path):
        raise FileNotFoundError(f"Dataset not found: {path}. Run ml/prepare_dataset.py first.")
    df = pd.read_csv(path).replace([np.inf, -np.inf], np.nan).fillna(0)
    logger.info("Dataset shape: %s", df.shape)
    logger.info("Label distribution:\n%s", df["label"].value_counts())
    return df


def _split_dataset(X, y):
    """Return deterministic 60/20/20 train/validation/test partitions."""
    X_train_val, X_test, y_train_val, y_test = train_test_split(
        X, y, test_size=0.20, random_state=RANDOM_STATE, stratify=y
    )
    X_train, X_val, y_train, y_val = train_test_split(
        X_train_val, y_train_val, test_size=0.25, random_state=RANDOM_STATE, stratify=y_train_val
    )
    return X_train, X_val, X_test, y_train, y_val, y_test


def _optimize_threshold(y_true, probs) -> float:
    """Select a threshold using validation labels only."""
    best_t, best_score = 0.5, -1.0
    for t in np.linspace(0.1, 0.9, 81):
        preds = (probs >= t).astype(int)
        tn, fp, fn, tp = confusion_matrix(y_true, preds).ravel()
        fpr = fp / max(fp + tn, 1)
        score = f1_score(y_true, preds, zero_division=0) - 0.7 * fpr
        if score > best_score:
            best_score, best_t = score, t
    logger.info("Validation threshold=%.3f (selection score=%.4f)", best_t, best_score)
    return float(best_t)


def train(dataset_path: str = None, model_output_path: str = None) -> dict:
    dataset_path = dataset_path or settings.DATASET_OUTPUT_PATH
    model_output_path = model_output_path or settings.MODEL_OUTPUT_PATH

    df = _load_dataset(dataset_path)
    missing = [c for c in FEATURE_COLUMNS if c not in df.columns]
    if missing:
        raise ValueError(f"Dataset is missing required feature columns: {missing}")

    X = df[FEATURE_COLUMNS].copy()
    y = df["label"].astype(int)
    X_train, X_val, X_test, y_train, y_val, y_test = _split_dataset(X, y)
    logger.info("Train=%d Validation=%d Test=%d", len(X_train), len(X_val), len(X_test))

    pos, neg = np.sum(y_train == 1), np.sum(y_train == 0)
    scale_pos_weight = neg / max(pos, 1)

    base_model = XGBClassifier(
        n_estimators=250, max_depth=5, learning_rate=0.05,
        subsample=0.85, colsample_bytree=0.85, min_child_weight=3,
        gamma=0.2, reg_alpha=0.1, reg_lambda=1.0,
        scale_pos_weight=scale_pos_weight, eval_metric="logloss",
        random_state=RANDOM_STATE,
    )
    base_model.fit(X_train, y_train)

    calibrated_model = CalibratedClassifierCV(estimator=base_model, method="isotonic", cv=5)
    calibrated_model.fit(X_train, y_train)

    validation_probs = calibrated_model.predict_proba(X_val)[:, 1]
    threshold = _optimize_threshold(y_val, validation_probs)

    test_probs = calibrated_model.predict_proba(X_test)[:, 1]
    test_preds = (test_probs >= threshold).astype(int)
    logger.info("\n%s", classification_report(y_test, test_preds))
    auc = roc_auc_score(y_test, test_probs)
    mcc = matthews_corrcoef(y_test, test_preds)
    tn, fp, fn, tp = confusion_matrix(y_test, test_preds).ravel()
    logger.info("Final test ROC-AUC=%.4f MCC=%.4f | TP=%d FP=%d TN=%d FN=%d", auc, mcc, tp, fp, tn, fn)

    os.makedirs(os.path.dirname(model_output_path) or ".", exist_ok=True)
    joblib.dump(
        {
            "model": calibrated_model,
            "features": FEATURE_COLUMNS,
            "threshold": threshold,
            "split": {"train": 0.60, "validation": 0.20, "test": 0.20, "random_state": RANDOM_STATE},
        },
        model_output_path,
    )
    logger.info("Model saved: %s", model_output_path)

    return {
        "roc_auc": auc, "mcc": mcc, "threshold": threshold,
        "tp": int(tp), "fp": int(fp), "tn": int(tn), "fn": int(fn),
    }


if __name__ == "__main__":
    train()
