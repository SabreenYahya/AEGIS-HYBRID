"""
Isolation Forest anomaly scorer over the same session-feature space
used by the XGBoost model.

Not wired into pipeline/offline_pipeline.py — see experimental/README.md.
Trained and persisted independently; would need explicit integration
into FusionEngine or the pipeline's scoring loop to affect detections.
"""

import os

import joblib
import numpy as np
import pandas as pd
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import RobustScaler

DEFAULT_ARTIFACT_PATH = "data/anomaly_detector.pkl"


class AnomalyDetector:
    def __init__(self, contamination: float = 0.005):
        self.model = IsolationForest(
            n_estimators=300, contamination=contamination,
            bootstrap=True, max_samples="auto", random_state=42, n_jobs=-1,
        )
        self.scaler = RobustScaler()
        self.feature_names: list = []
        self.ecdf_sorted = None
        self.ecdf_n = 0
        self.is_fitted = False

    def train(self, features_df: pd.DataFrame) -> None:
        if features_df is None or features_df.empty:
            raise ValueError("Training dataframe is empty")

        exclude = {"label", "src_ip", "session_id", "timestamp"}
        self.feature_names = [c for c in features_df.columns if c not in exclude]

        X = (
            features_df[self.feature_names]
            .replace([np.inf, -np.inf], np.nan)
            .fillna(0)
            .astype(np.float32)
        )

        mask = np.ones(len(X), dtype=bool)
        if "event_count" in X.columns:
            mask &= X["event_count"] >= 3
        if "duration" in X.columns:
            mask &= X["duration"] >= 1
        X = X[mask]

        X = np.log1p(X)
        X_scaled = self.scaler.fit_transform(X)
        self.model.fit(X_scaled)

        raw_scores = -self.model.decision_function(X_scaled)
        self.ecdf_sorted = np.sort(raw_scores)
        self.ecdf_n = len(raw_scores)
        self.is_fitted = True

    def _prepare_vector(self, feature_dict: dict) -> np.ndarray:
        if not self.is_fitted:
            raise RuntimeError("Model not trained/loaded")
        vector = np.array(
            [feature_dict.get(k, 0.0) for k in self.feature_names], dtype=np.float32
        )
        vector = np.nan_to_num(vector, nan=0.0, posinf=0.0, neginf=0.0)
        vector = np.log1p(vector)
        return self.scaler.transform([vector])

    def score(self, session_features: dict) -> float:
        try:
            if session_features.get("event_count", 0) < 3:
                return 0.05

            X = self._prepare_vector(session_features)
            raw_score = -self.model.decision_function(X)[0]

            if self.ecdf_sorted is None or self.ecdf_n == 0:
                return 0.5

            rank = np.searchsorted(self.ecdf_sorted, raw_score, side="right")
            prob = rank / (self.ecdf_n + 1e-9)
            calibrated = float(np.clip((np.tanh((prob - 0.5) * 4.0) + 1) / 2, 0.0, 1.0))

            if session_features.get("unique_stages_count", 1) <= 1 and calibrated > 0.70:
                calibrated *= 0.65

            return calibrated
        except Exception:
            return 0.0

    def save(self, path: str = DEFAULT_ARTIFACT_PATH) -> None:
        os.makedirs(os.path.dirname(path) or ".", exist_ok=True)
        joblib.dump({
            "model": self.model, "scaler": self.scaler,
            "features": self.feature_names,
            "ecdf_sorted": self.ecdf_sorted, "ecdf_n": self.ecdf_n,
        }, path)

    def load(self, path: str = DEFAULT_ARTIFACT_PATH) -> None:
        artifact = joblib.load(path)
        self.model = artifact["model"]
        self.scaler = artifact["scaler"]
        self.feature_names = artifact["features"]
        self.ecdf_sorted = artifact["ecdf_sorted"]
        self.ecdf_n = artifact["ecdf_n"]
        self.is_fitted = True
