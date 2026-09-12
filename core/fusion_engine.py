"""
Hybrid scoring: combines the calibrated XGBoost probability with
behavioral indicators (stage progression, burst timing, lateral
movement fan-out, etc.) into a single 0-1 threat score.

This is a hand-tuned weighted heuristic, not a second learned model —
the weights below were set manually and are a primary candidate for
overfitting to the lab dataset. See docs/PROJECT_STATUS.md.
"""

import numpy as np


class FusionEngine:
    def __init__(
        self,
        low_threshold: float = 0.45,
        medium_threshold: float = 0.70,
        critical_threshold: float = 0.85,
    ):
        self.low_threshold = low_threshold
        self.medium_threshold = medium_threshold
        self.critical_threshold = critical_threshold

    @staticmethod
    def _safe_float(value, default: float = 0.0) -> float:
        try:
            if value is None:
                return default
            value = float(value)
            return default if (np.isnan(value) or np.isinf(value)) else value
        except (TypeError, ValueError):
            return default

    def _normalize(self, value, divisor: float, max_value: float = 1.0) -> float:
        value = self._safe_float(value)
        if divisor <= 0:
            return 0.0
        return float(np.clip(value / float(divisor), 0.0, max_value))

    def calculate_hybrid_score(self, ml_score: float, features: dict) -> float:
        f = self._safe_float
        unique_stages = f(features.get("unique_stages_count", 0))
        risk_density = f(features.get("risk_density", 0))
        stage_entropy = f(features.get("stage_entropy", 0))
        duration = f(features.get("duration", 0))
        burst_ratio = f(features.get("burst_ratio", 0))
        event_rate = f(features.get("event_rate", 0))
        command_count = f(features.get("command_count", 0))
        command_diversity = f(features.get("command_diversity", 0))
        unique_ports = f(features.get("unique_port_count", 0))
        unique_ips = f(features.get("unique_ip_count", 0))
        risk_score = f(features.get("risk_score", 0))
        stage_transitions = f(features.get("stage_transitions", 0))

        ml_score = np.clip(f(ml_score), 0.0, 1.0)

        progression_factor = self._normalize(unique_stages, 4.5)
        risk_density_factor = self._normalize(risk_density, 4.0)
        entropy_factor = self._normalize(stage_entropy, 1.0)
        burst_factor = self._normalize(burst_ratio, 4.0)
        event_rate_factor = self._normalize(event_rate, 25.0)
        command_factor = self._normalize(command_count, 25.0)
        command_diversity_factor = self._normalize(command_diversity, 1.0)
        port_factor = self._normalize(unique_ports, 25.0)
        lateral_factor = self._normalize(unique_ips, 10.0)
        transition_factor = self._normalize(stage_transitions, 14.0)
        risk_score_factor = self._normalize(risk_score, 60.0)

        base_ml = (ml_score ** 1.3) * 0.55

        hybrid_score = (
            base_ml
            + progression_factor * 0.08
            + risk_density_factor * 0.07
            + entropy_factor * 0.04
            + burst_factor * 0.06
            + event_rate_factor * 0.05
            + transition_factor * 0.05
            + risk_score_factor * 0.06
            + command_factor * 0.02
            + command_diversity_factor * 0.01
            + port_factor * 0.01
            + lateral_factor * 0.01
        )

        bonus = 0.0
        if unique_stages >= 3:
            bonus += 0.04
        if risk_density >= 4:
            bonus += 0.04
        if burst_ratio >= 3:
            bonus += 0.03
        if unique_ips >= 5:
            bonus += 0.03
        if unique_ports >= 15:
            bonus += 0.03
        if stage_transitions >= 8:
            bonus += 0.03
        if command_count >= 15:
            bonus += 0.02
        if duration >= 3600:
            bonus += 0.02
        hybrid_score += min(bonus, 0.18)

        behavioral_strength = (
            progression_factor + risk_density_factor + burst_factor + transition_factor
        ) / 4.0
        if behavioral_strength >= 0.55:
            hybrid_score += 0.04
        if behavioral_strength >= 0.75:
            hybrid_score += 0.03

        attack_indicators = sum([
            unique_stages >= 3,
            risk_density >= 4,
            burst_ratio >= 3,
            stage_transitions >= 8,
            unique_ips >= 5,
        ])
        if attack_indicators >= 4:
            hybrid_score *= 1.04
        elif attack_indicators >= 3:
            hybrid_score *= 1.02

        if ml_score < 0.30 and behavioral_strength < 0.35:
            hybrid_score *= 0.85

        return float(np.clip(hybrid_score, 0.0, 1.0))

    def evaluate_threat(self, score: float) -> str:
        score = np.clip(self._safe_float(score), 0.0, 1.0)
        if score >= self.critical_threshold:
            return "CRITICAL"
        if score >= self.medium_threshold:
            return "HIGH"
        if score >= self.low_threshold:
            return "MEDIUM"
        return "LOW"
