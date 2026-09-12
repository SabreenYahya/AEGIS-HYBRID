from core.fusion_engine import FusionEngine


def _base_features(**overrides) -> dict:
    features = {
        "unique_stages_count": 0, "risk_density": 0, "stage_entropy": 0,
        "duration": 0, "burst_ratio": 0, "event_rate": 0, "command_count": 0,
        "command_diversity": 0, "unique_port_count": 0, "unique_ip_count": 0,
        "risk_score": 0, "stage_transitions": 0,
    }
    features.update(overrides)
    return features


def test_hybrid_score_stays_in_unit_interval():
    fusion = FusionEngine()
    score = fusion.calculate_hybrid_score(
        ml_score=1.0,
        features=_base_features(
            unique_stages_count=6, risk_density=5, burst_ratio=5,
            unique_ip_count=10, unique_port_count=30, stage_transitions=20,
        ),
    )
    assert 0.0 <= score <= 1.0


def test_zero_ml_and_zero_behavior_yields_low_score():
    fusion = FusionEngine()
    score = fusion.calculate_hybrid_score(ml_score=0.0, features=_base_features())
    assert score < fusion.low_threshold


def test_evaluate_threat_boundaries():
    fusion = FusionEngine(low_threshold=0.45, medium_threshold=0.70, critical_threshold=0.85)
    assert fusion.evaluate_threat(0.10) == "LOW"
    assert fusion.evaluate_threat(0.50) == "MEDIUM"
    assert fusion.evaluate_threat(0.75) == "HIGH"
    assert fusion.evaluate_threat(0.90) == "CRITICAL"


def test_safe_float_handles_garbage_input():
    fusion = FusionEngine()
    assert fusion._safe_float(None) == 0.0
    assert fusion._safe_float("not-a-number") == 0.0
    assert fusion._safe_float(float("nan")) == 0.0
