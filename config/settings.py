"""
Centralized configuration.

Everything that was previously hardcoded (file paths, thresholds, the
iptables active-response switch) is read from environment variables here,
with safe defaults. Load a .env file in local development with
python-dotenv; in production, set real environment variables instead.
"""

import os
from dotenv import load_dotenv

load_dotenv()  # no-op if .env is absent — fine for CI/production


def _bool(name: str, default: bool) -> bool:
    val = os.getenv(name)
    if val is None:
        return default
    return val.strip().lower() in ("1", "true", "yes", "on")


def _float(name: str, default: float) -> float:
    try:
        return float(os.getenv(name, default))
    except (TypeError, ValueError):
        return default


def _int(name: str, default: int) -> int:
    try:
        return int(os.getenv(name, default))
    except (TypeError, ValueError):
        return default


# --- Telemetry sources ---
COWRIE_LOG_PATH = os.getenv("COWRIE_LOG_PATH", "/opt/logs/cowrie.json")
SURICATA_LOG_PATH = os.getenv("SURICATA_LOG_PATH", "/var/log/suricata/eve.json")

# --- Artifacts ---
MODEL_OUTPUT_PATH = os.getenv("MODEL_OUTPUT_PATH", "data/ids_model.pkl")
DATASET_OUTPUT_PATH = os.getenv("DATASET_OUTPUT_PATH", "data/dataset.csv")
DASHBOARD_OUTPUT_PATH = os.getenv("DASHBOARD_OUTPUT_PATH", "data/final_soc_output.json")

# --- Ingestion API ---
INGEST_API_KEY = os.getenv("INGEST_API_KEY")  # required — no insecure default
INGEST_API_HOST = os.getenv("INGEST_API_HOST", "127.0.0.1")
INGEST_API_PORT = _int("INGEST_API_PORT", 5000)
INGEST_RATE_LIMIT_PER_MIN = _int("INGEST_RATE_LIMIT_PER_MIN", 120)

# --- Active response (safety-critical: see core/active_response.py) ---
ENABLE_ACTIVE_RESPONSE = _bool("ENABLE_ACTIVE_RESPONSE", False)
ACTIVE_RESPONSE_ALLOWED_CIDRS = [
    c.strip()
    for c in os.getenv("ACTIVE_RESPONSE_ALLOWED_CIDRS", "").split(",")
    if c.strip()
]
ACTIVE_RESPONSE_DRY_RUN = _bool("ACTIVE_RESPONSE_DRY_RUN", True)

# --- Detection ---
DETECTION_THRESHOLD = _float("DETECTION_THRESHOLD", 0.42)

# --- Optional LLM investigation layer (not part of detection decisions) ---
OLLAMA_URL = os.getenv("OLLAMA_URL", "")
OLLAMA_MODEL = os.getenv("OLLAMA_MODEL", "deepseek-r1:1.5b")


def require_ingest_api_key() -> str:
    """Fail fast at startup instead of running an unauthenticated endpoint."""
    if not INGEST_API_KEY:
        raise RuntimeError(
            "INGEST_API_KEY is not set. Refusing to start an unauthenticated "
            "ingestion endpoint. Set it in .env or the environment."
        )
    return INGEST_API_KEY
