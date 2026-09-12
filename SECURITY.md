# Security Notice

AEGIS-HYBRID is a graduation-project research prototype. It was built and
tested inside an **isolated VMware lab network** (attacker VM, Cowrie
honeypot VM, detection/analysis VM) and is **not hardened for production or
public-facing deployment**.

## Known scope limitations (by design, not oversight)

| Component | Status | Notes |
|---|---|---|
| `ingestion/ingest_api.py` | Requires `INGEST_API_KEY` | Simple shared-secret auth + in-memory rate limiting. No TLS termination is provided — put this behind a reverse proxy (nginx/Caddy) with HTTPS if exposed beyond localhost. |
| `core/active_response.py` | **Disabled by default** (`ENABLE_ACTIVE_RESPONSE=false`) | Even when enabled, it only acts on IPs inside `ACTIVE_RESPONSE_ALLOWED_CIDRS` and defaults to `ACTIVE_RESPONSE_DRY_RUN=true` (logs the action instead of executing `iptables`). Do not point this at a production subnet. |
| `experimental/llm_analysis.py` | Not part of the detection decision path | Calls a local Ollama instance for human-readable incident summaries only. It does not influence scoring, blocking, or classification. |
| `experimental/anomaly_detector.py` | Not wired into `pipeline/offline_pipeline.py` | Isolation Forest model trained/saved independently; kept for future integration. |
| `experimental/mitre_mapping.py` | Not wired into `pipeline/offline_pipeline.py` | Rule-based tactic/technique lookup; not currently invoked by any scoring path. |

## If you deploy this outside the lab

1. Put `ingestion/ingest_api.py` behind TLS and a network ACL — it is not designed to sit directly on the public internet.
2. Keep `ENABLE_ACTIVE_RESPONSE=false` unless you have reviewed `core/active_response.py` and understand the blast radius of an automated `iptables` rule triggered by a false positive.
3. Rotate `INGEST_API_KEY` and never commit `.env`.
4. Treat all files under `data/` as regenerable pipeline output, not ground truth — see `docs/PROJECT_STATUS.md` for dataset/labeling caveats.

## Reporting an issue

This is an academic project without a dedicated security contact. Please open
a GitHub issue describing the concern; avoid filing exploit details publicly
if the concern involves a live deployment you are aware of.
