# AEGIS-HYBRID

A hybrid behavioral intrusion detection research prototype: fuses
Suricata (network IDS) and Cowrie (SSH honeypot) telemetry into
per-source-IP behavioral sessions, extracts a feature vector per
session, scores it with a calibrated XGBoost model, and combines that
score with hand-tuned behavioral indicators (stage progression, burst
timing, lateral-movement fan-out) into a single hybrid threat score.

Built and evaluated inside an isolated VMware lab network as a
graduation project. **Not a production IDS/IPS** — see
[`SECURITY.md`](SECURITY.md) before deploying any part of this beyond
a lab.

For an honest breakdown of what is actually wired into the detection
path versus what is implemented-but-standalone, see
[`docs/PROJECT_STATUS.md`](docs/PROJECT_STATUS.md). For what changed
during the public-release cleanup and why, see
[`MIGRATION_NOTES.md`](MIGRATION_NOTES.md).

## Architecture

```
Cowrie honeypot ──┐
                   ├──> core/parser.py ──> core/session_builder.py ──> core/feature_engine.py
Suricata IDS ──────┘                                                          │
                                                                                ▼
                                                          ml/train_model.py (XGBoost, offline)
                                                                                │
                                                                                ▼
                                                    core/fusion_engine.py (ML score + behavior)
                                                                                │
                                            ┌───────────────────────────────────┼──────────────────────────┐
                                            ▼                                   ▼                          ▼
                              core/attack_timeline.py            core/apt_campaign_engine.py   core/active_response.py
                              (stage sequence, heuristic          (campaign fingerprinting,      (disabled by default,
                               APT-likelihood label)               heuristic APT score)           gated + dry-run)
                                            │                                   │
                                            └───────────────┬───────────────────┘
                                                             ▼
                                          pipeline/offline_pipeline.py
                                                             │
                                                             ▼
                                        data/final_soc_output.json
```

`experimental/` contains real, runnable code (MITRE mapping, Isolation
Forest, LLM-assisted incident summaries, an alternate session builder)
that is **not** called from `pipeline/offline_pipeline.py`. See
`experimental/README.md`.

## Quick start

```bash
git clone <this-repo>
cd AEGIS-HYBRID
python -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt
cp .env.example .env   # then edit paths / INGEST_API_KEY as needed
```

Build the dataset and train the model from your own Cowrie/Suricata
logs (paths configured in `.env`):

```bash
python -m ml.prepare_dataset
python -m ml.train_model
python -m pipeline.offline_pipeline   # writes data/final_soc_output.json
python -m evaluation.evaluate_system  # writes evaluation_results/metrics.json
```

Run the (optional, authenticated) ingestion API for live Cowrie log
shipping:

```bash
export $(grep -v '^#' .env | xargs)  # or use python-dotenv in your own launcher
python -m ingestion.ingest_api
```

Run the test suite:

```bash
pytest
```

## Repository layout

| Path | Contents |
|---|---|
| `config/` | Environment-driven settings (no hardcoded paths or secrets). |
| `core/` | The wired detection path: parsing, sessionization, feature engineering, fusion scoring, timeline/campaign heuristics, active response. |
| `ml/` | Dataset construction and XGBoost training. |
| `ingestion/` | Authenticated, rate-limited Cowrie event ingestion API. |
| `pipeline/` | The offline batch pipeline that ties `core/` and `ml/` together and produces the SOC output JSON. |
| `evaluation/` | Held-out evaluation of the fused detection path. |
| `experimental/` | Implemented but not currently wired into detection — see its own README. |
| `tests/` | Unit tests, including safety-gate tests for `core/active_response.py`. |
| `docs/` | Status/classification and methodology caveats. |

## License

MIT — see [`LICENSE`](LICENSE).

## Author & Copyright

**Author:** Sabreen Yahya Hajouri  
**Project:** AEGIS-HYBRID  
**Copyright © 2026 Sabreen Yahya Hajouri. All rights reserved.**

This repository is publicly viewable for reference and portfolio purposes. Reuse,
redistribution, modification, publication, or commercial use requires explicit
written permission from the copyright holders. Third-party dependencies remain
subject to their respective licenses.

