# AEGIS-HYBRID

A hybrid behavioral intrusion-detection research prototype that processes Suricata network telemetry and Cowrie honeypot telemetry through a shared normalization, sessionization, feature-engineering, XGBoost scoring, and behavioral-fusion pipeline.

**Important architectural limitation:** the current canonical session builder keeps Cowrie and Suricata sessions source-specific (`source + src_ip`). The repository therefore does **not** currently perform cross-source event fusion inside one behavioral session. The hybrid decision combines ML scoring with hand-tuned behavioral heuristics; multi-source telemetry is processed by the same pipeline but is not yet correlated into a single per-attacker session.

Built and evaluated inside an isolated VMware lab network as a graduation-project research prototype. **Not a production IDS/IPS and not a live/streaming detection system.** See [`SECURITY.md`](SECURITY.md) before deploying any component beyond a lab.

For the exact distinction between the canonical detection path and standalone experimental components, see [`docs/PROJECT_STATUS.md`](docs/PROJECT_STATUS.md). For public-release cleanup history, see [`MIGRATION_NOTES.md`](MIGRATION_NOTES.md).

## Architecture

```text
Cowrie ───────────────┐
                      ├──> core/parser.py
Suricata ─────────────┘          │
                                 ▼
                       core/session_builder.py
                       (source + source-IP sessions)
                                 │
                                 ▼
                       core/feature_engine.py
                                 │
                                 ▼
                         XGBoost model (offline)
                                 │
                                 ▼
                       core/fusion_engine.py
                       (ML + behavioral heuristics)
                                 │
              ┌──────────────────┼──────────────────┐
              ▼                  ▼                  ▼
      attack timeline     campaign heuristics   active response
        (heuristic)           (heuristic)       (disabled by default)
              └──────────────────┼──────────────────┘
                                 ▼
                   pipeline/offline_pipeline.py
                                 │
                                 ▼
                    data/final_soc_output.json
```

`experimental/` contains runnable research components (MITRE mapping, Isolation Forest, local-LLM investigation summaries, and an alternate session builder) that are **not called by** `pipeline/offline_pipeline.py`. They must not be presented as active detection capabilities.

## Scope

- **Canonical path:** offline/batch processing only.
- **Telemetry:** Suricata `eve.json` and Cowrie JSON logs supplied by the operator.
- **Primary ML model:** calibrated XGBoost classifier.
- **Hybrid scoring:** XGBoost probability plus hand-tuned behavioral indicators.
- **Response:** optional lab-only `iptables` block mechanism, disabled by default and protected by multiple gates.
- **Not included:** live/streaming detection, a dashboard, production deployment, or a verified APT detector.

## Quick start

Use Python **3.11+** (the canonical pipeline imports `datetime.UTC`).

```bash
git clone <this-repo>
cd AEGIS-HYBRID
python -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt
cp .env.example .env   # edit telemetry/model paths as needed
```

Build the dataset and train the model from your own Cowrie/Suricata logs:

```bash
python -m ml.prepare_dataset
python -m ml.train_model
python -m pipeline.offline_pipeline   # writes data/final_soc_output.json
python -m evaluation.evaluate_system # writes evaluation_results/metrics.json
```

Run the test suite:

```bash
pytest
```

### Optional auxiliary ingestion API

`ingestion/ingest_api.py` is a hardened **standalone log-shipping utility**. It is **not part of the canonical offline detection path** and does not make AEGIS-HYBRID a live IDS. It requires `INGEST_API_KEY`, binds to `127.0.0.1` by default, and remains lab-grade. See `SECURITY.md` before using it.

```bash
export $(grep -v '^#' .env | xargs)
python -m ingestion.ingest_api
```

## Data and evaluation caveats

The repository intentionally does not commit a trained model, raw telemetry, or generated metrics. The dataset builder uses source-based heuristic labels, and the current train/evaluation code selects a threshold on the same held-out split used for reported metrics. These choices can make performance optimistic and can allow the model to learn source-specific artifacts rather than general malicious behavior. Do **not** cite the historical thesis metrics as results of this repository; regenerate and report versioned metrics from the current code instead.

## Repository layout

| Path | Contents |
|---|---|
| `config/` | Environment-driven settings and safe defaults. |
| `core/` | Canonical parsing, source-specific sessionization, feature engineering, fusion, timeline/campaign heuristics, and active-response gate. |
| `ml/` | Dataset construction and XGBoost training. |
| `pipeline/` | Offline batch detection pipeline and SOC JSON output. |
| `evaluation/` | Evaluation of the fused scoring path. |
| `ingestion/` | Optional standalone Cowrie event ingestion utility; not part of offline detection. |
| `experimental/` | Implemented but not wired research components. |
| `tests/` | Focused unit and safety-gate tests. |
| `architecture/` | Architecture notes matching the current implementation. |
| `docs/` | Status, methodology caveats, and release-audit records. |

## License

The repository's original source and documentation are **not released under the MIT License**. See [`LICENSE`](LICENSE) and [`NOTICE`](NOTICE) for the applicable copyright and permission terms. Third-party dependencies remain subject to their respective licenses.

## Author & Copyright

**Author:** Sabreen Yahya Hajouri  
**Project:** AEGIS-HYBRID  
**Copyright © 2026 Sabreen Yahya Hajouri. All rights reserved.**

This repository is publicly viewable for reference and portfolio purposes. Reuse,
redistribution, modification, publication, or commercial use requires explicit
written permission from the copyright holders.
