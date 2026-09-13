# AEGIS-HYBRID System Architecture

AEGIS-HYBRID is an **offline/batch defensive analytics pipeline**. It separates telemetry parsing, normalization, source-specific behavioral sessionization, feature engineering, ML scoring, heuristic fusion, and downstream timeline/campaign analysis.

## Layer 1 — Collection

**Sources:**
- **Suricata IDS** — network telemetry, alerts, protocols, flows, and source/destination context.
- **Cowrie Honeypot** — SSH/Telnet interaction, login attempts, sessions, and commands.

The repository consumes exported log files. It does not currently capture packets or run a live detection loop.

## Layer 2 — Processing

### Parsing and normalization
`core/parser.py` converts supported Cowrie and Suricata records into the shared `UnifiedEvent` schema.

### Sessionization
`core/session_builder.py` groups events by **source and source IP**, then splits groups by time gaps and maximum session size.

**Important:** this means Cowrie and Suricata events are normalized through the same schema and pipeline, but the current implementation does **not** create a single cross-source behavioral session for one attacker. Cross-source correlation remains outside the canonical sessionization logic.

## Layer 3 — Behavioral Analysis

Behavioral sessions are converted into numerical features describing activity volume, timing, burstiness, stage transitions, command diversity, port/IP fan-out, and related indicators.

The primary classifier is a calibrated **XGBoost** model trained offline from the dataset produced by `ml/prepare_dataset.py`.

## Layer 4 — Decision & Correlation

### Hybrid Fusion Engine
`core/fusion_engine.py` combines the ML probability with hand-tuned behavioral indicators into a single threat score. The fusion weights are heuristic and have not been independently validated for out-of-distribution traffic.

### Attack timeline and campaign analysis
`core/attack_timeline.py` and `core/apt_campaign_engine.py` perform deterministic, threshold-based analysis. Their APT labels are heuristic labels and are **not verified APT detection**.

### Active response
`core/active_response.py` contains an optional lab-only `iptables` response. It is disabled by default, restricted by an explicit CIDR allowlist, and dry-run by default. There is no automatic rollback.

## Experimental components

`experimental/` contains runnable but disconnected research components:

- MITRE ATT&CK keyword mapping
- Isolation Forest anomaly detection
- Local Ollama/LLM investigation summaries
- An alternate stateful session builder

None is called by `pipeline/offline_pipeline.py`, so none should be described as part of the canonical detection decision.

## Canonical data flow

```text
Suricata ─┐
          ├─> Parser / Unified Events
Cowrie ───┘          │
                     ▼
          Source + Source-IP Sessions
                     │
                     ▼
          Feature Engineering
                     │
                     ▼
              XGBoost Score
                     │
                     ▼
             Hybrid Fusion Score
                     │
          ┌──────────┼──────────┐
          ▼          ▼          ▼
      Timeline    Campaign   Active Response
      heuristics  heuristics  (gated/optional)
          └──────────┼──────────┘
                     ▼
             Offline SOC JSON
```

## Engineering classification

| Area | Classification |
|---|---|
| Suricata + Cowrie file telemetry | Core input |
| Parsing + normalization | Core |
| Source-specific behavioral sessions | Core |
| Cross-source session correlation | **Not implemented** |
| Feature engineering | Core |
| XGBoost classifier | Core |
| Hybrid Fusion Engine | Core, heuristic weights |
| Campaign/timeline analysis | Core, heuristic |
| MITRE mapping | Experimental / not wired |
| Isolation Forest | Experimental / not wired |
| LLM investigation | Experimental / not wired |
| Dashboard | **Not included** |
| Live/streaming detection | **Not implemented** |
| Active response | Optional lab artifact / disabled by default |

This document intentionally describes only capabilities that exist in the current repository. Future integrations must not be presented as implemented until code, tests, and operational documentation exist.
