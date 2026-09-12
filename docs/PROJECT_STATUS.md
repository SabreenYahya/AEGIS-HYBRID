# Project Status — Engineering Classification

> ## ⚠️ Do not cite the thesis/presentation metrics as this repository's results
>
> The graduation thesis and presentation report **Accuracy 94.39% /
> Precision 88.14% / Recall 75.91% / F1 81.57% / ROC-AUC 0.9824 / FPR
> 0.0199957**. Those numbers were produced by an earlier version of
> `evaluation/evaluate_system.py` that applied an undocumented
> `soft_recall_boost()` transform to the ML probability before fusion
> scoring — a transform that existed **only** in that evaluation
> script and was never part of the actual inference path
> (`pipeline/offline_pipeline.py`). That boost has been removed in
> this repository (see `MIGRATION_NOTES.md`).
>
> **Consequence:** re-running `evaluation/evaluate_system.py` in this
> repository against the same dataset will very likely produce
> *different, probably lower*, recall/F1/accuracy numbers than the
> thesis. This has not yet been re-run and confirmed here — no metrics
> from this repository have been published anywhere as of this
> writing.
>
> **Before publishing any accuracy/precision/recall/F1/ROC-AUC/FPR
> number for this repository, you must:**
> 1. Run `python -m ml.prepare_dataset` and `python -m ml.train_model`
>    against real Cowrie/Suricata telemetry.
> 2. Run `python -m evaluation.evaluate_system` and read
>    `evaluation_results/metrics.json`.
> 3. Report *those* numbers, explicitly dated and versioned, not the
>    thesis numbers. If they differ substantially from the thesis, say
>    so — that is expected given the boost removal, not a regression
>    to hide.
> 4. If you have not done step 1–3 yet, the README/thesis links in
>    this repo should describe methodology only, with no specific
>    performance numbers attached to *this* codebase.

This table reflects what the code in this repository actually does,
verified against `pipeline/offline_pipeline.py` (the only pipeline
that produces `data/final_soc_output.json`). Anything not imported
from there is marked accordingly, regardless of how complete the
module itself is.

| Component | Status | Evidence |
|---|---|---|
| Suricata + Cowrie parsing (`core/parser.py`) | **Core** | Called directly by `pipeline/offline_pipeline.py` via `load_events()`. |
| Event schema (`core/event_schema.py`) | **Core** | Data contract produced by the parser and consumed by every downstream module. |
| Behavioral sessionization (`core/session_builder.py`) | **Core** | `create_behavioral_sessions()` is called by the pipeline. |
| Feature engineering (`core/feature_engine.py`) | **Core** | `extract_features()` is called per-session by the pipeline. |
| XGBoost training/inference (`ml/train_model.py`) | **Core** | Model artifact loaded and scored against in `pipeline/offline_pipeline.py`. |
| Hybrid fusion scoring (`core/fusion_engine.py`) | **Core** | `calculate_hybrid_score()` combines the ML probability with behavioral features to produce the final threat score. |
| Attack timeline reconstruction (`core/attack_timeline.py`) | **Core, heuristic** | Called by the pipeline; stage detection is threshold-based, not learned. |
| APT-heuristic labeling (`core/attack_timeline.py::detect_apt_behavior`) | **Core, heuristic — not verified APT detection** | Weighted rule score against hand-set thresholds (5/8/12). "APT_CRITICAL" means "matched several heuristic conditions," not a confirmed advanced-persistent-threat determination. |
| Campaign correlation (`core/apt_campaign_engine.py`) | **Core, heuristic** | Deterministic fingerprinting/clustering, not a learned correlation model. |
| Active response (`core/active_response.py`) | **Implemented, disabled by default** | Three-gate safety model (feature flag, IP allowlist, dry-run). See `SECURITY.md`. |
| Ingestion API (`ingestion/ingest_api.py`) | **Core, hardened** | Requires API key; rate-limited; bounded dedup cache. Still lab-grade — no TLS termination provided. |
| **MITRE ATT&CK mapping** (`experimental/mitre_mapping.py`) | **Implemented, NOT wired** | Not imported by `pipeline/offline_pipeline.py`. No detection record currently carries a MITRE tactic/technique. |
| **Isolation Forest** (`experimental/anomaly_detector.py`) | **Implemented, NOT wired** | Trained/persisted independently; not loaded or scored against in the pipeline. |
| **LLM investigation** (`experimental/llm_analysis.py`) | **Implemented, NOT part of detection** | Consumes an already-scored detection record for a human-readable summary. Cannot change a score or classification. |
| Alternate stateful session builder (`experimental/stateful_session_builder.py`) | **Alternate implementation, unused** | Timeout-based streaming variant; not called by any entry point in this repo. |
| **Dashboard** | **Not included in this repository yet** | The pipeline's JSON output (`data/final_soc_output.json`) is a stable contract a dashboard can consume, but no dashboard code currently ships here. If/when one is added, verify explicitly whether it reads this file or uses mock data before describing it as "live." |
| Live/streaming detection path | **Missing** | No online-capture entry point in this repository consumes `core/parser.py`, `core/session_builder.py`, or the trained model. `pipeline/offline_pipeline.py` is batch-only. |

## Known methodology caveats (read before citing metrics)

- **Labeling is source-based, not purely behavioral.** `ml/prepare_dataset.py` labels Cowrie-sourced sessions as attacks and Suricata-sourced sessions by alert ratio. A model trained this way can partly learn "which log source produced this" rather than "is this behavior malicious" — command-based features in particular can act as a near-perfect proxy for the Cowrie label. Any reported accuracy/precision/recall should be read with this in mind.
- **Threshold selection is fit on the same held-out split used to report final metrics** (both in `ml/train_model.py` and `evaluation/evaluate_system.py`). This is threshold *fitting*, not an independently validated threshold — treat reported FPR/recall as optimistic.
- **The fusion weights in `core/fusion_engine.py` are hand-tuned**, not learned. They were adjusted against this lab's dataset and have not been validated against out-of-distribution traffic.
- **No automated rollback exists for active response.** Even with the safety gates in `core/active_response.py`, an IP that is blocked stays blocked until a human removes the iptables rule.

## Deliberate deviations from an earlier version of this codebase

- The evaluation script no longer applies an undocumented probability
  boost ("soft_recall_boost") that existed only in evaluation and not
  in `pipeline/offline_pipeline.py`'s actual inference path. Removing
  it makes the reported metrics representative of production
  behavior, at the cost of a lower reported recall than the earlier
  (misleading) figure.
- A `visualization/` module that referenced non-existent internal
  modules (`analysis.parser`, `analysis.classifier_new`) has been
  removed rather than carried forward — it could not have run.
- A live-capture script built around a different, older model
  artifact and a disjoint feature set has been removed rather than
  carried forward, to avoid implying it is part of the current
  detection path. Re-introducing live detection should build on
  `core/parser.py` + `core/session_builder.py` + the current model,
  not resurrect that script.
