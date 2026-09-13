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
> **Consequence:** this repository currently contains **no generated
> performance result**. Do not present the thesis metrics as results of
> the current codebase.
>
> **Before publishing any accuracy/precision/recall/F1/ROC-AUC/FPR
> number for this repository, you must:**
> 1. Run `python -m ml.prepare_dataset` and `python -m ml.train_model`
>    against real Cowrie/Suricata telemetry.
> 2. Run `python -m evaluation.evaluate_system` and inspect
>    `evaluation_results/metrics.json`.
> 3. Report those numbers explicitly dated and versioned, not the thesis
>    numbers. If they differ substantially, say so.
> 4. Until then, describe methodology and limitations only.

This table reflects what the code in this repository actually does,
verified against `pipeline/offline_pipeline.py` (the only pipeline that
produces `data/final_soc_output.json`). Anything not imported from there
is marked accordingly.

| Component | Status | Evidence |
|---|---|---|
| Suricata + Cowrie parsing (`core/parser.py`) | **Core** | Called directly by `pipeline/offline_pipeline.py` via `load_events()`. |
| Event schema (`core/event_schema.py`) | **Core** | Shared normalized event contract. |
| Behavioral sessionization (`core/session_builder.py`) | **Core** | Groups by **source + source IP** and is called by the pipeline. |
| Cross-source session correlation | **Not implemented** | Cowrie and Suricata events do not currently become one cross-source behavioral session. |
| Feature engineering (`core/feature_engine.py`) | **Core** | `extract_features()` is called per session. |
| XGBoost training/inference (`ml/train_model.py`) | **Core** | Model artifact is loaded and scored by the offline pipeline. |
| Hybrid fusion scoring (`core/fusion_engine.py`) | **Core, heuristic** | Combines ML probability with hand-tuned behavioral indicators. |
| Attack timeline reconstruction (`core/attack_timeline.py`) | **Core, heuristic** | Called by the pipeline; stage detection is threshold-based. |
| APT-heuristic labeling (`core/attack_timeline.py::detect_apt_behavior`) | **Core, heuristic — not verified APT detection** | Weighted rule score; `APT_CRITICAL` means several heuristic conditions matched, not a confirmed APT. |
| Campaign correlation (`core/apt_campaign_engine.py`) | **Core, heuristic** | Deterministic fingerprinting/correlation, not a learned campaign model. |
| Active response (`core/active_response.py`) | **Implemented, disabled by default** | Feature flag + CIDR allowlist + dry-run gate. No automatic rollback. |
| Ingestion API (`ingestion/ingest_api.py`) | **Standalone auxiliary utility** | Authenticated/rate-limited log shipping; **not part of the canonical offline detection path** and does not provide live detection. |
| **MITRE ATT&CK mapping** (`experimental/mitre_mapping.py`) | **Implemented, NOT wired** | No current detection record carries MITRE technique output. |
| **Isolation Forest** (`experimental/anomaly_detector.py`) | **Implemented, NOT wired** | Not loaded or scored by the canonical pipeline. |
| **LLM investigation** (`experimental/llm_analysis.py`) | **Implemented, NOT part of detection** | Consumes an already-scored record for human-readable investigation output. |
| Alternate stateful session builder (`experimental/stateful_session_builder.py`) | **Alternate implementation, unused** | Not called by the canonical pipeline. |
| **Dashboard** | **Not included** | No dashboard code currently ships in this repository. |
| Live/streaming detection path | **Not implemented** | `pipeline/offline_pipeline.py` is batch-only. |

## Known methodology caveats

- **Labeling is source-based, not ground truth.** `ml/prepare_dataset.py` labels Cowrie sessions as attacks and Suricata sessions using alert-ratio thresholds. This can make the model learn source-specific artifacts rather than malicious behavior; command features are especially correlated with the Cowrie label.
- **Threshold selection is fit on the same held-out split used to report final metrics** in both `ml/train_model.py` and `evaluation/evaluate_system.py`. This is threshold fitting, not independent validation, so reported performance can be optimistic.
- **Fusion weights are hand-tuned**, not learned, and have not been validated against out-of-distribution traffic.
- `ml/train_model.py` stores a model threshold in the `.pkl`, but `pipeline/offline_pipeline.py` intentionally uses the environment-controlled `DETECTION_THRESHOLD` instead. The logged `model_threshold` is therefore metadata, not the runtime decision threshold.
- **No automatic rollback exists for active response.** A successfully added iptables rule remains until a human removes it.

## Deliberate deviations from the earlier prototype

- Removed the evaluation-only `soft_recall_boost()` because it was not part of the actual inference path.
- Removed the obsolete visualization implementation because it referenced missing internal modules and did not provide a truthful live dashboard.
- Removed the older live-capture script because it used a different model artifact and incompatible feature dictionary.
- Removed unused legacy analysis/alerting/classifier modules rather than presenting them as active functionality.
- Kept MITRE mapping, Isolation Forest, LLM analysis, and alternate sessionization under `experimental/` because they are implemented but not wired into the canonical detection path.
