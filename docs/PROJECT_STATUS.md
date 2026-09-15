# Project Status — Engineering Classification

> ## ⚠️ Do not cite historical thesis metrics as repository results
>
> The graduation thesis/presentation reported Accuracy 94.39%, Precision 88.14%, Recall 75.91%, F1 81.57%, ROC-AUC 0.9824, and FPR 0.0199957. Those values came from an earlier evaluation implementation that included an evaluation-only `soft_recall_boost()` transform and are not results of the current public codebase.
>
> The public repository intentionally contains no generated benchmark metrics, raw telemetry, or trained model. Before publishing new numbers, run the current training/evaluation workflow and record the dataset, commit, date, split, threshold, and metrics.

This table reflects the current canonical implementation. Anything not imported by `pipeline/offline_pipeline.py` is not part of the active detection decision.

| Component | Status | Evidence |
|---|---|---|
| Suricata + Cowrie parsing (`core/parser.py`) | **Core** | Called by the canonical pipeline. |
| Event schema (`core/event_schema.py`) | **Core** | Shared normalized event contract. |
| Behavioral sessionization (`core/session_builder.py`) | **Core** | Groups by **source + source IP**. |
| Cross-source session correlation | **Not implemented** | Sources are not merged into one attacker session. |
| Feature engineering (`core/feature_engine.py`) | **Core** | Features are extracted per behavioral session. |
| XGBoost training/inference (`ml/train_model.py`) | **Core** | Calibrated model artifact is loaded at runtime. |
| Hybrid fusion scoring (`core/fusion_engine.py`) | **Core, heuristic** | ML probability plus hand-tuned behavioral indicators. |
| Attack timeline reconstruction | **Core, heuristic** | Deterministic threshold-based stage analysis. |
| APT-style labeling | **Core, heuristic — not verified APT detection** | Rule score, not attribution or confirmation. |
| Campaign correlation | **Core, heuristic** | Deterministic fingerprinting/correlation. |
| Active response | **Implemented, disabled by default** | Feature flag, allowlist, and dry-run gates; no rollback. |
| Ingestion API | **Standalone auxiliary utility** | Authenticated/rate-limited shipping; not live detection. |
| MITRE ATT&CK mapping | **Experimental / not wired** | Not emitted by the canonical detection path. |
| Isolation Forest | **Experimental / not wired** | Not scored by the canonical pipeline. |
| LLM investigation | **Experimental / not wired** | Not part of detection. |
| Alternate stateful session builder | **Experimental / unused** | Not called by the canonical pipeline. |
| Dashboard | **Not included** | No dashboard ships in the public repository. |
| Live/streaming detection | **Not implemented** | Canonical path is offline/batch. |

## Current ML/evaluation methodology

- Dataset labels remain heuristic/source-based; they are not verified ground truth.
- Training uses a deterministic **60% train / 20% validation / 20% test** split.
- The runtime decision threshold is selected on **validation fusion scores**, not raw ML probabilities and not the test set.
- The untouched test partition is reserved for final evaluation.
- The selected threshold is persisted as `threshold_space: "fusion_score"` and is consumed by the offline pipeline through the configured detection-threshold contract.
- The split is deterministic (`random_state=42`) for reproducibility, but it is not a substitute for attacker/time/group-aware splitting.
- Fusion weights remain hand-tuned and are not independently validated for out-of-distribution traffic.

## Dataset caveat

`ml/prepare_dataset.py` labels Cowrie sessions as attacks and derives Suricata labels from alert-ratio thresholds. This can create source/label correlation and allow the model to learn telemetry-source artifacts rather than generalized malicious behavior.

## Deliberate deviations from the earlier prototype

- Removed the evaluation-only `soft_recall_boost()` because it was not part of the actual inference path.
- Removed obsolete visualization/live-capture components that depended on incompatible internal modules/artifacts.
- Removed unused legacy analysis/alerting/classifier modules rather than presenting them as active functionality.
- Kept MITRE mapping, Isolation Forest, LLM analysis, and alternate sessionization under `experimental/` because they are implemented but not wired into the canonical detection path.
