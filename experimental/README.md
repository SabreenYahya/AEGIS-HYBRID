# Experimental / Not Wired to the Detection Path

Everything in this folder is real, runnable code — but **none of it is
imported by `pipeline/offline_pipeline.py`**, which is the only
pipeline that actually produces `data/final_soc_output.json`. Treat
these as standalone research components pending integration, not as
active parts of the detection decision.

| File | What it does | Why it's here and not in `core/` |
|---|---|---|
| `mitre_mapping.py` | Keyword-based lookup mapping a signature/stage string to a MITRE ATT&CK tactic/technique ID. | Implemented and self-contained, but no caller in the current pipeline attaches its output to a detection record. Wiring it in is a documented next step (see `docs/PROJECT_STATUS.md`). |
| `anomaly_detector.py` | Isolation Forest trained on the same session features, with an ECDF-based score calibration. | Trained/saved independently of `ml/train_model.py`'s XGBoost model; `pipeline/offline_pipeline.py` never loads or scores against it. |
| `llm_analysis.py` | Sends a detection record to a local Ollama model and returns a human-readable incident summary (attack stage, recommended actions, confidence). | Explicitly **not** part of scoring, classification, or blocking — it consumes a decision that was already made, it does not make one. Requires a locally running Ollama instance; disabled if `OLLAMA_URL` is unset. |
| `stateful_session_builder.py` | An alternate, timeout-based streaming session builder (`StatefulSessionBuilder`), distinct from `core/session_builder.py`'s batch implementation. | Not imported by either the offline pipeline or the disconnected live-capture script. Kept because it is a plausible foundation for a future real-time path, not because it currently runs. |

If you plan to publish results that mention MITRE mapping, anomaly
detection, or LLM-assisted analysis as capabilities of AEGIS-HYBRID,
qualify the claim: the code exists, but it is not part of the scored
detection output today.
