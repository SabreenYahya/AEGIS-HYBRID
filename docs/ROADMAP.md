# Roadmap

The roadmap is deliberately short. Future work should follow evidence from the current prototype rather than adding features for appearance.

## P0 — correctness

- Establish a leakage-resistant evaluation protocol with validation-based threshold selection and an untouched test set.
- Replace source-derived labels with independently justified ground truth where feasible.
- Add tests covering the final evaluation split and threshold contract.

## P1 — detection engineering

- Design explicit cross-source attacker/session correlation with documented temporal and identity semantics.
- Validate fusion weights on data independent from the tuning set.
- Add time-, attacker-, or campaign-aware split strategies for future experiments.
- Expand reproducibility metadata for model and evaluation artifacts.

## P2 — capability expansion

- Integrate MITRE ATT&CK mapping only when its evidence contract is defined and tested.
- Evaluate anomaly detection as a separate experiment rather than silently mixing it into the canonical score.
- Consider live/streaming operation only after the offline path has independent validation and operational safety tests.
