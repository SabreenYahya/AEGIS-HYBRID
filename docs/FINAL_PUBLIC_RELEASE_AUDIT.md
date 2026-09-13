# Public Release Audit Record

This document records the repository-release audits and their scope. It is not a substitute for a reproducible ML evaluation report.

## Previous release audit rounds

Earlier rounds covered restructuring, removal of misleading/dead legacy components, ingestion hardening, active-response safety gates, and focused unit tests. The previous lightweight suite recorded **23/23 tests passed**; it did not run training or end-to-end evaluation.

## Independent repository audit — 2026-09-13

A fresh read-only audit of the current public repository was performed across the repository tree, canonical pipeline, ML/evaluation code, configuration, security controls, tests, experimental boundary, and release documentation.

### Material findings

1. **Documentation overstated cross-source fusion.** The previous architecture text implied that Cowrie and Suricata events were fused into one behavioral session. The actual `core/session_builder.py` groups by source + source IP, so cross-source session correlation is not implemented.
2. **README/license wording was inconsistent.** `README.md` previously said `MIT` while `LICENSE` explicitly reserved rights. The README now reflects the actual repository license terms.
3. **Python-version metadata was inconsistent.** `pyproject.toml` declared Python >=3.10 although the canonical pipeline imports `datetime.UTC`, which requires Python 3.11+. The metadata now requires >=3.11.
4. **Ingestion import had an avoidable filesystem side effect.** Importing `ingestion.ingest_api` previously created `/opt/logs` and started a writer thread. The writer is now started lazily when the utility is used, and its output directory is created only when writing.
5. **The canonical/offline boundary was unclear for ingestion.** Documentation now explicitly classifies the ingestion API as a standalone auxiliary log-shipping utility, not as a live detection path.

### Methodology findings intentionally not “fixed” in this release

- Source-based labeling remains a known label-leakage risk.
- Threshold selection remains fit on the held-out split; this requires a methodological evaluation redesign, not a safe cosmetic patch.
- Fusion weights remain hand-tuned and unvalidated out of distribution.
- No cross-source session correlation was added because doing so would redesign the current project rather than correct a defect.
- No dashboard, live capture, MITRE wiring, Isolation Forest integration, LLM decisioning, or continual-learning functionality was added.

### Current release position

The repository can honestly be presented as an **Offline Hybrid IDS research/engineering prototype** when the description explicitly states:

- offline/batch operation;
- source-specific Cowrie/Suricata sessionization rather than cross-source session fusion;
- calibrated XGBoost plus hand-tuned behavioral fusion;
- heuristic timeline/campaign/APT labels;
- lab-only active response, disabled by default;
- experimental components are not part of the canonical decision path;
- historical thesis metrics are not current repository metrics.

The code is suitable for public portfolio review with these limitations. It should **not** be presented as a production IDS/IPS, live SOC platform, verified APT detector, or experimentally validated general-purpose detector.

## Final assessment

**READY WITH LIMITATIONS** for public GitHub portfolio use.

The remaining limitations are primarily methodological and scope-related rather than evidence of a hidden production capability. They should remain visible in the project documentation rather than being masked by additional claims or speculative refactoring.
