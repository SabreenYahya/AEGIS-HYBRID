# AEGIS-HYBRID — Phase A: Foundation, Scope & Repository Integrity Audit

## Purpose

Phase A establishes the engineering baseline before functional changes. It answers four questions:

1. What is AEGIS-HYBRID today?
2. Which artifacts belong to the academic/research core?
3. Which artifacts belong to the future HYBRID-AEGIS SOC product?
4. What must be protected, corrected, isolated, or removed before deeper implementation work?

This phase is an **audit and alignment phase**, not a feature-development phase.

## Source-of-Truth Model

The repository and the available project source/blueprint are treated as two different evidence layers:

- **Repository evidence:** what is actually committed to GitHub.
- **Engineering-source evidence:** the complete project source and product blueprint supplied for analysis.

A feature is not classified as implemented merely because it appears in the blueprint. Runtime status must be verified against executable source and tests.

## System Boundary

### AEGIS-HYBRID — Academic / Research Core

The core pipeline is:

`Suricata + Cowrie → Parsing → Normalization → Behavioral Sessions → Feature Engineering → XGBoost → Hybrid Fusion → Campaign/Timeline Analysis → MITRE Enrichment → SOC Presentation`

This is the system that must remain scientifically traceable and reproducible.

### HYBRID-AEGIS SOC — Future Product Layer

The enterprise product blueprint includes capabilities such as multi-tenancy, RBAC, persistent databases, API-first services, external telemetry integrations, multi-LLM orchestration, investigation workspaces, audit trails, and production deployment.

These are **product scope**, not evidence that the academic core currently implements them.

## Phase A Findings

### A1 — Repository Integrity

- The repository is publicly accessible and the engineering-alignment work is being developed on a dedicated branch: `docs/engineering-alignment`.
- The repository currently contains documentation and architecture material, but the GitHub tree inspected during this phase does not contain the full upgraded Python/ML application source described in the supplied engineering source.
- Therefore, the upgraded source must not be represented as already present in GitHub until it is actually imported, reviewed, tested, and committed.

### A2 — Documentation Alignment

The README and architecture documentation have been upgraded to describe the layered behavioral architecture rather than the earlier student-style implementation status.

The current project-status document explicitly separates Core, Experimental/Hardening, Legacy, and Future scope.

### A3 — Security Hygiene

A root `.gitignore` has been added to prevent common secrets, credentials, runtime logs, generated state, ML artifacts, local datasets, and development-tool artifacts from entering source control.

This is a preventative control. It does **not** prove that historical commits contain no secrets. Historical secret scanning remains a separate verification task.

### A4 — Runtime Reality

The supplied engineering source demonstrates a real Python pipeline design including parser, unified schema, feature extraction, session construction, model loading, fusion, campaign analysis, and active-response code.

However, the available GitHub repository snapshot does not yet contain those implementation files. Consequently, Phase A records them as **source evidence awaiting repository integration**, not as GitHub-verified runtime components.

### A5 — Active Response Boundary

The supplied source contains an `iptables` block path. Because firewall changes are consequential, active response must remain disabled-by-default until allowlists, validation, authorization/approval, cooldowns, audit logging, and rollback are implemented and tested.

### A6 — ML Integrity Boundary

The project must not publish academic performance values as current product performance. Any future ML result must be generated from a documented dataset and reproducible evaluation procedure with leakage checks and session-level train/test separation.

The product UI must use truthful states such as `Not Evaluated Yet` when no current validated model exists.

## Artifact Classification Rules

| Classification | Meaning | Action |
|---|---|---|
| Core | Required for the AEGIS-HYBRID detection/correlation pipeline | Preserve, test, document |
| Experimental | Useful but not trusted as a primary production path | Isolate, label, test before promotion |
| Legacy | Superseded implementation retained for provenance | Preserve only when useful; do not use as primary path |
| Static/Demo | UI or presentation fixture rather than runtime evidence | Label clearly; replace with live data when implementing product |
| Future | Product roadmap capability not currently implemented | Keep in blueprint/roadmap, not implementation claims |
| Remove | Misleading, duplicated, secret-bearing, or unsafe artifact | Remove after confirming provenance/impact |

## Phase A Exit Criteria

Phase A is complete when all of the following are true:

- [x] Repository identity and branch boundary established.
- [x] README aligned with the engineering architecture.
- [x] Architecture documentation aligned with the layered pipeline.
- [x] Project status and provenance rules documented.
- [x] Root Git ignore policy added.
- [x] Academic-vs-product boundary explicitly documented.
- [x] ML integrity and active-response safety boundaries documented.
- [ ] Full upgraded source tree imported into the repository.
- [ ] Every source file classified against the actual runtime graph.
- [ ] Secrets/history scan completed.
- [ ] Runtime entry points verified end-to-end.
- [ ] Phase A validation tests executed on the committed source.

## Phase A Decision

**Decision: PASS WITH BLOCKERS.**

The architecture and documentation baseline is aligned, but implementation claims must remain conservative until the upgraded source tree is present in GitHub and executable paths are verified. The next engineering action is therefore **source integration and code-level audit**, not adding new product features.
