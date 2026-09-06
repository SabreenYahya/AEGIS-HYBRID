# AEGIS-HYBRID — Engineering Status

## Scope

AEGIS-HYBRID is the academic/research system: a multi-layer hybrid security platform for correlating network IDS telemetry and honeypot behavior into behavioral sessions, threat scores, and SOC-oriented analysis.

## Implemented Foundation

- Suricata network telemetry
- Cowrie SSH/Telnet honeypot telemetry
- Log parsing and normalization
- Unified event representation
- Behavioral session construction
- Security feature extraction
- XGBoost-based session classification
- Hybrid Fusion Engine
- Multi-stage attack timeline/campaign analysis
- MITRE ATT&CK and Cyber Kill Chain mapping
- SOC dashboard and analytical views
- Basic active-response capability
- Offline evaluation pipeline
- LLM-assisted security analysis concept

## Engineering Classification

| Component | Status | Notes |
|---|---|---|
| Suricata | Core | Network telemetry / IDS |
| Cowrie | Core | Honeypot telemetry |
| Parsing & normalization | Core | Multi-source event unification |
| Behavioral sessions | Core | Source/time based aggregation |
| Feature engineering | Core | Session-level security features |
| XGBoost | Core | Threat probability/classification |
| Fusion Engine | Core | ML + behavioral risk fusion |
| Campaign/timeline analysis | Core | Multi-stage correlation |
| MITRE mapping | Core | Analytical enrichment |
| Dashboard | Core | SOC visualization |
| Active response | Experimental / hardening required | Must include safety controls, audit logging and rollback |
| LLM analysis | Experimental | Evidence-grounded explanation; not the detector |
| Isolation Forest | Experimental / legacy | Retain only if independently validated and clearly separated from the primary path |
| Enterprise SaaS / multi-tenancy | Future scope | Not part of the academic core |

## Evaluation Integrity

Published metrics must be tied to a reproducible evaluation procedure. Training/test separation, session-level leakage, label construction, threshold selection, and calibration must be documented before presenting performance as a generalization claim.

## Security Hardening Priorities

1. Remove secrets and environment-specific credentials from source control.
2. Validate all external inputs and IP addresses before processing or response actions.
3. Put active response behind explicit safety controls, allowlists, cooldowns, audit logs, and rollback.
4. Replace broad exception handling with specific errors and observable failure states.
5. Separate demo/static outputs from runtime-generated state.
6. Document every pipeline dependency and execution path.
7. Add reproducible tests for parsing, normalization, sessionization, feature extraction, scoring, and response safety.

## Product Direction

A future enterprise platform may be derived from AEGIS-HYBRID, but enterprise features such as multi-tenancy, RBAC, external SIEM/EDR integrations, cloud telemetry, and multi-LLM orchestration remain separate future/product scope unless implemented and tested in this repository.
