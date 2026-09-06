# AEGIS-HYBRID

**A Hybrid Behavioral Framework for Multi-Stage Cyberattack Correlation within SOC Environments**

> From Deception to Learning — integrating network IDS telemetry, honeypot behavior, behavioral sessions, machine learning, and hybrid threat correlation.

## Overview

AEGIS-HYBRID is a multi-layer cybersecurity research and engineering platform designed to correlate heterogeneous security telemetry into meaningful behavioral activity rather than treating every alert as an isolated event.

The system combines **Suricata IDS** network telemetry with **Cowrie Honeypot** interaction logs, transforms the raw data into a unified event representation, builds behavioral sessions, extracts security features, applies an **XGBoost** classifier, and combines machine-learning output with behavioral indicators through a **Hybrid Fusion Engine**.

The resulting analysis is designed for SOC-oriented monitoring, multi-stage attack reconstruction, threat scoring, and analyst decision support.

## Architecture

```text
Kali / Attack Traffic
        |
        v
+----------------------+       +----------------------+
| Suricata IDS         |       | Cowrie Honeypot      |
| Network Telemetry    |       | SSH/Telnet Behavior  |
+----------+-----------+       +----------+-----------+
           |                              |
           +--------------+---------------+
                          v
               +-----------------------+
               | Parsing & Normalization|
               | Unified Event Schema   |
               +-----------+-----------+
                           |
                           v
               +-----------------------+
               | Behavioral Sessions   |
               | Time / Source grouping|
               +-----------+-----------+
                           |
                           v
               +-----------------------+
               | Feature Engineering   |
               | Session-level features|
               +-----------+-----------+
                           |
                           v
               +-----------------------+
               | XGBoost Classification|
               | Threat probability     |
               +-----------+-----------+
                           |
                           v
               +-----------------------+
               | Hybrid Fusion Engine  |
               | ML + behavior + stage |
               +-----------+-----------+
                           |
             +-------------+-------------+
             |             |             |
             v             v             v
        Threat Score   Campaign/Timeline  MITRE Mapping
             |             |             |
             +-------------+-------------+
                           v
                    SOC Dashboard
                           |
                           v
                  Analyst / Response
```

## Core Pipeline

1. **Collection** — Suricata and Cowrie generate heterogeneous security telemetry.
2. **Parsing** — source-specific JSON records are interpreted and relevant fields extracted.
3. **Normalization** — records are transformed into a common event structure.
4. **Sessionization** — related events are grouped into behavioral sessions using source and temporal context.
5. **Feature Engineering** — behavioral sessions are converted into numerical security features.
6. **ML Detection** — XGBoost estimates threat probability from session features.
7. **Hybrid Fusion** — ML output is combined with behavioral and attack-stage indicators to produce a unified threat assessment.
8. **Campaign Analysis** — related sessions can be reconstructed as multi-stage attack activity.
9. **Enrichment** — MITRE ATT&CK and Cyber Kill Chain mappings provide analyst context.
10. **SOC Presentation** — results are exposed through dashboards and analytical views.
11. **Response** — basic IP blocking exists as an experimental capability and requires operational safety controls.

## Key Components

| Component | Role |
|---|---|
| Suricata | Network IDS / security telemetry source |
| Cowrie | SSH/Telnet honeypot and attacker-interaction telemetry |
| Parser & Event Schema | Parse, normalize, and unify source events |
| Session Engine | Build behavioral sessions from related events |
| Feature Engineering | Extract session-level detection features |
| XGBoost | Supervised threat classification / probability estimation |
| Hybrid Fusion Engine | Combine ML and behavioral evidence |
| Campaign Engine | Correlate sessions into multi-stage campaigns |
| MITRE Mapper | Map observed behavior to ATT&CK techniques |
| Timeline Analysis | Reconstruct attack progression |
| SOC Dashboard | Monitoring, analysis, and visualization |
| Active Response | Experimental automated IP blocking |
| LLM Analysis | Experimental evidence-grounded analyst assistance |

## Project Structure

```text
AEGIS-HYBRID/
├── analysis/
├── ml/
├── ingestion/
├── evaluation/
├── visualization/
├── llm/
├── data/
├── state/
├── aegis-dashboard/
├── offline_pipeline_v2.py
└── online_pipeline_v2.py
```

## Experimental Environment

The academic validation environment uses isolated virtual machines with **Kali Linux**, **Ubuntu Server**, **Cowrie**, **Suricata**, and **VMware Workstation**. Attack scenarios include network reconnaissance/scanning, SSH brute force, and multi-stage attack behavior.

## Machine Learning & Evaluation

The primary classification path uses **XGBoost** on behavioral-session features. Evaluation is treated as an engineering integrity concern: reported metrics must be tied to reproducible labels, session-level train/test separation, leakage checks, calibration/threshold selection, and a documented evaluation procedure.

The repository should not interpret a single benchmark result as proof of production-level generalization.

## Active Response Safety

The project contains a basic firewall IP-blocking capability. Because automated response can disrupt legitimate traffic, it must be treated as a controlled security action rather than an unconditional detector output. Recommended safeguards include allowlists, dry-run mode, explicit approval where appropriate, cooldowns, audit logging, and rollback.

## Scope & Provenance

**AEGIS-HYBRID is the academic/research foundation.** Future product concepts such as multi-tenancy, RBAC, external SIEM/EDR integrations, cloud telemetry, and multi-LLM orchestration are not represented as implemented core functionality unless they are actually present, tested, and documented in this repository.

## Engineering Documentation

- [`docs/PROJECT_STATUS.md`](docs/PROJECT_STATUS.md) — implementation status, scope boundaries, and hardening priorities.
- `architecture/` — architecture documentation and diagrams.
- `evaluation/` — evaluation and reproducibility material.

## Status

**Research / Engineering Prototype — actively being hardened and documented.**

The current focus is reproducibility, ML integrity, security hardening, clean separation of core vs. experimental components, and professional documentation.

## Responsible Use

This project is intended for authorized security research, isolated laboratory environments, defensive monitoring, and educational use. Attack simulations should only be performed against systems you own or are explicitly authorized to test.
