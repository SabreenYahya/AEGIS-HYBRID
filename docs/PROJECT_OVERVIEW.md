# Project Overview

## Identity

**AEGIS-HYBRID** is an offline/batch cybersecurity research prototype for behavioral detection using telemetry from Suricata and Cowrie.

**Author:** Sabreen Yahya Hajouri, Cybersecurity Engineer.

## Problem

Network IDS alerts and honeypot interactions expose different evidence about attacker behavior. AEGIS-HYBRID explores whether those signals can be normalized, transformed into behavioral sessions/features, scored with machine learning, and combined with deterministic behavioral indicators into one traceable threat score.

## Scope

The current canonical system:

- consumes exported Suricata and Cowrie logs;
- normalizes records into a shared event schema;
- builds **source-specific, source-IP sessions**;
- extracts behavioral features;
- scores sessions with a calibrated XGBoost model;
- applies hand-tuned behavioral fusion;
- produces heuristic timeline/campaign information;
- writes SOC-oriented JSON output;
- can optionally request a lab-only `iptables` block through a gated mechanism.

## Explicit non-goals

The repository does not currently provide:

- live packet capture or streaming detection;
- a SIEM;
- a production IDS/IPS;
- cross-source attacker session correlation;
- verified APT detection;
- a dashboard;
- an independently validated production benchmark.

## Evidence model

The project prioritizes traceability over marketing claims. The canonical implementation is defined by `pipeline/offline_pipeline.py`; components not imported by that path are not part of the active detection decision.

For the exact classification of every major component, see [`PROJECT_STATUS.md`](PROJECT_STATUS.md).
