# AEGIS-HYBRID System Architecture

AEGIS-HYBRID is organized as a multi-layer defensive analytics pipeline. The design separates collection, processing, behavioral analysis, decision/fusion, and SOC presentation so that each stage has a clear responsibility and test boundary.

## Layer 1 — Collection

**Sources:**
- **Suricata IDS** — network telemetry, alerts, protocols, flows, source/destination context.
- **Cowrie Honeypot** — SSH/Telnet login attempts, sessions, commands, and attacker interaction.

**Input:** network activity and honeypot interaction.

**Output:** heterogeneous source logs such as `eve.json` and `cowrie.json`.

## Layer 2 — Processing

### Parsing
Source-specific records are parsed and relevant security fields are extracted.

### Normalization
Different source schemas are converted into a common **Unified Event Schema** so downstream components do not need source-specific logic.

**Why this boundary matters:** raw Suricata and Cowrie records cannot be reliably fused directly because their schemas and semantics differ.

## Layer 3 — Behavioral Analysis

### Sessionization
Related events are grouped into **Behavioral Sessions** using source identity and temporal context.

Example:

```text
Port Scan
   -> SSH Connection
   -> Failed Login
   -> Failed Login
   -> Successful Login
   -> whoami
   -> uname -a
```

These events can represent one connected attacker activity sequence rather than seven independent attacks.

### Feature Engineering
Behavioral sessions are converted into numerical features describing activity volume, timing, burstiness, diversity, transitions, and other security-relevant behavior.

### Machine Learning
The primary classification path uses **XGBoost** to estimate threat probability from session-level features.

## Layer 4 — Decision & Correlation

### Hybrid Fusion Engine
The Fusion Engine combines machine-learning output with behavioral indicators and attack-stage evidence to produce a unified threat assessment.

### Campaign & Timeline Analysis
Related sessions can be correlated into multi-stage attack campaigns and reconstructed as timelines.

### Threat Enrichment
Observed behavior can be mapped to **MITRE ATT&CK** techniques and **Cyber Kill Chain** stages for analyst context.

## SOC Presentation & Response

The analytical results are exposed through the SOC dashboard for monitoring and investigation. A basic IP-blocking capability exists as an experimental response mechanism.

Automated response must remain separated from detection logic and protected by allowlists, validation, cooldowns, audit logging, and rollback mechanisms before being treated as operationally safe.

## Data Flow

```text
Suricata ─┐
          ├─> Parser ─> Normalization ─> Behavioral Sessions
Cowrie ───┘                                  |
                                             v
                                      Feature Engineering
                                             |
                                             v
                                          XGBoost
                                             |
                                             v
                                      Fusion Engine
                                             |
                         ┌───────────────────┼───────────────────┐
                         v                   v                   v
                   Threat Score        Campaigns/Timeline   MITRE Mapping
                         └───────────────────┼───────────────────┘
                                             v
                                       SOC Dashboard
                                             |
                                             v
                                    Analyst / Response
```

## Engineering Classification

| Area | Classification |
|---|---|
| Suricata + Cowrie collection | Core |
| Parsing + normalization | Core |
| Behavioral sessions | Core |
| Feature engineering | Core |
| XGBoost classifier | Core |
| Hybrid Fusion Engine | Core |
| Campaign/timeline analysis | Core |
| MITRE/Cyber Kill Chain enrichment | Core |
| Dashboard | Core |
| Active response | Experimental / hardening required |
| LLM assistance | Experimental |
| Enterprise SaaS features | Future scope |

The architecture documentation describes the implemented research system. Future product capabilities must not be presented as implemented unless their code, tests, and operational documentation exist in this repository.
