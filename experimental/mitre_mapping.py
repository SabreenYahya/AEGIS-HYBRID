"""
Keyword-based MITRE ATT&CK tactic/technique lookup.

Not wired into pipeline/offline_pipeline.py — see experimental/README.md.
This is a rule-based lookup table, not a learned or verified mapping;
treat its output as a suggestion for a human analyst, not a confirmed
technique attribution.
"""

from collections import defaultdict


def map_to_mitre(alerts: list) -> list:
    mapping = []

    for alert in alerts:
        signature = alert.get("signature", "").lower()
        stage = alert.get("stage", "UNKNOWN")
        risk = alert.get("risk_score", 0)

        if "scan" in signature or "nmap" in signature or stage == "RECON":
            mapping.append({
                "tactic": "Reconnaissance", "tactic_id": "TA0043",
                "technique": "Active Scanning", "technique_id": "T1595", "risk": risk,
            })
        elif "ssh" in signature or "brute" in signature or stage == "BRUTE":
            mapping.append({
                "tactic": "Credential Access", "tactic_id": "TA0006",
                "technique": "Brute Force", "technique_id": "T1110", "risk": risk,
            })
        elif "exploit" in signature or stage == "EXPLOIT":
            mapping.append({
                "tactic": "Execution", "tactic_id": "TA0002",
                "technique": "Exploitation of Remote Services", "technique_id": "T1210", "risk": risk,
            })
        elif "flood" in signature or "dos" in signature:
            mapping.append({
                "tactic": "Impact", "tactic_id": "TA0040",
                "technique": "Network Denial of Service", "technique_id": "T1498", "risk": risk,
            })
        elif stage == "LATERAL" or "pivot" in signature:
            mapping.append({
                "tactic": "Lateral Movement", "tactic_id": "TA0008",
                "technique": "Remote Services", "technique_id": "T1021", "risk": risk,
            })
        elif risk > 70:
            mapping.append({
                "tactic": "Unknown (possible novel behavior)", "tactic_id": "N/A",
                "technique": "Behavioral anomaly, unattributed", "technique_id": "N/A", "risk": risk,
            })
        else:
            mapping.append({
                "tactic": "Unknown", "tactic_id": "N/A",
                "technique": "Low-confidence event", "technique_id": "N/A", "risk": risk,
            })

    return [dict(t) for t in {tuple(d.items()) for d in mapping}]


def summarize_mitre(mapping: list) -> dict:
    summary = defaultdict(int)
    for m in mapping:
        summary[m.get("tactic", "Unknown")] += 1
    return dict(summary)
