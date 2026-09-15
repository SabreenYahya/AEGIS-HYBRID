# Limitations

AEGIS-HYBRID is intentionally documented with its boundaries visible.

## Detection limitations

- Sessionization is source-specific; there is no completed cross-source attacker session.
- Behavioral fusion weights are manually chosen and not independently validated.
- Heuristic APT/campaign outputs do not establish attribution or confirm an APT.
- The system is batch/offline rather than a live detector.

## Dataset limitations

- Labels are derived from telemetry-source/alert heuristics rather than verified ground truth.
- Source identity can become a shortcut feature.
- Random splits can overestimate generalization when related activity is present across splits.

## Operational limitations

- The optional response mechanism is lab-oriented and has no automatic rollback.
- No production HA, access-control model, multi-tenant isolation, or operational monitoring is provided.
- The repository does not include a dashboard.

## Research interpretation

A high score is evidence that the configured model and heuristic layer consider a session suspicious under the current feature and threshold definitions. It is not proof of compromise, attribution, or adversary identity.
