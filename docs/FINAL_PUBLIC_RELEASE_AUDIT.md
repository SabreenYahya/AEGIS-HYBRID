# Final Public Release Audit

This file did not exist before this entry. It consolidates the three
audit rounds actually performed on this repository, in order, with no
assumed prior history.

## Round 1 — Restructuring (security + dead-code removal)

- Rebuilt from the original prototype into `core/` / `ml/` /
  `ingestion/` / `pipeline/` / `evaluation/` / `experimental/`.
- Hardened `ingestion/ingest_api.py` (API key auth, bounded dedup
  cache, per-IP rate limiting, no `0.0.0.0` bind by default).
- Made `core/active_response.py` disabled-by-default with a CIDR
  allowlist and dry-run default.
- Removed dead/misleading code and stale outputs — full list and
  rationale in `MIGRATION_NOTES.md`.
- Removed the undocumented `soft_recall_boost()` from evaluation.

## Round 2 — Verification of Round 1

Read-only verification (no training/evaluation run):

- Confirmed `MIGRATION_NOTES.md` wording changes were applied exactly
  as specified (dropped the "byte-for-byte" claim; corrected the
  claim about the four removed legacy modules being "preserved in
  local git history").
- Confirmed `docs/PROJECT_STATUS.md` carries an explicit warning
  separating the thesis/presentation metrics from this repository's
  (not-yet-generated) results.
- Confirmed the four removed modules (`siem_correlation.py`,
  `alerting.py`, `threat_scoring.py`, `classifier_v2.py`) have zero
  references anywhere except the documentation explaining their
  removal.
- Confirmed no stale `_v2`/`_v3`/`analysis.*`/`visualization/`
  references exist in actual code (only in migration-log prose).
- Confirmed all 19 internal modules import successfully at runtime
  (18/19 in the audit sandbox; the 1 failure was `xgboost` being
  absent from that sandbox specifically, not a code defect —
  `xgboost==2.0.3` is correctly pinned in `requirements.txt` and the
  file passes `py_compile`).
- Confirmed every `python -m ...` command referenced in `README.md`
  and `docs/PROJECT_STATUS.md` matches a real file with a
  `__main__` entry point.
- Confirmed all 15 environment variables read in `config/settings.py`
  are documented in `.env.example`.
- **Open item at end of Round 2:** no `.git` repository exists yet in
  the working copy, so no real `git diff`/`git status` could be
  produced — only direct text comparison of the two edited files.
- **Open item at end of Round 2 (unresolved by design — training/
  evaluation was explicitly out of scope):** metrics reproducibility.
  See the warning in `docs/PROJECT_STATUS.md` — this remains gated
  and is intentionally **not** resolved by this audit entry.

## Round 3 — Active Response correctness fix

**Problem:** `request_block()` added the IP to `_BLOCKED_IPS` before
confirming the `iptables` command had actually succeeded;
`_execute_block()` used `subprocess.run(..., check=False)` and
returned nothing, so failure was indistinguishable from success.

**Fix (file changed: `core/active_response.py` only):**
- `_execute_block(ip)` now returns `bool`, `True` only if the
  `iptables` process exited with status `0`.
- `request_block()` no longer adds the IP to `_BLOCKED_IPS` until
  `_execute_block()` has confirmed success.
- A failed execution now returns `"execution_failed"` and leaves
  `blocked_ips()` unchanged.
- `"executed"` is returned only after confirmed success.
- Unchanged: disabled-by-default behavior, dry-run behavior, CIDR
  allowlist, IP validation, cooldown logic, the iptables command
  itself, and the overall three-gate safety model.

**Test changed:** `tests/test_active_response.py` — added
`test_execution_failure_returns_execution_failed_and_does_not_record_ip`
and `test_execution_success_returns_executed_and_records_ip`, both
via monkeypatching `_execute_block` directly (no real `subprocess`/
`iptables` invocation in either test).

**Test run (lightweight suite only — no training, no evaluation):**
`tests/test_event_schema.py`, `tests/test_parser.py`,
`tests/test_fusion_engine.py`, `tests/test_active_response.py`
→ **23/23 passed**, 0 failed.

**Confirmed:** no real `iptables`/`sudo` command was executed during
this fix or its tests — every test that reaches the execution branch
mocks `_execute_block` itself, so the real function containing the
`subprocess.run(["sudo", "-n", "iptables", ...])` call was never
invoked.

## Final verdict

🟢 **READY FOR PUBLIC RELEASE** — scoped to code correctness,
security posture, and internal consistency, which is what Rounds 1–3
actually audited.

This verdict does **not** override the separate, still-open
metrics-publication gate documented at the top of
`docs/PROJECT_STATUS.md`. That gate governs what performance numbers
may be *claimed* about this repository (none have been generated
here yet); it is not a code defect and does not block publishing the
code itself. Do not remove that warning box when reading this verdict
as "green."
