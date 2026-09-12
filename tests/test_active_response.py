"""
Verifies the three safety gates in core/active_response.py actually
gate execution — these are the tests that matter most given this
module can trigger a real iptables command.
"""

import core.active_response as ar


def test_disabled_by_default_blocks_nothing(monkeypatch):
    monkeypatch.setattr(ar.settings, "ENABLE_ACTIVE_RESPONSE", False)
    result = ar.request_block("192.168.139.50", "CRITICAL")
    assert result == "disabled"


def test_enabled_but_ip_outside_allowlist_is_refused(monkeypatch):
    monkeypatch.setattr(ar.settings, "ENABLE_ACTIVE_RESPONSE", True)
    monkeypatch.setattr(ar.settings, "ACTIVE_RESPONSE_ALLOWED_CIDRS", ["10.0.0.0/8"])
    monkeypatch.setattr(ar.settings, "ACTIVE_RESPONSE_DRY_RUN", True)
    result = ar.request_block("192.168.139.50", "CRITICAL")
    assert result == "not_in_allowlist"


def test_invalid_ip_is_rejected(monkeypatch):
    monkeypatch.setattr(ar.settings, "ENABLE_ACTIVE_RESPONSE", True)
    monkeypatch.setattr(ar.settings, "ACTIVE_RESPONSE_ALLOWED_CIDRS", ["192.168.139.0/24"])
    result = ar.request_block("not-an-ip", "CRITICAL")
    assert result == "invalid_ip"


def test_enabled_in_allowlist_dry_run_does_not_execute(monkeypatch):
    monkeypatch.setattr(ar.settings, "ENABLE_ACTIVE_RESPONSE", True)
    monkeypatch.setattr(ar.settings, "ACTIVE_RESPONSE_ALLOWED_CIDRS", ["192.168.139.0/24"])
    monkeypatch.setattr(ar.settings, "ACTIVE_RESPONSE_DRY_RUN", True)

    executed = {"called": False}
    monkeypatch.setattr(ar, "_execute_block", lambda ip: executed.__setitem__("called", True))

    result = ar.request_block("192.168.139.77", "CRITICAL")
    assert result == "dry_run"
    assert executed["called"] is False


def test_execution_failure_returns_execution_failed_and_does_not_record_ip(monkeypatch):
    """Core of the correctness fix: if the (mocked) iptables call fails,
    request_block must report failure and MUST NOT have added the IP
    to the blocked set. _execute_block itself is monkeypatched out, so
    no real subprocess/iptables call happens here."""
    monkeypatch.setattr(ar.settings, "ENABLE_ACTIVE_RESPONSE", True)
    monkeypatch.setattr(ar.settings, "ACTIVE_RESPONSE_ALLOWED_CIDRS", ["192.168.139.0/24"])
    monkeypatch.setattr(ar.settings, "ACTIVE_RESPONSE_DRY_RUN", False)
    monkeypatch.setattr(ar, "_execute_block", lambda ip: False)

    target_ip = "192.168.139.201"
    result = ar.request_block(target_ip, "CRITICAL")

    assert result == "execution_failed"
    assert target_ip not in ar.blocked_ips()


def test_execution_success_returns_executed_and_records_ip(monkeypatch):
    """Symmetric case: only a confirmed-successful (mocked) execution
    results in "executed" and the IP being recorded. No real
    subprocess/iptables call happens here either."""
    monkeypatch.setattr(ar.settings, "ENABLE_ACTIVE_RESPONSE", True)
    monkeypatch.setattr(ar.settings, "ACTIVE_RESPONSE_ALLOWED_CIDRS", ["192.168.139.0/24"])
    monkeypatch.setattr(ar.settings, "ACTIVE_RESPONSE_DRY_RUN", False)
    monkeypatch.setattr(ar, "_execute_block", lambda ip: True)

    target_ip = "192.168.139.202"
    result = ar.request_block(target_ip, "CRITICAL")

    assert result == "executed"
    assert target_ip in ar.blocked_ips()


def test_severity_below_threshold_is_ignored(monkeypatch):
    monkeypatch.setattr(ar.settings, "ENABLE_ACTIVE_RESPONSE", True)
    monkeypatch.setattr(ar.settings, "ACTIVE_RESPONSE_ALLOWED_CIDRS", ["192.168.139.0/24"])
    result = ar.request_block("192.168.139.77", "MEDIUM")
    assert result == "severity_below_threshold"
