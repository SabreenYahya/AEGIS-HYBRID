from core.parser import calculate_severity, is_noise_ip, map_behavior, parse_timestamp


def test_parse_timestamp_valid_iso():
    ts = parse_timestamp("2026-06-14T14:09:57.925725+00:00")
    assert ts is not None
    assert ts.year == 2026


def test_parse_timestamp_invalid_returns_none():
    assert parse_timestamp("not-a-date") is None
    assert parse_timestamp(None) is None


def test_is_noise_ip_filters_loopback_and_link_local():
    assert is_noise_ip("127.0.0.1") is True
    assert is_noise_ip("169.254.1.1") is True
    assert is_noise_ip("192.168.1.1") is False


def test_map_behavior_scan_keyword():
    assert map_behavior("alert", "Possible Nmap Scan Detected") == "SCAN"


def test_map_behavior_access_keyword():
    assert map_behavior("cowrie", "cowrie.login.failed") != "SCAN"
    assert map_behavior("alert", "SSH brute force attempt") == "ACCESS"


def test_map_behavior_unknown_fallback():
    assert map_behavior("alert", "totally unrecognized signature text") == "UNKNOWN"


def test_calculate_severity_within_bounds():
    for stage in ("RECON", "SCAN", "ACCESS", "EXPLOIT", "PERSISTENCE", "EXFILTRATION", "UNKNOWN"):
        sev = calculate_severity(stage, "generic signature")
        assert 1 <= sev <= 10


def test_calculate_severity_critical_keyword_boost():
    base = calculate_severity("ACCESS", "generic signature")
    boosted = calculate_severity("ACCESS", "meterpreter reverse tcp shell")
    assert boosted >= base
