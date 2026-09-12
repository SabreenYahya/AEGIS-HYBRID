from core.event_schema import normalize_ip, UnifiedEvent
from datetime import datetime, timezone


def test_normalize_ip_valid():
    assert normalize_ip("192.168.1.10") == "192.168.1.10"


def test_normalize_ip_invalid_returns_default():
    assert normalize_ip("not-an-ip") == "0.0.0.0"


def test_normalize_ip_empty_returns_default():
    assert normalize_ip("") == "0.0.0.0"
    assert normalize_ip(None) == "0.0.0.0"


def test_session_key_excludes_port():
    e1 = UnifiedEvent(
        timestamp=datetime.now(timezone.utc), src_ip="10.0.0.1", dest_ip="10.0.0.2",
        dest_port=22, protocol="TCP", event_type="cowrie", stage="ACCESS",
        severity=5, signature="login",
    )
    e2 = UnifiedEvent(
        timestamp=datetime.now(timezone.utc), src_ip="10.0.0.1", dest_ip="10.0.0.2",
        dest_port=9999, protocol="TCP", event_type="cowrie", stage="ACCESS",
        severity=5, signature="login",
    )
    # Same key despite different ports — this is intentional, see
    # core/event_schema.py's docstring on get_session_key.
    assert e1.get_session_key() == e2.get_session_key()
