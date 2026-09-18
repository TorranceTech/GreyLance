import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

from modules.vulns.tls_audit import classify_cert_expiry

NOW = datetime(2026, 9, 18, tzinfo=timezone.utc)


def test_expired_certificate_is_critical():
    result = classify_cert_expiry(NOW - timedelta(days=5), now=NOW)
    assert result is not None
    severity, message = result
    assert severity == "critical"
    assert "expired" in message.lower()


def test_expiring_within_a_week_is_high():
    result = classify_cert_expiry(NOW + timedelta(days=5), now=NOW)
    assert result is not None
    assert result[0] == "high"


def test_expiring_within_a_month_is_medium():
    result = classify_cert_expiry(NOW + timedelta(days=20), now=NOW)
    assert result is not None
    assert result[0] == "medium"


def test_healthy_certificate_returns_none():
    assert classify_cert_expiry(NOW + timedelta(days=90), now=NOW) is None


def test_boundary_exactly_thirty_days_is_medium_not_none():
    result = classify_cert_expiry(NOW + timedelta(days=30), now=NOW)
    assert result is not None
    assert result[0] == "medium"
