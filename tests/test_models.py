import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

from core.models import (
    Severity, calculate_severity, owasp_category_for,
    Vulnerability, ScanResult,
)


def test_calculate_severity_boundaries():
    assert calculate_severity(9.0) == Severity.CRITICAL
    assert calculate_severity(10.0) == Severity.CRITICAL
    assert calculate_severity(7.0) == Severity.HIGH
    assert calculate_severity(8.9) == Severity.HIGH
    assert calculate_severity(4.0) == Severity.MEDIUM
    assert calculate_severity(6.9) == Severity.MEDIUM
    assert calculate_severity(1.0) == Severity.LOW
    assert calculate_severity(3.9) == Severity.LOW
    assert calculate_severity(0.0) == Severity.INFO
    assert calculate_severity(0.9) == Severity.INFO


def _make_vuln(vuln_type="XSS", cvss=7.2, severity=Severity.HIGH):
    return Vulnerability(
        vuln_type=vuln_type, url="https://target.test", severity=severity,
        cvss_score=cvss, title="t", description="d", evidence="e",
        exploitation="x", remediation="r",
    )


def test_risk_score_empty():
    result = ScanResult(target="https://target.test")
    assert result.risk_score == 0.0


def test_risk_score_weighted():
    result = ScanResult(target="https://target.test")
    result.vulnerabilities = [
        _make_vuln(cvss=10.0, severity=Severity.CRITICAL),
        _make_vuln(cvss=1.0, severity=Severity.LOW),
    ]
    assert 0.0 < result.risk_score <= 10.0
    assert result.vuln_count_by_severity["critical"] == 1
    assert result.vuln_count_by_severity["low"] == 1


def test_owasp_category_known_type():
    assert owasp_category_for("XSS") == "A03:2021 – Injection"
    assert owasp_category_for("SQL Injection") == "A03:2021 – Injection"


def test_owasp_category_unknown_type_falls_back():
    assert owasp_category_for("Something Never Seen") == "A05:2021 – Security Misconfiguration"


def test_owasp_category_nuclei_prefix():
    assert owasp_category_for("Nuclei: CVE-2024-12345") == "A06:2021 – Vulnerable and Outdated Components"


def test_vulnerability_owasp_category_property_and_dict():
    v = _make_vuln(vuln_type="IDOR")
    assert v.owasp_category == "A01:2021 – Broken Access Control"
    assert v.to_dict()["owasp_category"] == "A01:2021 – Broken Access Control"
