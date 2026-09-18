import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

from modules.recon.fingerprint import TechFingerprinter

GOOD_HEADERS = {
    "Strict-Transport-Security": "max-age=31536000; includeSubDomains",
    "X-Frame-Options": "DENY",
    "X-Content-Type-Options": "nosniff",
    "Content-Security-Policy": "default-src 'self'",
    "Permissions-Policy": "geolocation=()",
    "Referrer-Policy": "strict-origin-when-cross-origin",
}


def test_missing_headers_flagged_on_empty_response():
    fp = TechFingerprinter(http_client=None)
    vulns = fp._check_security_headers({}, "https://target.test")
    titles = {v.title for v in vulns}
    assert "Missing HSTS Header" in titles
    assert "Missing X-Frame-Options" in titles
    assert "Missing Content-Security-Policy" in titles
    assert "Missing Referrer-Policy" in titles
    assert len(vulns) == 6  # 6 tracked security headers, all missing; no Server header to flag


def test_no_findings_when_all_headers_present_and_no_version_leak():
    fp = TechFingerprinter(http_client=None)
    vulns = fp._check_security_headers(GOOD_HEADERS, "https://target.test")
    assert vulns == []


def test_server_version_disclosure_flagged():
    fp = TechFingerprinter(http_client=None)
    headers = dict(GOOD_HEADERS)
    headers["Server"] = "nginx/1.18.0"
    vulns = fp._check_security_headers(headers, "https://target.test")
    assert any(v.title == "Server Version Disclosure" for v in vulns)


def test_cookie_flags_all_missing():
    fp = TechFingerprinter(http_client=None)
    vulns = fp._check_cookie_flags(["session=abc123"], "https://target.test")
    titles = {v.title for v in vulns}
    assert titles == {
        "Cookie Missing Secure Flag",
        "Cookie Missing HttpOnly Flag",
        "Cookie Missing SameSite Attribute",
    }


def test_cookie_flags_all_present():
    fp = TechFingerprinter(http_client=None)
    vulns = fp._check_cookie_flags(
        ["session=abc123; Secure; HttpOnly; SameSite=Lax"], "https://target.test"
    )
    assert vulns == []


def test_cookie_flags_no_cookies_no_findings():
    fp = TechFingerprinter(http_client=None)
    assert fp._check_cookie_flags([], "https://target.test") == []
