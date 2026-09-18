import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

from modules.vulns.xss import XSSScanner, MARKER


def test_extract_params():
    scanner = XSSScanner(http_client=None)
    params = scanner._extract_params("https://target.test/search?q=abc&page=2")
    assert set(params) == {"q", "page"}


def test_extract_params_no_query():
    scanner = XSSScanner(http_client=None)
    assert scanner._extract_params("https://target.test/") == []


def test_inject_payload_replaces_param_value():
    scanner = XSSScanner(http_client=None)
    url = scanner._inject_payload("https://target.test/search?q=abc", "q", "<script>")
    assert "q=" in url
    assert "abc" not in url


def test_check_reflection_direct_match():
    scanner = XSSScanner(http_client=None)
    assert scanner._check_reflection("<script>alert(1)</script>", "<html><script>alert(1)</script></html>")


def test_check_reflection_marker_match():
    scanner = XSSScanner(http_client=None)
    assert scanner._check_reflection("anything", f"<div><{MARKER}></div>")


def test_check_reflection_no_match():
    scanner = XSSScanner(http_client=None)
    assert not scanner._check_reflection("<script>alert(1)</script>", "<html>nothing here</html>")
