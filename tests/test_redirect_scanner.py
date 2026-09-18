import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

from modules.vulns.redirect import RedirectScanner


def test_is_redirect_param_matches_known_hints():
    scanner = RedirectScanner(http_client=None)
    assert scanner._is_redirect_param("redirect_url")
    assert scanner._is_redirect_param("next")
    assert scanner._is_redirect_param("RETURNURL")


def test_is_redirect_param_rejects_unrelated_names():
    scanner = RedirectScanner(http_client=None)
    assert not scanner._is_redirect_param("username")
    assert not scanner._is_redirect_param("page")


def test_inject_replaces_param_value():
    scanner = RedirectScanner(http_client=None)
    url = scanner._inject("https://target.test/go?next=/home", "next", "https://evil.com")
    assert "evil.com" in url
    assert "/home" not in url
