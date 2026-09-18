from typing import Optional
"""
Endpoint & Directory Discovery
- Wordlist-based bruteforce
- Common API endpoint detection
- Backup file discovery
"""

import asyncio
from urllib.parse import urljoin
from rich.console import Console
from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn
from core.models import Vulnerability, Severity

console = Console()

COMMON_PATHS = [
    # Admin panels
    "admin", "admin/", "administrator", "admin/login",
    "admin/dashboard", "wp-admin", "panel", "cpanel",
    "dashboard", "manage", "management", "backend",
    # API endpoints
    "api", "api/v1", "api/v2", "api/v3", "api/users",
    "api/admin", "api/config", "api/debug", "api/health",
    "api/status", "api/info", "api/docs", "api/swagger",
    "graphql", "graphiql", "api/graphql",
    "rest", "rest/v1", "rest/api",
    # Auth endpoints
    "login", "signin", "signup", "register", "logout",
    "auth", "auth/login", "oauth", "oauth/token",
    "forgot-password", "reset-password", "verify",
    # Debug & dev
    "debug", "test", "dev", "development", "staging",
    "phpinfo.php", "info.php", "test.php",
    "console", "shell", "terminal",
    # Config & sensitive
    ".env", ".env.local", "config", "config.php",
    "configuration", "settings", "setup",
    ".git/HEAD", ".git/config",
    "backup", "backup.zip", "backup.sql",
    # Health & metrics
    "health", "healthz", "ping", "status",
    "metrics", "actuator", "actuator/env",
    "actuator/health", "actuator/info",
    "actuator/mappings", "actuator/beans",
    # Common files
    "robots.txt", "sitemap.xml", "crossdomain.xml",
    "security.txt", ".well-known/security.txt",
    "humans.txt", "ads.txt",
    # Package & build
    "package.json", "composer.json", "Dockerfile",
    "docker-compose.yml", ".travis.yml",
    # Upload dirs
    "uploads", "upload", "files", "media",
    "images", "assets", "static",
]

# Spring Boot actuator endpoints — ayrıca siyahı
ACTUATOR_PATHS = [
    "actuator", "actuator/env", "actuator/health",
    "actuator/info", "actuator/mappings", "actuator/beans",
    "actuator/configprops", "actuator/logfile",
    "actuator/heapdump", "actuator/threaddump",
]

# Interesting status codes
INTERESTING_CODES = [200, 201, 204, 301, 302, 401, 403]


class DiscoveryScanner:
    def __init__(self, http_client, extra_wordlist: list[str] = None):
        self.http_client = http_client
        self.wordlist = COMMON_PATHS + (extra_wordlist or [])

    async def _check_path(self, base_url: str, path: str) -> Optional[dict ]:
        url = urljoin(base_url.rstrip("/") + "/", path.lstrip("/"))
        response = await self.http_client.get(url)
        if not response:
            return None

        if response.status_code not in INTERESTING_CODES:
            return None

        return {
            "url": url,
            "path": path,
            "status": response.status_code,
            "size": len(response.content),
            "content_type": response.headers.get("content-type", ""),
        }

    def _analyze_findings(self, findings: list[dict], base_url: str) -> list[Vulnerability]:
        """Tapılan endpoint-ləri analiz et, vuln yarat"""
        vulns = []

        for f in findings:
            path = f["path"].lower()
            status = f["status"]
            url = f["url"]

            # Admin panel is open
            if any(p in path for p in ["admin", "dashboard", "panel", "cpanel"]):
                if status == 200:
                    vulns.append(Vulnerability(
                        vuln_type="Exposed Admin Panel",
                        url=url,
                        severity=Severity.HIGH,
                        cvss_score=7.5,
                        title=f"Admin Panel Exposed — /{f['path']}",
                        description=(
                            f"Admin panel ({url}) is publicly accessible. "
                            f"Vulnerable to brute force, credential stuffing attacks.",
                        ),
                        evidence=f"HTTP {status}, Size: {f['size']} bytes",
                        exploitation=(
                            f"Hydra ilə brute force:\n"
                            f"hydra -l admin -P /usr/share/wordlists/rockyou.txt "
                            f"{base_url} http-post-form "
                            f"'/admin/login:user=^USER^&pass=^PASS^:Invalid'"
                        ),
                        remediation=(
                            "1. Protect admin panel with IP whitelist\n"
                            "2. Enable 2FA\n"
                            "3. Change default URL\n"
                            "4. Add rate limiting"
                        ),
                        cwe_id="CWE-284",
                    ))

            # Spring Boot Actuator
            if "actuator" in path and status in [200, 204]:
                severity = Severity.CRITICAL if "heapdump" in path or "env" in path else Severity.HIGH
                cvss = 9.1 if severity == Severity.CRITICAL else 7.5
                vulns.append(Vulnerability(
                    vuln_type="Information Disclosure",
                    url=url,
                    severity=severity,
                    cvss_score=cvss,
                    title=f"Spring Boot Actuator Exposed — /{f['path']}",
                    description=(
                        f"Spring Boot Actuator endpoint ({f['path']}) is publicly accessible. "
                        f"Risk of leaking environment variables, heap dump, credentials."
                    ),
                    evidence=f"HTTP {status}",
                    exploitation=(
                        f"Get environment variables:\n"
                        f"curl {base_url}/actuator/env | python3 -m json.tool\n\n"
                        f"Download heap dump (may contain credentials):\n"
                        f"curl {base_url}/actuator/heapdump -o heap.bin\n"
                        f"strings heap.bin | grep -i 'password\\|secret\\|key'"
                    ),
                    remediation=(
                        "1. Disable Actuator in production\n"
                        "2. management.endpoints.web.exposure.include=health,info\n"
                        "3. Protect actuator with Spring Security"
                    ),
                    cwe_id="CWE-215",
                ))

            # GraphQL
            if "graphql" in path and status == 200:
                vulns.append(Vulnerability(
                    vuln_type="Information Disclosure",
                    url=url,
                    severity=Severity.MEDIUM,
                    cvss_score=5.3,
                    title="GraphQL Endpoint Exposed",
                    description=(
                        "GraphQL endpoint found. Introspection may be enabled — "
                        "entire schema, types, and mutations may be visible."
                    ),
                    evidence=f"HTTP {status} — {url}",
                    exploitation=(
                        "Introspection query:\n"
                        "curl -X POST -H 'Content-Type: application/json' \\\n"
                        f"  -d '{{\"query\":\"{{__schema{{types{{name}}}}}}\"}}' \\\n"
                        f"  {url}\n\n"
                        "Visualize schema with GraphQL Voyager:\n"
                        "https://github.com/graphql-kit/graphql-voyager"
                    ),
                    remediation=(
                        "1. Disable introspection in production\n"
                        "2. Apply query depth limit\n"
                        "3. Add rate limiting\n"
                        "4. Require authentication"
                    ),
                    cwe_id="CWE-200",
                ))

            # 403 Forbidden — potensial bypass
            if status == 403:
                vulns.append(Vulnerability(
                    vuln_type="Access Control",
                    url=url,
                    severity=Severity.LOW,
                    cvss_score=3.7,
                    title=f"403 Forbidden — Bypass may be possible — /{f['path']}",
                    description=(
                        f"/{f['path']} endpoint returns 403. "
                        f"Bypass may be possible via header manipulation."
                    ),
                    evidence=f"HTTP 403",
                    exploitation=(
                        f"Header bypass attempts:\n"
                        f"curl -H 'X-Original-URL: /{f['path']}' {base_url}/\n"
                        f"curl -H 'X-Rewrite-URL: /{f['path']}' {base_url}/\n"
                        f"curl -H 'X-Custom-IP-Authorization: 127.0.0.1' {url}\n"
                        f"curl -H 'X-Forwarded-For: 127.0.0.1' {url}\n\n"
                        f"Path traversal attempts:\n"
                        f"curl {base_url}//{f['path']}\n"
                        f"curl {base_url}/{f['path']}/.."
                    ),
                    remediation=(
                        "1. Do not trust proxy headers\n"
                        "2. Apply server-side authorization checks\n"
                        "3. Ignore headers like X-Original-URL"
                    ),
                    cwe_id="CWE-284",
                ))

        return vulns

    async def scan(self, base_url: str) -> tuple[list[str], list[Vulnerability]]:
        """
        Returns: (discovered_endpoints, vulnerabilities)
        """
        console.print(f"\n[bold cyan]🗂  Endpoint Discovery:[/bold cyan] {len(self.wordlist)} path")

        semaphore = asyncio.Semaphore(30)

        async def check_with_sem(path):
            async with semaphore:
                return await self._check_path(base_url, path)

        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            BarColumn(),
            console=console,
        ) as progress:
            task = progress.add_task("[cyan]Path scan...[/cyan]", total=len(self.wordlist))

            async def tracked(path):
                result = await check_with_sem(path)
                progress.advance(task)
                return result

            results = await asyncio.gather(
                *[tracked(p) for p in self.wordlist],
                return_exceptions=True
            )

        findings = [r for r in results if isinstance(r, dict)]
        endpoints = [f["url"] for f in findings]

        for f in findings:
            status_color = {200: "green", 403: "yellow", 401: "yellow"}.get(f["status"], "blue")
            console.print(
                f"  [{status_color}]{f['status']}[/{status_color}] "
                f"/{f['path']} "
                f"[dim]({f['size']} bytes)[/dim]"
            )

        vulns = self._analyze_findings(findings, base_url)
        console.print(f"[bold green]  Discovery complete: {len(endpoints)} endpoints found[/bold green]")

        return endpoints, vulns