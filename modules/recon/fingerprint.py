"""
Technology Fingerprinting
- HTTP headers analysis
- HTML content analysis
- Cookie patterns
- JS library detection
"""

import re
from typing import Optional
import httpx
from rich.console import Console
from core.models import Vulnerability, Severity

console = Console()

# Technology signatures
TECH_SIGNATURES = {
    # Headers
    "headers": {
        "X-Powered-By": {
            r"PHP/(\d+\.\d+)":          "PHP",
            r"ASP\.NET":                 "ASP.NET",
            r"Express":                  "Express.js",
            r"Next\.js":                 "Next.js",
        },
        "Server": {
            r"nginx/([\d.]+)":           "nginx",
            r"Apache/([\d.]+)":          "Apache",
            r"Microsoft-IIS/([\d.]+)":   "IIS",
            r"cloudflare":               "Cloudflare",
            r"LiteSpeed":                "LiteSpeed",
        },
        "X-Generator":       {".*": "Generator"},
        "X-Drupal-Cache":    {".*": "Drupal"},
        "X-WordPress":       {".*": "WordPress"},
    },
    # HTML patterns
    "html": {
        r'<meta name="generator" content="WordPress ([^"]+)"':  "WordPress",
        r'wp-content/':                                          "WordPress",
        r'wp-includes/':                                         "WordPress",
        r'Drupal\.settings':                                     "Drupal",
        r'Joomla!':                                              "Joomla",
        r'data-reactroot':                                       "React",
        r'ng-version="([^"]+)"':                                 "Angular",
        r'__NUXT__':                                             "Nuxt.js",
        r'__next':                                               "Next.js",
        r'vue\.js':                                              "Vue.js",
        r'bootstrap\.min\.css':                                  "Bootstrap",
        r'jquery\.min\.js':                                      "jQuery",
        r'laravel_session':                                      "Laravel",
        r'_rails_session':                                       "Ruby on Rails",
        r'Django':                                               "Django",
        r'FastAPI':                                              "FastAPI",
        r'Swagger UI':                                           "Swagger/OpenAPI",
        r'graphql':                                              "GraphQL",
    },
    # Cookies
    "cookies": {
        r"PHPSESSID":        "PHP",
        r"JSESSIONID":       "Java/Tomcat",
        r"ASP\.NET_SessionId":"ASP.NET",
        r"laravel_session":  "Laravel",
        r"_rails_session":   "Ruby on Rails",
        r"csrftoken":        "Django",
        r"connect\.sid":     "Node.js/Express",
    },
}

# Old/vulnerable versions
VULNERABLE_VERSIONS = {
    "PHP": {
        "< 8.1": "PHP 8.0 and below — EOL, no security updates",
        "5.x":   "PHP 5.x — critical security issues (CVE-2019-11043 etc.)",
    },
    "Apache": {
        "< 2.4.51": "Apache Path Traversal (CVE-2021-41773/CVE-2021-42013)",
    },
    "nginx": {
        "< 1.20": "nginx old version — buffer overflow issues",
    },
}


class TechFingerprinter:
    def __init__(self, http_client):
        self.http_client = http_client

    def _check_headers(self, headers: dict) -> list[str]:
        techs = []
        for header, patterns in TECH_SIGNATURES["headers"].items():
            value = headers.get(header, "")
            if not value:
                # Check case-insensitively
                value = next((v for k, v in headers.items()
                               if k.lower() == header.lower()), "")
            if value:
                for pattern, tech in patterns.items():
                    match = re.search(pattern, value, re.IGNORECASE)
                    if match:
                        version = match.group(1) if match.lastindex else ""
                        techs.append(f"{tech}{' ' + version if version else ''}")
        return techs

    def _check_html(self, html: str) -> list[str]:
        techs = []
        for pattern, tech in TECH_SIGNATURES["html"].items():
            if re.search(pattern, html, re.IGNORECASE):
                if tech not in techs:
                    techs.append(tech)
        return techs

    def _check_cookies(self, cookies) -> list[str]:
        techs = []
        cookie_str = str(cookies)
        for pattern, tech in TECH_SIGNATURES["cookies"].items():
            if re.search(pattern, cookie_str, re.IGNORECASE):
                if tech not in techs:
                    techs.append(tech)
        return techs

    def _check_security_headers(self, headers: dict, url: str) -> list[Vulnerability]:
        """Check for missing security headers"""
        vulns = []
        headers_lower = {k.lower(): v for k, v in headers.items()}

        security_headers = {
            "strict-transport-security": {
                "title": "Missing HSTS Header",
                "desc": "Strict-Transport-Security header missing. Vulnerable to MITM attacks.",
                "cvss": 4.3,
                "remediation": "Add header: Strict-Transport-Security: max-age=31536000; includeSubDomains",
            },
            "x-frame-options": {
                "title": "Missing X-Frame-Options",
                "desc": "No protection against clickjacking attacks.",
                "cvss": 4.3,
                "remediation": "Add header: X-Frame-Options: DENY",
            },
            "x-content-type-options": {
                "title": "Missing X-Content-Type-Options",
                "desc": "Vulnerable to MIME sniffing attacks.",
                "cvss": 3.7,
                "remediation": "Add header: X-Content-Type-Options: nosniff",
            },
            "content-security-policy": {
                "title": "Missing Content-Security-Policy",
                "desc": "No CSP. No additional protection against XSS attacks.",
                "cvss": 4.3,
                "remediation": "Add CSP header: Content-Security-Policy: default-src 'self'",
            },
            "permissions-policy": {
                "title": "Missing Permissions-Policy",
                "desc": "Browser feature policy not set.",
                "cvss": 2.0,
                "remediation": "Add Permissions-Policy header",
            },
            "referrer-policy": {
                "title": "Missing Referrer-Policy",
                "desc": "No Referrer-Policy header. The full URL (including sensitive query "
                        "parameters) may leak to third parties via the Referer header.",
                "cvss": 2.0,
                "remediation": "Add header: Referrer-Policy: strict-origin-when-cross-origin",
            },
        }

        for header, info in security_headers.items():
            if header not in headers_lower:
                vuln = Vulnerability(
                    vuln_type="Missing Security Header",
                    url=url,
                    severity=Severity.LOW if info["cvss"] < 4 else Severity.MEDIUM,
                    cvss_score=info["cvss"],
                    title=info["title"],
                    description=info["desc"],
                    evidence=f"Header '{header}' not in response",
                    exploitation=(
                        f"Attacker can exploit the missing header. "
                        f"For example, without X-Frame-Options: "
                        f"clickjacking via <iframe src='{url}'></iframe>."
                    ),
                    remediation=info["remediation"],
                    cwe_id="CWE-693",
                )
                vulns.append(vuln)

        # Server version disclosure
        server = headers_lower.get("server", "")
        if server and re.search(r"\d+\.\d+", server):
            vulns.append(Vulnerability(
                vuln_type="Information Disclosure",
                url=url,
                severity=Severity.INFO,
                cvss_score=2.0,
                title="Server Version Disclosure",
                description=f"Server header reveals version info: {server}",
                evidence=f"Server: {server}",
                exploitation="Version info can be used for targeted exploitation.",
                remediation="Hide server header: use 'server_tokens off;' in nginx",
                cwe_id="CWE-200",
            ))

        return vulns

    def _check_cookie_flags(self, set_cookie_headers: list[str], url: str) -> list[Vulnerability]:
        """Check Set-Cookie headers for missing Secure/HttpOnly/SameSite attributes"""
        vulns = []
        if not set_cookie_headers:
            return vulns

        missing_secure = any("secure" not in c.lower() for c in set_cookie_headers)
        missing_httponly = any("httponly" not in c.lower() for c in set_cookie_headers)
        missing_samesite = any("samesite" not in c.lower() for c in set_cookie_headers)

        if missing_secure and url.lower().startswith("https"):
            vulns.append(Vulnerability(
                vuln_type="Missing Security Header",
                url=url,
                severity=Severity.MEDIUM,
                cvss_score=4.3,
                title="Cookie Missing Secure Flag",
                description="One or more Set-Cookie headers are missing the Secure attribute, "
                            "so the cookie may be sent over unencrypted HTTP.",
                evidence="Set-Cookie header(s) without 'Secure' attribute",
                exploitation="A network attacker (e.g. on public Wi-Fi) can intercept the cookie if the browser ever sends it over plain HTTP.",
                remediation="Set the Secure attribute on all session/auth cookies.",
                cwe_id="CWE-614",
            ))
        if missing_httponly:
            vulns.append(Vulnerability(
                vuln_type="Missing Security Header",
                url=url,
                severity=Severity.MEDIUM,
                cvss_score=4.3,
                title="Cookie Missing HttpOnly Flag",
                description="One or more Set-Cookie headers are missing the HttpOnly attribute, "
                            "so client-side JavaScript can read the cookie.",
                evidence="Set-Cookie header(s) without 'HttpOnly' attribute",
                exploitation="An XSS vulnerability elsewhere on the site can be used to steal this cookie via document.cookie.",
                remediation="Set the HttpOnly attribute on all session/auth cookies.",
                cwe_id="CWE-1004",
            ))
        if missing_samesite:
            vulns.append(Vulnerability(
                vuln_type="Missing Security Header",
                url=url,
                severity=Severity.MEDIUM,
                cvss_score=4.3,
                title="Cookie Missing SameSite Attribute",
                description="One or more Set-Cookie headers are missing the SameSite attribute, "
                            "weakening CSRF defenses.",
                evidence="Set-Cookie header(s) without 'SameSite' attribute",
                exploitation="Cookies are sent on cross-site requests, which can enable CSRF attacks against authenticated endpoints.",
                remediation="Set SameSite=Lax (or Strict where possible) on all session/auth cookies.",
                cwe_id="CWE-352",
            ))
        return vulns

    async def fingerprint(self, url: str) -> tuple[list[str], list[Vulnerability]]:
        """Fingerprint the URL, return technologies and header vulnerabilities"""
        response = await self.http_client.get(url)
        if not response:
            return [], []

        techs = []
        techs.extend(self._check_headers(dict(response.headers)))
        techs.extend(self._check_html(response.text[:50000]))
        techs.extend(self._check_cookies(response.cookies))
        techs = list(set(techs))

        vulns = self._check_security_headers(dict(response.headers), url)
        vulns.extend(self._check_cookie_flags(response.headers.get_list("set-cookie"), url))

        if techs:
            console.print(f"  [bold]Technologies:[/bold] {', '.join(techs)}")

        return techs, vulns
