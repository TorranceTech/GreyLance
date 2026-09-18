"""
TLS/SSL certificate and protocol auditing
- Weak protocol negotiation (SSLv2/3, TLSv1.0/1.1)
- Certificate expiry / self-signed detection
"""

import asyncio
import socket
import ssl
from datetime import datetime, timezone
from typing import Optional
from urllib.parse import urlparse
from rich.console import Console
from core.models import Vulnerability, Severity

console = Console()

WEAK_PROTOCOLS = {"TLSv1", "TLSv1.1", "SSLv2", "SSLv3"}


def classify_cert_expiry(not_after: datetime, now: Optional[datetime] = None) -> Optional[tuple[str, str]]:
    """Pure function (no I/O) so it's unit-testable: returns (severity, message) or None if healthy."""
    now = now or datetime.now(timezone.utc)
    days_left = (not_after - now).days
    if days_left < 0:
        return ("critical", f"Certificate expired {-days_left} day(s) ago ({not_after.date()}).")
    if days_left <= 7:
        return ("high", f"Certificate expires in {days_left} day(s) ({not_after.date()}).")
    if days_left <= 30:
        return ("medium", f"Certificate expires in {days_left} day(s) ({not_after.date()}).")
    return None


class TLSAuditor:
    def __init__(self, http_client=None):
        self.http_client = http_client

    def _negotiated_protocol(self, host: str, port: int, timeout: float) -> tuple[str, tuple]:
        """Connect without verifying the cert — we only care about the negotiated protocol/cipher here."""
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        with socket.create_connection((host, port), timeout=timeout) as sock:
            with ctx.wrap_socket(sock, server_hostname=host) as ssock:
                return ssock.version(), ssock.cipher()

    def _cert_info(self, host: str, port: int, timeout: float) -> dict:
        """Connect with default (verifying) context to get the parsed certificate dict."""
        ctx = ssl.create_default_context()
        with socket.create_connection((host, port), timeout=timeout) as sock:
            with ctx.wrap_socket(sock, server_hostname=host) as ssock:
                return ssock.getpeercert()

    async def scan(self, base_url: str) -> list[Vulnerability]:
        parsed = urlparse(base_url)
        if parsed.scheme != "https":
            return []
        host = parsed.hostname
        port = parsed.port or 443
        if not host:
            return []

        vulns = []

        try:
            protocol, cipher = await asyncio.to_thread(self._negotiated_protocol, host, port, 8.0)
            if protocol in WEAK_PROTOCOLS:
                vulns.append(Vulnerability(
                    vuln_type="TLS/SSL Misconfiguration",
                    url=base_url,
                    severity=Severity.HIGH,
                    cvss_score=7.4,
                    title=f"Weak TLS Protocol In Use — {protocol}",
                    description=(
                        f"The server negotiated {protocol}, which has known cryptographic "
                        f"weaknesses and is deprecated."
                    ),
                    evidence=f"Negotiated protocol: {protocol}, cipher: {cipher}",
                    exploitation=(
                        "An attacker positioned on the network path may be able to downgrade "
                        "or exploit protocol-level weaknesses (e.g. POODLE, BEAST) depending "
                        "on the server's configuration."
                    ),
                    remediation="Disable TLSv1.0/1.1/SSLv3 server-side; require TLSv1.2+ (prefer TLSv1.3).",
                    cwe_id="CWE-326",
                    references=["https://owasp.org/www-community/vulnerabilities/Insecure_Transport"],
                ))
        except Exception as e:
            console.print(f"  [dim]TLS protocol check skipped ({host}): {e}[/dim]")

        try:
            cert_dict = await asyncio.to_thread(self._cert_info, host, port, 8.0)
            not_after = datetime.strptime(
                cert_dict["notAfter"], "%b %d %H:%M:%S %Y %Z"
            ).replace(tzinfo=timezone.utc)

            issuer = dict(x[0] for x in cert_dict.get("issuer", []))
            subject = dict(x[0] for x in cert_dict.get("subject", []))
            if issuer.get("commonName") and issuer.get("commonName") == subject.get("commonName"):
                vulns.append(Vulnerability(
                    vuln_type="TLS/SSL Misconfiguration",
                    url=base_url,
                    severity=Severity.MEDIUM,
                    cvss_score=5.3,
                    title="Self-Signed Certificate",
                    description=(
                        "The server presents a self-signed certificate (issuer matches "
                        "subject), which browsers and clients will not trust by default."
                    ),
                    evidence=f"Subject/Issuer CN: {subject.get('commonName')}",
                    exploitation=(
                        "Trains users to click through certificate warnings, enabling MITM "
                        "attacks; also breaks automated clients that verify certificates."
                    ),
                    remediation="Use a certificate from a trusted CA (e.g. Let's Encrypt) for any publicly reachable service.",
                    cwe_id="CWE-295",
                ))

            expiry = classify_cert_expiry(not_after)
            if expiry:
                sev, msg = expiry
                severity = {"critical": Severity.CRITICAL, "high": Severity.HIGH, "medium": Severity.MEDIUM}[sev]
                cvss = {"critical": 9.1, "high": 7.5, "medium": 5.3}[sev]
                vulns.append(Vulnerability(
                    vuln_type="TLS/SSL Misconfiguration",
                    url=base_url,
                    severity=severity,
                    cvss_score=cvss,
                    title="TLS Certificate Expiry Issue",
                    description=msg,
                    evidence=f"notAfter: {cert_dict['notAfter']}",
                    exploitation=(
                        "An expired certificate breaks trust validation for clients and can "
                        "be a sign of unmaintained infrastructure; may already be causing "
                        "outages for strict clients."
                    ),
                    remediation="Renew the certificate and set up automated renewal (e.g. certbot with a cron/systemd timer).",
                    cwe_id="CWE-295",
                ))
        except ssl.SSLCertVerificationError:
            # Untrusted/self-signed cert — getpeercert() can still return the dict via an
            # unverified context, but keeping this simple: the unverified path above already
            # covers protocol/cipher, and a verification failure is itself worth flagging.
            vulns.append(Vulnerability(
                vuln_type="TLS/SSL Misconfiguration",
                url=base_url,
                severity=Severity.MEDIUM,
                cvss_score=5.3,
                title="Certificate Verification Failed",
                description="The server's TLS certificate failed standard chain-of-trust verification (untrusted, expired, or hostname mismatch).",
                evidence=f"Host: {host}:{port}",
                exploitation="Clients relying on strict cert verification will fail to connect or may be tricked into disabling verification, enabling MITM.",
                remediation="Ensure a valid certificate from a trusted CA covering the correct hostname is deployed.",
                cwe_id="CWE-295",
            ))
        except Exception as e:
            console.print(f"  [dim]TLS cert parse skipped ({host}): {e}[/dim]")

        for v in vulns:
            console.print(f"  {v.severity.emoji} [bold]TLS/SSL:[/bold] {v.title}")
        return vulns
