"""
Data models — Vulnerability, ScanResult, SeverityRating
"""

from dataclasses import dataclass, field
from enum import Enum
from datetime import datetime
from typing import Optional


class Severity(Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"

    @property
    def score_range(self) -> tuple:
        ranges = {
            "critical": (9.0, 10.0),
            "high":     (7.0, 8.9),
            "medium":   (4.0, 6.9),
            "low":      (1.0, 3.9),
            "info":     (0.0, 0.9),
        }
        return ranges[self.value]

    @property
    def color(self) -> str:
        colors = {
            "critical": "red",
            "high":     "orange3",
            "medium":   "yellow",
            "low":      "blue",
            "info":     "dim",
        }
        return colors[self.value]

    @property
    def emoji(self) -> str:
        emojis = {
            "critical": "🔴",
            "high":     "🟠",
            "medium":   "🟡",
            "low":      "🔵",
            "info":     "⚪",
        }
        return emojis[self.value]


OWASP_TOP10_2021 = {
    "XSS": "A03:2021 – Injection",
    "SQL Injection": "A03:2021 – Injection",
    "CORS Misconfiguration": "A05:2021 – Security Misconfiguration",
    "SSRF": "A10:2021 – Server-Side Request Forgery",
    "Open Redirect": "A01:2021 – Broken Access Control",
    "JWT Security": "A07:2021 – Identification and Authentication Failures",
    "IDOR": "A01:2021 – Broken Access Control",
    "Access Control": "A01:2021 – Broken Access Control",
    "Exposed Admin Panel": "A01:2021 – Broken Access Control",
    "Information Disclosure": "A05:2021 – Security Misconfiguration",
    "Missing Security Header": "A05:2021 – Security Misconfiguration",
    "Business Logic": "A01:2021 – Broken Access Control",
    "TLS/SSL Misconfiguration": "A02:2021 – Cryptographic Failures",
}
_DEFAULT_OWASP_CATEGORY = "A05:2021 – Security Misconfiguration"


def owasp_category_for(vuln_type: str) -> str:
    """Best-effort mapping from an internal vuln_type to an OWASP Top 10 (2021) category.

    This is a heuristic, not an authoritative classification — some vuln_types
    (e.g. "Business Logic") span multiple OWASP categories in reality.
    """
    if vuln_type.startswith("Nuclei:"):
        return "A06:2021 – Vulnerable and Outdated Components"
    return OWASP_TOP10_2021.get(vuln_type, _DEFAULT_OWASP_CATEGORY)


def calculate_severity(cvss_score: float) -> Severity:
    if cvss_score >= 9.0:
        return Severity.CRITICAL
    elif cvss_score >= 7.0:
        return Severity.HIGH
    elif cvss_score >= 4.0:
        return Severity.MEDIUM
    elif cvss_score >= 1.0:
        return Severity.LOW
    else:
        return Severity.INFO


@dataclass
class Vulnerability:
    vuln_type: str                          # "XSS", "SQLi", "CORS", etc.
    url: str                                # URL where it was found
    severity: Severity
    cvss_score: float
    title: str
    description: str
    evidence: str                           # What we saw (response snippet)
    exploitation: str                       # How it can be exploited
    remediation: str                        # How to fix it
    parameter: Optional[str] = None         # Which parameter
    method: Optional[str] = "GET"
    payload_used: Optional[str] = None      # Which payload worked
    curl_poc: Optional[str] = None          # curl PoC command
    cwe_id: Optional[str] = None            # CWE-79, CWE-89, etc.
    references: list[str] = field(default_factory=list)
    timestamp: datetime = field(default_factory=datetime.now)

    @property
    def owasp_category(self) -> str:
        return owasp_category_for(self.vuln_type)

    def to_dict(self) -> dict:
        return {
            "vuln_type": self.vuln_type,
            "url": self.url,
            "severity": self.severity.value,
            "cvss_score": self.cvss_score,
            "title": self.title,
            "description": self.description,
            "evidence": self.evidence,
            "exploitation": self.exploitation,
            "remediation": self.remediation,
            "parameter": self.parameter,
            "method": self.method,
            "payload_used": self.payload_used,
            "curl_poc": self.curl_poc,
            "cwe_id": self.cwe_id,
            "owasp_category": self.owasp_category,
            "references": self.references,
            "timestamp": self.timestamp.isoformat(),
        }


@dataclass
class PortInfo:
    port: int
    protocol: str           # tcp/udp
    state: str              # open/closed/filtered
    service: str            # http, ssh, mysql, etc.
    version: Optional[str] = None
    banner: Optional[str] = None
    vulnerabilities: list[Vulnerability] = field(default_factory=list)


@dataclass
class SubdomainInfo:
    subdomain: str
    ip: Optional[str] = None
    status: Optional[int] = None        # HTTP status
    technologies: list[str] = field(default_factory=list)
    open_ports: list[PortInfo] = field(default_factory=list)
    vulnerabilities: list[Vulnerability] = field(default_factory=list)


@dataclass
class ScanResult:
    target: str
    start_time: datetime = field(default_factory=datetime.now)
    end_time: Optional[datetime] = None

    # Recon results
    subdomains: list[SubdomainInfo] = field(default_factory=list)
    technologies: list[str] = field(default_factory=list)
    open_ports: list[PortInfo] = field(default_factory=list)
    endpoints: list[str] = field(default_factory=list)

    # Vulnerability results
    vulnerabilities: list[Vulnerability] = field(default_factory=list)

    # Statistics
    @property
    def vuln_count_by_severity(self) -> dict:
        counts = {s.value: 0 for s in Severity}
        for v in self.vulnerabilities:
            counts[v.severity.value] += 1
        return counts

    @property
    def risk_score(self) -> float:
        """Overall risk score — weighted average"""
        if not self.vulnerabilities:
            return 0.0
        weights = {"critical": 4, "high": 3, "medium": 2, "low": 1, "info": 0}
        total = sum(v.cvss_score * weights[v.severity.value] for v in self.vulnerabilities)
        max_possible = len(self.vulnerabilities) * 10 * 4
        return round((total / max_possible) * 10, 2) if max_possible > 0 else 0.0

    def to_dict(self) -> dict:
        return {
            "target": self.target,
            "start_time": self.start_time.isoformat(),
            "end_time": self.end_time.isoformat() if self.end_time else None,
            "summary": {
                "subdomains_found": len(self.subdomains),
                "open_ports": len(self.open_ports),
                "endpoints_found": len(self.endpoints),
                "total_vulnerabilities": len(self.vulnerabilities),
                "by_severity": self.vuln_count_by_severity,
                "risk_score": self.risk_score,
            },
            "technologies": self.technologies,
            "subdomains": [
                {
                    "subdomain": s.subdomain,
                    "ip": s.ip,
                    "status": s.status,
                    "technologies": s.technologies,
                }
                for s in self.subdomains
            ],
            "open_ports": [
                {
                    "port": p.port,
                    "protocol": p.protocol,
                    "state": p.state,
                    "service": p.service,
                    "version": p.version,
                }
                for p in self.open_ports
            ],
            "vulnerabilities": [v.to_dict() for v in self.vulnerabilities],
        }
