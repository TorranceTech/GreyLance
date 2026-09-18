"""
Port Scanner — asyncio-based TCP connect scan + nmap service detection
"""

import asyncio
import socket
from typing import Optional
from rich.console import Console
from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn
from core.models import PortInfo

console = Console()

# Port → Service mapping (fallback when nmap not available)
SERVICE_MAP = {
    21: "ftp", 22: "ssh", 23: "telnet", 25: "smtp", 53: "dns",
    80: "http", 110: "pop3", 111: "rpcbind", 135: "msrpc",
    139: "netbios-ssn", 143: "imap", 443: "https", 445: "smb",
    993: "imaps", 995: "pop3s", 1723: "pptp", 3306: "mysql",
    3389: "rdp", 5432: "postgresql", 5900: "vnc", 6379: "redis",
    8080: "http-alt", 8443: "https-alt", 8888: "http-alt",
    9200: "elasticsearch", 27017: "mongodb",
}

# Potential vulnerability hints for ports
PORT_VULN_HINTS = {
    21:    "FTP — Check anonymous login, plaintext credentials",
    22:    "SSH — Check brute force, outdated version",
    23:    "Telnet — Plaintext protocol, dangerous to use",
    25:    "SMTP — Check open relay, user enumeration",
    3306:  "MySQL — Check remote access, weak credentials",
    3389:  "RDP — Check BlueKeep, brute force",
    5432:  "PostgreSQL — Check remote access, weak credentials",
    5900:  "VNC — Check authentication bypass, weak password",
    6379:  "Redis — Check unauthenticated access (CVE-2022-0543)",
    9200:  "Elasticsearch — Check unauthenticated access, data exposure",
    27017: "MongoDB — Check unauthenticated access",
}


class PortScanner:
    def __init__(self, timeout: float = 1.5, max_concurrent: int = 200):
        self.timeout = timeout
        self.max_concurrent = max_concurrent

    async def _tcp_connect(self, host: str, port: int) -> bool:
        """Simple TCP connect scan"""
        try:
            _, writer = await asyncio.wait_for(
                asyncio.open_connection(host, port),
                timeout=self.timeout
            )
            writer.close()
            try:
                await writer.wait_closed()
            except Exception:
                pass
            return True
        except (asyncio.TimeoutError, ConnectionRefusedError, OSError):
            return False

    async def _grab_banner(self, host: str, port: int) -> Optional[str]:
        """Grab service banner"""
        try:
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(host, port),
                timeout=2.0
            )
            # Send GET for HTTP ports
            if port in [80, 8080, 8888]:
                writer.write(b"HEAD / HTTP/1.0\r\n\r\n")
                await writer.drain()

            data = await asyncio.wait_for(reader.read(256), timeout=2.0)
            writer.close()
            banner = data.decode("utf-8", errors="ignore").strip()
            return banner[:200] if banner else None
        except Exception:
            return None

    async def _scan_port(self, host: str, port: int,
                         semaphore: asyncio.Semaphore) -> Optional[PortInfo]:
        async with semaphore:
            is_open = await self._tcp_connect(host, port)
            if not is_open:
                return None

            service = SERVICE_MAP.get(port, "unknown")
            banner = await self._grab_banner(host, port)

            # Try to extract version from banner
            version = None
            if banner:
                lines = banner.split("\n")
                version = lines[0][:100] if lines else None

            return PortInfo(
                port=port,
                protocol="tcp",
                state="open",
                service=service,
                version=version,
                banner=banner,
            )

    async def scan(self, host: str, ports: list[int] = None,
                   mode: str = "common") -> list[PortInfo]:
        """
        mode: "common" (19 port), "extended" (25 port), "full" (1-65535)
        """
        if ports is None:
            if mode == "full":
                ports = list(range(1, 65536))
            elif mode == "extended":
                ports = list(SERVICE_MAP.keys()) + [8080, 8443, 8888]
            else:  # common
                ports = list(SERVICE_MAP.keys())

        # Resolve IP address
        try:
            ip = socket.gethostbyname(host)
        except socket.gaierror:
            console.print(f"[red]❌ Could not resolve {host}[/red]")
            return []

        console.print(f"\n[bold cyan]🔌 Port scan:[/bold cyan] {host} ({ip}) — {len(ports)} port")

        semaphore = asyncio.Semaphore(self.max_concurrent)
        open_ports = []

        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            BarColumn(),
            TextColumn("[progress.percentage]{task.percentage:>3.0f}%"),
            console=console,
        ) as progress:
            task = progress.add_task(f"[cyan]Port scan...[/cyan]", total=len(ports))

            async def scan_with_progress(port):
                result = await self._scan_port(ip, port, semaphore)
                progress.advance(task)
                return result

            results = await asyncio.gather(
                *[scan_with_progress(p) for p in ports],
                return_exceptions=True
            )

        for r in results:
            if isinstance(r, PortInfo):
                open_ports.append(r)
                hint = PORT_VULN_HINTS.get(r.port, "")
                hint_str = f" [dim]→ {hint}[/dim]" if hint else ""
                console.print(
                    f"  [green]OPEN[/green] {r.port}/tcp  "
                    f"[yellow]{r.service}[/yellow]"
                    f"{' — ' + r.version[:50] if r.version else ''}"
                    f"{hint_str}"
                )

        console.print(f"[bold green]  Port scan completed: {len(open_ports)} open ports[/bold green]")
        return open_ports
