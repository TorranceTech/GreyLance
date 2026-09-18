#!/usr/bin/env python3
"""
GreyLance CLI v2.0
"""

import asyncio
import sys
from pathlib import Path

import click
from rich.console import Console
from rich.panel import Panel

sys.path.insert(0, str(Path(__file__).parent))

from core.scanner import GreyLanceScanner
from core.reporter import Reporter

console = Console()


def print_banner():
    console.print(Panel.fit(
        "[bold cyan]GREYLANCE[/bold cyan]\n"
        "[dim]Web Vulnerability Assessment & Recon Framework — v2.0[/dim]\n"
        "[dim]Authorized use only[/dim]",
        border_style="cyan",
    ))


def confirm_authorization(target: str, auto_confirm: bool) -> None:
    """Refuse to scan without an explicit authorization confirmation."""
    if auto_confirm:
        console.print("[dim]Authorization confirmed via --authorized flag.[/dim]")
        return

    if not sys.stdin.isatty():
        console.print(
            "[bold red]✖ Refusing to run:[/bold red] non-interactive session and "
            "no --authorized flag. Pass --authorized only if you have explicit "
            "permission to test this target."
        )
        sys.exit(1)

    console.print(
        "\n[bold yellow]⚠ AUTHORIZATION REQUIRED[/bold yellow]\n"
        "This tool performs active security testing (injected payloads, port scans,\n"
        "endpoint brute-forcing). Only run it against systems you own or have explicit,\n"
        "documented permission to test (a pentest engagement, a bug bounty program's\n"
        "in-scope assets, or your own lab).\n"
    )
    typed = click.prompt(
        f"Type the target host ('{target}') to confirm you are authorized",
        default="", show_default=False,
    )
    if typed.strip() != target.strip():
        console.print("[bold red]✖ Confirmation did not match. Aborting.[/bold red]")
        sys.exit(1)


def parse_cookies(cookie_list: tuple) -> dict:
    """Create a dict from 'name=value' format"""
    result = {}
    for c in cookie_list:
        c = c.strip()
        if '=' in c:
            k, v = c.split('=', 1)
            result[k.strip()] = v.strip()
        else:
            console.print(
                f"[yellow]⚠️  Cookie parse error:[/yellow] '{c}' "
                f"— 'name=value' Format should be followed."
            )
    return result


def parse_headers(header_list: tuple) -> dict:
    """Create a dict from 'Name: Value' format"""
    result = {}
    for h in header_list:
        h = h.strip()
        if ':' in h:
            k, v = h.split(':', 1)
            result[k.strip()] = v.strip()
        else:
            console.print(
                f"[yellow]⚠️  Header parse error:[/yellow] '{h}' "
                f"— 'Name: Value' Format should be as follows"
            )
    return result


@click.group()
def cli():
    """GreyLance v2.0 — Web Vulnerability Assessment & Recon Framework"""
    pass


@cli.command()
@click.argument("url")
@click.option(
    "--mode", "-m",
    type=click.Choice(["all", "recon", "vulns"]),
    default="all",
    help="Scan module (default: all)",
    show_default=True,
)
@click.option(
    "--ports", "-p",
    type=click.Choice(["common", "extended", "full"]),
    default="common",
    help="Port scan depth (default: common)",
    show_default=True,
)
@click.option(
    "--no-subdomains",
    is_flag=True,
    default=False,
    help="Skip subdomain scan",
)
@click.option(
    "--output", "-o",
    default="./reports",
    help="Report folder (default: ./reports)",
    show_default=True,
)
@click.option(
    "--format", "-f",
    type=click.Choice(["all", "json", "html"]),
    default="all",
    help="Output format (default: all)",
    show_default=True,
)
@click.option(
    "--rps",
    type=float,
    default=10.0,
    help="Max requests per second (default: 10)",
    show_default=True,
)
@click.option(
    "--cookie", "-c",
    multiple=True,
    help='Cookie — "name=value" (use multiple times)',
)
@click.option(
    "--header", "-H",
    multiple=True,
    help='Custom header — "Name: Value"',
)
@click.option(
    "--proxy",
    default=None,
    help="Proxy URL — http://127.0.0.1:8080 (Burp Suite)",
)
@click.option(
    "--business-logic",
    is_flag=True,
    default=False,
    help="Business logic scan (recommended for authenticated scan)",
)
@click.option(
    "--no-fp-validation",
    is_flag=True,
    default=False,
    help="Disable false-positive validation (for quick scan)",
)
@click.option(
    "--no-nuclei",
    is_flag=True,
    default=False,
    help="Skip the nuclei scan",
)
@click.option(
    "--authorized",
    is_flag=True,
    default=False,
    help="Confirm you have explicit authorization to test this target "
         "(skips the interactive prompt — required for non-interactive/CI use)",
)
def scan(
    url, mode, ports, no_subdomains, output, format,
    rps, cookie, header, proxy,
    business_logic, no_fp_validation, no_nuclei, authorized,
):
    """
    Scan the target URL.

    \b
    Samples:
      # Simple scan
      python cli.py scan https://target.com

      # Authenticated scan
      python cli.py scan https://target.com \\
        --cookie "session=abc123" \\
        --cookie "csrf=xyz789"

      # With a Bearer token
      python cli.py scan https://target.com \\
        --header "Authorization: Bearer eyJ..."

      # Burp Suite proxy + business logic
      python cli.py scan https://target.com \\
        --cookie "session=abc123" \\
        --proxy http://127.0.0.1:8080 \\
        --business-logic

      # Quick scan — skip FP validation
      python cli.py scan https://target.com \\
        --no-subdomains \\
        --no-fp-validation \\
        --rps 20

      # Target behind a WAF — slow, cautious
      python cli.py scan https://target.com \\
        --rps 3 \\
        --no-subdomains \\
        --ports common
    """
    print_banner()
    confirm_authorization(url, authorized)

    # Cookie + Header parse
    parsed_cookies = parse_cookies(cookie)
    parsed_headers = parse_headers(header)

    if parsed_cookies:
        console.print(
            f"[green]🍪 Cookie:[/green] "
            f"{', '.join(parsed_cookies.keys())}"
        )
    if parsed_headers:
        console.print(
            f"[green]📋 Headers:[/green] "
            f"{', '.join(parsed_headers.keys())}"
        )
    if proxy:
        console.print(f"[green]🔀 Proxy:[/green] {proxy}")
    if business_logic:
        console.print("[green]🧠 Business Logic:[/green] active")

    # Configure settings
    config = None
    if rps != 10.0:
        from core.scanner import load_config
        config = load_config()
        config["rate_limiting"]["default_rps"] = rps

    async def run():
        scanner = GreyLanceScanner(
            config=config,
            cookies=parsed_cookies,
            headers=parsed_headers,
            proxy=proxy,
            validate_fp=not no_fp_validation,
            run_business_logic=business_logic,
        )

        result = await scanner.scan(
            target=url,
            modes=[mode],
            port_mode=ports,
            skip_subdomains=no_subdomains,
        )

        reporter = Reporter(output_dir=output)
        if format == "json":
            await reporter.save_json(result)
        elif format == "html":
            await reporter.save_html(result)
        else:
            await reporter.save_all(result)

        # Print summary
        console.print(
            f"\n[bold green]✅ Scan completed![/bold green] "
            f"Reports: {output}/"
        )

        return result

    asyncio.run(run())


@cli.command()
@click.argument("url")
@click.option(
    "--ports", "-p",
    type=click.Choice(["common", "extended", "full"]),
    default="common",
)
@click.option("--no-subdomains", is_flag=True)
@click.option("--output", "-o", default="./reports")
@click.option(
    "--authorized", is_flag=True, default=False,
    help="Confirm you have explicit authorization to test this target",
)
def recon(url, ports, no_subdomains, output, authorized):
    """
    Recon only — subdomain + port + fingerprint + discovery.

    \b
    Sample:
      python cli.py recon https://target.com --ports extended
    """
    print_banner()
    confirm_authorization(url, authorized)

    async def run():
        scanner = GreyLanceScanner()
        result = await scanner.scan(
            target=url,
            modes=["recon"],
            port_mode=ports,
            skip_subdomains=no_subdomains,
        )
        reporter = Reporter(output_dir=output)
        await reporter.save_all(result)

    asyncio.run(run())


@cli.command()
@click.argument("url")
@click.option("--cookie", "-c", multiple=True)
@click.option("--header", "-H", multiple=True)
@click.option("--proxy", default=None)
@click.option("--output", "-o", default="./reports")
@click.option("--no-fp-validation", is_flag=True, default=False)
@click.option(
    "--authorized", is_flag=True, default=False,
    help="Confirm you have explicit authorization to test this target",
)
def vulnscan(url, cookie, header, proxy, output, no_fp_validation, authorized):
    """
    Only vulnerability scan — without recon.

    \b
    Example:
      python cli.py vulnscan https://target.com \\
        --cookie "session=abc123"
    """
    print_banner()
    confirm_authorization(url, authorized)

    parsed_cookies = parse_cookies(cookie)
    parsed_headers = parse_headers(header)

    async def run():
        scanner = GreyLanceScanner(
            cookies=parsed_cookies,
            headers=parsed_headers,
            proxy=proxy,
            validate_fp=not no_fp_validation,
        )
        result = await scanner.scan(
            target=url,
            modes=["vulns"],
            skip_subdomains=True,
        )
        reporter = Reporter(output_dir=output)
        await reporter.save_all(result)

    asyncio.run(run())


@cli.command()
@click.argument("url")
@click.option("--cookie", "-c", multiple=True)
@click.option("--header", "-H", multiple=True)
@click.option("--proxy", default=None)
@click.option("--output", "-o", default="./reports")
@click.option(
    "--authorized", is_flag=True, default=False,
    help="Confirm you have explicit authorization to test this target",
)
def bizlogic(url, cookie, header, proxy, output, authorized):
    """
    Business logic scan — authenticated.

    \b
    Example:
      python cli.py bizlogic https://target.com \\
        --cookie "session=abc123" \\
        --proxy http://127.0.0.1:8080
    """
    print_banner()
    confirm_authorization(url, authorized)

    parsed_cookies = parse_cookies(cookie)
    parsed_headers = parse_headers(header)

    if not parsed_cookies and not parsed_headers:
        console.print(
            "[yellow]⚠️  Notification:[/yellow] "
            "Running a business logic scan without authentication "
            "produces limited results. Use it together with --cookie."
        )

    async def run():
        scanner = GreyLanceScanner(
            cookies=parsed_cookies,
            headers=parsed_headers,
            proxy=proxy,
            run_business_logic=True,
            validate_fp=True,
        )
        result = await scanner.scan(
            target=url,
            modes=["vulns"],
            skip_subdomains=True,
        )
        reporter = Reporter(output_dir=output)
        await reporter.save_all(result)

    asyncio.run(run())


@cli.command()
def version():
    """Version information"""
    console.print("[bold cyan]GreyLance[/bold cyan] v2.0")
    console.print("[dim]Web Vulnerability Assessment & Recon Framework[/dim]")
    console.print("[dim]Authorized use only[/dim]")


if __name__ == "__main__":
    cli()