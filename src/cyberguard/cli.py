"""CyberGuard CLI — entry point for the ``cyberguard`` command."""

from __future__ import annotations

from pathlib import Path
from typing import Optional

import typer
from rich.console import Console
from rich.table import Table

from . import __version__
from .models import SEVERITY_RANK, Severity
from .reporters.json_reporter import JsonReporter
from .reporters.sarif_reporter import SarifReporter
from .scanner import create_scanner

app = typer.Typer(
    name="cyberguard",
    help="🛡  CyberGuard — AI-powered cybersecurity code scanner.",
    add_completion=False,
    no_args_is_help=True,
)
# All decorative / human-readable output goes to stderr so that stdout
# carries only the structured JSON or SARIF payload (pipe-friendly).
console = Console(stderr=True)
err_console = Console(stderr=True)

# ---------------------------------------------------------------------------
# Version callback
# ---------------------------------------------------------------------------


def _version_callback(value: bool) -> None:
    if value:
        typer.echo(f"CyberGuard {__version__}")
        raise typer.Exit()


@app.callback()
def _global_options(
    version: Optional[bool] = typer.Option(
        None,
        "--version",
        "-V",
        callback=_version_callback,
        is_eager=True,
        help="Print version and exit.",
    ),
) -> None:
    """CyberGuard — AI-powered cybersecurity code scanner."""


# ---------------------------------------------------------------------------
# scan command
# ---------------------------------------------------------------------------


@app.command()
def scan(
    path: Path = typer.Argument(
        ...,
        exists=True,
        help="File or directory to scan.",
    ),
    output_format: str = typer.Option(
        "json",
        "--format",
        "-f",
        help="Output format: json or sarif.",
    ),
    output: Optional[Path] = typer.Option(
        None,
        "--output",
        "-o",
        help="Write output to this file (printed to stdout when omitted).",
    ),
    fail_on: str = typer.Option(
        "high",
        "--fail-on",
        help=(
            "Exit with code 1 when findings at or above this severity are found. "
            "Accepted values: critical, high, medium, low, none."
        ),
    ),
    no_ai: bool = typer.Option(
        False,
        "--no-ai",
        help="Disable the AI semantic analysis engine.",
    ),
    no_bandit: bool = typer.Option(
        False,
        "--no-bandit",
        help="Disable the Bandit engine (Python only).",
    ),
    no_pattern: bool = typer.Option(
        False,
        "--no-pattern",
        help="Disable the regex pattern-matching engine.",
    ),
    quiet: bool = typer.Option(
        False,
        "--quiet",
        "-q",
        help="Suppress informational console output (errors are still shown).",
    ),
) -> None:
    """Scan a file or directory for security vulnerabilities."""

    # ── Validate --format ────────────────────────────────────────────────────
    fmt = output_format.lower()
    if fmt not in ("json", "sarif"):
        err_console.print("[red]Error: --format must be 'json' or 'sarif'.[/red]")
        raise typer.Exit(code=2)

    # ── Validate --fail-on ───────────────────────────────────────────────────
    fail_on_lower = fail_on.lower()
    fail_threshold: Optional[Severity]
    if fail_on_lower == "none":
        fail_threshold = None
    else:
        try:
            fail_threshold = Severity(fail_on_lower)
        except ValueError:
            err_console.print(
                "[red]Error: --fail-on must be one of: critical, high, medium, low, none.[/red]"
            )
            raise typer.Exit(code=2)

    # ── Banner ───────────────────────────────────────────────────────────────
    if not quiet:
        console.rule(f"[bold cyan]🛡  CyberGuard v{__version__}[/bold cyan]")
        console.print(f"[bold]Target:[/bold] {path.resolve()}")
        console.print()

    # ── Run scan ─────────────────────────────────────────────────────────────
    scanner = create_scanner(
        no_bandit=no_bandit,
        no_pattern=no_pattern,
        no_ai=no_ai,
    )
    scanner._quiet = quiet

    try:
        result = scanner.scan(str(path))
    except FileNotFoundError as exc:
        err_console.print(f"[red]Error: {exc}[/red]")
        raise typer.Exit(code=2)

    # ── Render output ────────────────────────────────────────────────────────
    reporter = SarifReporter() if fmt == "sarif" else JsonReporter()
    rendered = reporter.write(result, output_path=output)

    if output:
        if not quiet:
            console.print(f"\n[green]✓ Output written to:[/green] {output}")
    else:
        # Write the structured output to stdout so it can be piped / redirected.
        # typer.echo integrates properly with Click's test-runner capture.
        typer.echo(rendered)

    # ── Summary table ────────────────────────────────────────────────────────
    if not quiet:
        _print_summary(result)

    # ── Exit code ────────────────────────────────────────────────────────────
    if fail_threshold is not None and result.has_findings_at_or_above(fail_threshold):
        raise typer.Exit(code=1)


# ---------------------------------------------------------------------------
# Summary helpers
# ---------------------------------------------------------------------------

_SEVERITY_COLORS = {
    Severity.CRITICAL: "bright_red",
    Severity.HIGH: "red",
    Severity.MEDIUM: "yellow",
    Severity.LOW: "blue",
    Severity.INFO: "dim",
}


def _print_summary(result) -> None:  # type: ignore[no-untyped-def]
    counts = result.findings_by_severity()
    total = len(result.findings)

    console.print()
    console.rule("[bold]Scan Summary[/bold]")
    console.print(
        f"  Files scanned : [bold]{result.scanned_files}[/bold]\n"
        f"  Total findings: [bold]{total}[/bold]\n"
        f"  Duration      : [bold]{result.scan_duration_ms:.0f} ms[/bold]"
    )

    if total == 0:
        console.print("\n[bold green]✓ No security vulnerabilities found.[/bold green]")
        return

    # Severity breakdown table
    sev_table = Table(show_header=True, header_style="bold magenta", box=None, padding=(0, 2))
    sev_table.add_column("Severity", style="bold")
    sev_table.add_column("Count", justify="right")

    for sev in [Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM, Severity.LOW, Severity.INFO]:
        count = counts.get(sev, 0)
        if count > 0:
            color = _SEVERITY_COLORS.get(sev, "white")
            sev_table.add_row(f"[{color}]{sev.value.upper()}[/{color}]", str(count))

    console.print()
    console.print(sev_table)

    # Top-10 findings table
    top = sorted(result.findings, key=lambda f: SEVERITY_RANK[f.severity], reverse=True)[:10]
    console.print()
    find_table = Table(
        title="Top Findings",
        show_header=True,
        header_style="bold",
        box=None,
        padding=(0, 1),
    )
    find_table.add_column("Sev", width=8)
    find_table.add_column("Rule", width=16)
    find_table.add_column("Title", width=38)
    find_table.add_column("Location")

    for f in top:
        color = _SEVERITY_COLORS.get(f.severity, "white")
        loc = f"{f.location.file_path}:{f.location.line_start}"
        find_table.add_row(
            f"[{color}]{f.severity.value.upper()}[/{color}]",
            f.rule_id,
            f.title,
            loc,
        )

    console.print(find_table)
