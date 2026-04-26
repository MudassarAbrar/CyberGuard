import time
from enum import Enum
from pathlib import Path
from typing import Optional

import typer
from pydantic import BaseModel, Field
from rich.console import Console
from rich.progress import Progress, SpinnerColumn, TextColumn
from rich.table import Table

app = typer.Typer(
    name="securescope",
    help="SecureScope — Professional security scanner.",
    no_args_is_help=True,
    add_completion=False,
)
console = Console()
err_console = Console(stderr=True)

VERSION = "0.1.0"


class Depth(str, Enum):
    quick = "quick"
    standard = "standard"
    deep = "deep"


class Focus(str, Enum):
    network = "network"
    crypto = "crypto"
    all = "all"


class Format(str, Enum):
    json = "json"
    sarif = "sarif"
    pdf = "pdf"
    table = "table"


class Severity(str, Enum):
    critical = "critical"
    high = "high"
    medium = "medium"
    low = "low"
    info = "info"


class Language(str, Enum):
    auto = "auto"
    python = "python"
    javascript = "javascript"
    typescript = "typescript"
    go = "go"
    java = "java"


class ScanConfig(BaseModel):
    path: Path
    depth: Depth = Field(default=Depth.standard)
    focus: Focus = Field(default=Focus.all)
    format: Format = Field(default=Format.table)
    output: Optional[Path] = None
    fail_on: Severity = Field(default=Severity.high)
    no_ai: bool = Field(default=False)
    language: Language = Field(default=Language.auto)


SEVERITY_COLORS = {
    Severity.critical: "bold white on red",
    Severity.high: "bold red",
    Severity.medium: "bold yellow",
    Severity.low: "bold blue",
    Severity.info: "bold white",
}

SEVERITY_RANKS = {
    Severity.critical: 5,
    Severity.high: 4,
    Severity.medium: 3,
    Severity.low: 2,
    Severity.info: 1,
}


@app.command()
def version():
    """Print the version of SecureScope."""
    console.print(f"SecureScope version [bold cyan]{VERSION}[/bold cyan]")


@app.command()
def init():
    """Create a default .securescope.yml configuration file."""
    config_path = Path(".securescope.yml")
    if config_path.exists():
        console.print(f"[yellow]Configuration file already exists at {config_path}[/yellow]")
        raise typer.Exit(code=1)

    config_content = """# SecureScope Configuration
depth: standard
focus: all
fail_on: high
no_ai: false
language: auto
"""
    config_path.write_text(config_content)
    console.print(f"[green]✓ Created configuration file at {config_path}[/green]")


@app.command()
def scan(
    path: Path = typer.Argument(
        ...,
        exists=True,
        help="The path to scan.",
    ),
    depth: Depth = typer.Option(
        Depth.standard,
        "--depth",
        help="Scan depth: quick, standard, or deep.",
    ),
    focus: Focus = typer.Option(
        Focus.all,
        "--focus",
        help="Focus area: network, crypto, or all.",
    ),
    output_format: Format = typer.Option(
        Format.table,
        "--format",
        "-f",
        help="Output format: json, sarif, pdf, or table.",
    ),
    output: Optional[Path] = typer.Option(
        None,
        "--output",
        "-o",
        help="Output file path.",
    ),
    fail_on: Severity = typer.Option(
        Severity.high,
        "--fail-on",
        help="Exit code 1 if findings are >= this severity.",
    ),
    no_ai: bool = typer.Option(
        False,
        "--no-ai",
        help="Skip AI engine for speed.",
    ),
    language: Language = typer.Option(
        Language.auto,
        "--language",
        help="Target language.",
    ),
):
    """Scan a path for security vulnerabilities."""

    config = ScanConfig(
        path=path,
        depth=depth,
        focus=focus,
        format=output_format,
        output=output,
        fail_on=fail_on,
        no_ai=no_ai,
        language=language,
    )

    console.rule("[bold cyan]SecureScope Scan Started[/bold cyan]")

    # Mocking scan progress
    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        console=console,
    ) as progress:
        task_prep = progress.add_task("[cyan]Preparing environment...", total=None)
        time.sleep(0.5)
        progress.update(task_prep, completed=True)

        task_static = progress.add_task("[blue]Running static analysis...", total=None)
        time.sleep(1.0)
        progress.update(task_static, completed=True)

        if not config.no_ai:
            task_ai = progress.add_task("[magenta]Running AI engine...", total=None)
            time.sleep(1.5)
            progress.update(task_ai, completed=True)

    console.print("\n[bold green]Scan complete![/bold green]\n")

    # Mock findings
    findings = [
        {"severity": Severity.critical, "engine": "AI", "location": "app/auth.py:42", "type": "SQL Injection"},
        {"severity": Severity.high, "engine": "Static", "location": "app/utils.py:12", "type": "Hardcoded Secret"},
        {"severity": Severity.medium, "engine": "Static", "location": "app/api.py:55", "type": "Weak Crypto"},
        {"severity": Severity.info, "engine": "Static", "location": "app/main.py:1", "type": "TODO comment"},
    ]

    max_found_severity_rank = 0

    if config.format == Format.table:
        table = Table(show_header=True, header_style="bold magenta")
        table.add_column("Severity")
        table.add_column("Engine")
        table.add_column("File:Line")
        table.add_column("Type")

        for f in findings:
            sev = f["severity"]
            rank = SEVERITY_RANKS[sev]
            if rank > max_found_severity_rank:
                max_found_severity_rank = rank

            color = SEVERITY_COLORS[sev]
            table.add_row(
                f"[{color}]{sev.value.upper()}[/{color}]",
                f["engine"],
                f["location"],
                f["type"],
            )

        console.print(table)
    else:
        # For simplicity in mock, just print text for non-table outputs
        for f in findings:
            sev = f["severity"]
            rank = SEVERITY_RANKS[sev]
            if rank > max_found_severity_rank:
                max_found_severity_rank = rank
        console.print(f"Output would be saved as {config.format.value}")

    if config.output:
        console.print(f"[green]Results saved to {config.output}[/green]")

    fail_rank = SEVERITY_RANKS[config.fail_on]
    if max_found_severity_rank >= fail_rank:
        console.print(f"\n[red]Findings found at or above {config.fail_on.value} severity. Failing check.[/red]")
        raise typer.Exit(code=1)


if __name__ == "__main__":
    app()
