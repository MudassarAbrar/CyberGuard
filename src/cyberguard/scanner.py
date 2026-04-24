"""CyberGuard scanner — orchestrates all engines over a target path."""

from __future__ import annotations

import time
from pathlib import Path
from typing import List

from rich.console import Console

from .engines.ai_engine import AIEngine
from .engines.bandit_engine import BanditEngine
from .engines.base import BaseEngine
from .engines.pattern_engine import PatternEngine
from .models import Finding, ScanResult

_console = Console(stderr=True)

# Directories that should never be scanned.
_SKIP_DIRS = frozenset(
    {
        ".git",
        ".venv",
        "venv",
        "env",
        "node_modules",
        "__pycache__",
        ".tox",
        ".mypy_cache",
        ".pytest_cache",
        "dist",
        "build",
        ".eggs",
    }
)


def _collect_files(target_path: Path) -> List[Path]:
    """Return a sorted list of files under *target_path*, skipping vendor dirs."""
    if target_path.is_file():
        return [target_path]

    files: List[Path] = []
    for p in target_path.rglob("*"):
        if any(part in _SKIP_DIRS for part in p.parts):
            continue
        if p.is_file():
            files.append(p)
    return sorted(files)


class Scanner:
    """Orchestrates one or more scan engines over a target path.

    Parameters
    ----------
    use_bandit:
        Enable the Bandit engine (Python static analysis).
    use_pattern:
        Enable the regex pattern engine (Python + JavaScript).
    use_ai:
        Enable the AI semantic analysis engine.  The engine is silently
        skipped when no API key is configured.
    """

    def __init__(
        self,
        use_bandit: bool = True,
        use_pattern: bool = True,
        use_ai: bool = True,
    ) -> None:
        engines: List[BaseEngine] = []

        if use_bandit:
            engines.append(BanditEngine())

        if use_pattern:
            engines.append(PatternEngine())

        if use_ai:
            ai_engine = AIEngine()
            if ai_engine.is_available:
                engines.append(ai_engine)
            else:
                _console.print(
                    "[yellow]⚠  AI engine disabled: set GROQ_API_KEY or "
                    "OPENAI_API_KEY to enable semantic analysis.[/yellow]"
                )

        self.engines = engines

    def scan(self, target_path: str) -> ScanResult:
        """Run all configured engines against *target_path*.

        Returns a :class:`~cyberguard.models.ScanResult` with deduplicated
        findings from every engine.

        Raises
        ------
        FileNotFoundError
            If *target_path* does not exist on disk.
        """
        path = Path(target_path).resolve()
        if not path.exists():
            raise FileNotFoundError(f"Path does not exist: {path}")

        files = _collect_files(path)
        start_ms = time.monotonic() * 1000
        all_findings: List[Finding] = []

        for engine in self.engines:
            _console.print(f"[dim]  → Running [bold]{engine.name}[/bold] engine…[/dim]")
            try:
                engine_findings = engine.scan_path(path)
                all_findings.extend(engine_findings)
            except Exception as exc:  # noqa: BLE001
                _console.print(
                    f"[red]  ✗ Engine [bold]{engine.name}[/bold] failed: {exc}[/red]"
                )

        elapsed_ms = time.monotonic() * 1000 - start_ms

        # Deduplicate by (rule_id, file_path, line_start) across engines.
        seen: set[tuple[str, str, int]] = set()
        unique: List[Finding] = []
        for finding in all_findings:
            key = (finding.rule_id, finding.location.file_path, finding.location.line_start)
            if key not in seen:
                seen.add(key)
                unique.append(finding)

        return ScanResult(
            target_path=str(path),
            findings=unique,
            engines_used=[e.name for e in self.engines],
            scanned_files=len(files),
            scan_duration_ms=elapsed_ms,
        )


def create_scanner(
    no_bandit: bool = False,
    no_pattern: bool = False,
    no_ai: bool = False,
) -> Scanner:
    """Convenience factory used by the CLI."""
    return Scanner(
        use_bandit=not no_bandit,
        use_pattern=not no_pattern,
        use_ai=not no_ai,
    )
