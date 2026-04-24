"""Bandit-based static analysis engine for Python source code."""

from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path
from typing import Any, Dict, List

from ..models import Finding, Location, Severity
from .base import BaseEngine

_SEVERITY_MAP: Dict[str, Severity] = {
    "HIGH": Severity.HIGH,
    "MEDIUM": Severity.MEDIUM,
    "LOW": Severity.LOW,
}


class BanditEngine(BaseEngine):
    """Runs Bandit (https://bandit.readthedocs.io/) for Python security analysis.

    The engine invokes Bandit as a subprocess so that it uses the same Python
    interpreter as CyberGuard, ensuring the correct version of Bandit is used
    regardless of the user's PATH.
    """

    name = "bandit"
    supported_extensions = [".py"]

    def scan_file(self, file_path: Path) -> List[Finding]:
        return self._run_bandit(file_path)

    def scan_path(self, target_path: Path) -> List[Finding]:
        # Override to run Bandit on the entire path at once (more efficient
        # than invoking it once per file when scanning a directory tree).
        return self._run_bandit(target_path)

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _run_bandit(self, target: Path) -> List[Finding]:
        try:
            result = subprocess.run(
                [sys.executable, "-m", "bandit", "-r", "-f", "json", "-q", str(target)],
                capture_output=True,
                text=True,
                timeout=120,
            )
        except (subprocess.TimeoutExpired, FileNotFoundError, OSError):
            return []

        stdout = result.stdout.strip()
        if not stdout:
            return []

        try:
            data = json.loads(stdout)
        except json.JSONDecodeError:
            return []

        return [self._issue_to_finding(issue) for issue in data.get("results", [])]

    def _issue_to_finding(self, issue: Dict[str, Any]) -> Finding:
        severity_str = issue.get("issue_severity", "LOW").upper()
        severity = _SEVERITY_MAP.get(severity_str, Severity.LOW)

        line_range = issue.get("line_range") or []
        line_end = line_range[-1] if line_range else issue.get("line_number", 1)

        cwe_info = issue.get("issue_cwe")
        cwe: str | None = None
        if isinstance(cwe_info, dict) and cwe_info.get("id"):
            cwe = f"CWE-{cwe_info['id']}"

        return Finding(
            rule_id=f"bandit.{issue.get('test_id', 'B000')}",
            title=issue.get("test_name", "Security Issue").replace("_", " ").title(),
            description=issue.get("issue_text", ""),
            severity=severity,
            location=Location(
                file_path=issue.get("filename", ""),
                line_start=issue.get("line_number", 1),
                line_end=line_end,
                code_snippet=issue.get("code", "").strip(),
            ),
            engine=self.name,
            cwe=cwe,
            tags=["bandit", f"confidence:{issue.get('issue_confidence', 'unknown').lower()}"],
        )
