"""Data models for CyberGuard scan findings and results."""

from __future__ import annotations

import uuid
from enum import Enum
from typing import Dict, List, Optional

from pydantic import BaseModel, Field


class Severity(str, Enum):
    """Severity levels for security findings."""

    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


# Maps each severity to an integer rank (higher = more severe).
SEVERITY_RANK: Dict[Severity, int] = {
    Severity.CRITICAL: 4,
    Severity.HIGH: 3,
    Severity.MEDIUM: 2,
    Severity.LOW: 1,
    Severity.INFO: 0,
}


class Location(BaseModel):
    """Source-code location of a finding."""

    file_path: str
    line_start: int = 1
    line_end: int = 1
    col_start: Optional[int] = None
    col_end: Optional[int] = None
    code_snippet: Optional[str] = None


class Finding(BaseModel):
    """A single security finding produced by a scan engine."""

    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    rule_id: str
    title: str
    description: str
    severity: Severity
    location: Location
    engine: str
    cwe: Optional[str] = None
    owasp: Optional[str] = None
    fix_suggestion: Optional[str] = None
    tags: List[str] = Field(default_factory=list)


class ScanResult(BaseModel):
    """Aggregated result of a CyberGuard scan run."""

    scan_id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    target_path: str
    findings: List[Finding] = Field(default_factory=list)
    engines_used: List[str] = Field(default_factory=list)
    scanned_files: int = 0
    scan_duration_ms: float = 0.0

    def findings_by_severity(self) -> Dict[Severity, int]:
        """Return a count of findings grouped by severity."""
        counts: Dict[Severity, int] = {s: 0 for s in Severity}
        for finding in self.findings:
            counts[finding.severity] += 1
        return counts

    def highest_severity(self) -> Optional[Severity]:
        """Return the highest severity found, or None if there are no findings."""
        if not self.findings:
            return None
        return max(self.findings, key=lambda f: SEVERITY_RANK[f.severity]).severity

    def has_findings_at_or_above(self, threshold: Severity) -> bool:
        """Return True if any finding has severity >= *threshold*."""
        threshold_rank = SEVERITY_RANK[threshold]
        return any(SEVERITY_RANK[f.severity] >= threshold_rank for f in self.findings)
