"""SARIF 2.1.0 output reporter.

Specification: https://docs.oasis-open.org/sarif/sarif/v2.1.0/sarif-v2.1.0.html
"""

from __future__ import annotations

import json
from typing import Any, Dict, List

from .. import __version__
from ..models import Finding, ScanResult, Severity
from .base import BaseReporter

# Mapping from CyberGuard severity to the SARIF ``level`` field.
_SEVERITY_TO_LEVEL: Dict[Severity, str] = {
    Severity.CRITICAL: "error",
    Severity.HIGH: "error",
    Severity.MEDIUM: "warning",
    Severity.LOW: "note",
    Severity.INFO: "none",
}

# GitHub Advanced Security uses ``security-severity`` (a 0–10 float string)
# to bucket findings into critical / high / medium / low.
_SEVERITY_TO_SECURITY_SCORE: Dict[Severity, str] = {
    Severity.CRITICAL: "9.5",
    Severity.HIGH: "7.5",
    Severity.MEDIUM: "5.0",
    Severity.LOW: "3.0",
    Severity.INFO: "1.0",
}


class SarifReporter(BaseReporter):
    """Renders :class:`~cyberguard.models.ScanResult` in SARIF 2.1.0 format."""

    format_name = "sarif"

    def render(self, result: ScanResult) -> str:
        rules = self._build_rules(result.findings)
        sarif: Dict[str, Any] = {
            "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
            "version": "2.1.0",
            "runs": [
                {
                    "tool": {
                        "driver": {
                            "name": "CyberGuard",
                            "version": __version__,
                            "informationUri": "https://github.com/MudassarAbrar/CyberGuard",
                            "rules": rules,
                        }
                    },
                    "results": [self._finding_to_result(f) for f in result.findings],
                    "properties": {
                        "scanId": result.scan_id,
                        "targetPath": result.target_path,
                        "scannedFiles": result.scanned_files,
                        "enginesUsed": result.engines_used,
                        "scanDurationMs": result.scan_duration_ms,
                    },
                }
            ],
        }
        return json.dumps(sarif, indent=2)

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    def _build_rules(self, findings: List[Finding]) -> List[Dict[str, Any]]:
        """Build a deduplicated list of SARIF rule descriptors."""
        seen: Dict[str, Dict[str, Any]] = {}
        for finding in findings:
            if finding.rule_id in seen:
                continue

            rule: Dict[str, Any] = {
                "id": finding.rule_id,
                "name": finding.title,
                "shortDescription": {"text": finding.title},
                "fullDescription": {"text": finding.description},
                "defaultConfiguration": {
                    "level": _SEVERITY_TO_LEVEL.get(finding.severity, "warning"),
                },
                "properties": {
                    "tags": finding.tags,
                    "security-severity": _SEVERITY_TO_SECURITY_SCORE.get(
                        finding.severity, "5.0"
                    ),
                },
            }

            if finding.cwe:
                rule["relationships"] = [
                    {
                        "target": {
                            "id": finding.cwe,
                            "toolComponent": {"name": "CWE"},
                        }
                    }
                ]

            if finding.fix_suggestion:
                rule["help"] = {"text": finding.fix_suggestion}

            seen[finding.rule_id] = rule

        return list(seen.values())

    def _finding_to_result(self, finding: Finding) -> Dict[str, Any]:
        """Convert a single :class:`Finding` to a SARIF result object."""
        region: Dict[str, Any] = {
            "startLine": finding.location.line_start,
            "endLine": finding.location.line_end,
        }
        if finding.location.code_snippet:
            region["snippet"] = {"text": finding.location.code_snippet}

        sarif_result: Dict[str, Any] = {
            "ruleId": finding.rule_id,
            "level": _SEVERITY_TO_LEVEL.get(finding.severity, "warning"),
            "message": {"text": finding.description},
            "locations": [
                {
                    "physicalLocation": {
                        "artifactLocation": {
                            "uri": finding.location.file_path,
                            "uriBaseId": "%SRCROOT%",
                        },
                        "region": region,
                    }
                }
            ],
            "properties": {
                "severity": finding.severity.value,
                "engine": finding.engine,
            },
        }

        if finding.fix_suggestion:
            sarif_result["fixes"] = [
                {"description": {"text": finding.fix_suggestion}}
            ]

        return sarif_result
