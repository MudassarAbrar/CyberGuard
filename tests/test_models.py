"""Tests for CyberGuard data models."""

from __future__ import annotations

from cyberguard.models import SEVERITY_RANK, Finding, Location, ScanResult, Severity


class TestSeverity:
    def test_values_are_strings(self):
        assert Severity.HIGH == "high"
        assert Severity.CRITICAL == "critical"

    def test_rank_order(self):
        assert SEVERITY_RANK[Severity.CRITICAL] > SEVERITY_RANK[Severity.HIGH]
        assert SEVERITY_RANK[Severity.HIGH] > SEVERITY_RANK[Severity.MEDIUM]
        assert SEVERITY_RANK[Severity.MEDIUM] > SEVERITY_RANK[Severity.LOW]
        assert SEVERITY_RANK[Severity.LOW] > SEVERITY_RANK[Severity.INFO]


class TestFinding:
    def test_default_id_is_uuid(self, sample_finding):
        assert len(sample_finding.id) == 36  # UUID4 format

    def test_fields(self, sample_finding):
        assert sample_finding.rule_id == "TEST-001"
        assert sample_finding.severity == Severity.HIGH
        assert sample_finding.engine == "test"
        assert sample_finding.cwe == "CWE-95"


class TestScanResult:
    def test_findings_by_severity(self):
        findings = [
            Finding(
                rule_id="R1",
                title="T",
                description="D",
                severity=Severity.HIGH,
                location=Location(file_path="f.py", line_start=1, line_end=1),
                engine="e",
            ),
            Finding(
                rule_id="R2",
                title="T",
                description="D",
                severity=Severity.HIGH,
                location=Location(file_path="f.py", line_start=2, line_end=2),
                engine="e",
            ),
            Finding(
                rule_id="R3",
                title="T",
                description="D",
                severity=Severity.LOW,
                location=Location(file_path="f.py", line_start=3, line_end=3),
                engine="e",
            ),
        ]
        result = ScanResult(target_path="/tmp", findings=findings)
        counts = result.findings_by_severity()
        assert counts[Severity.HIGH] == 2
        assert counts[Severity.LOW] == 1
        assert counts[Severity.CRITICAL] == 0

    def test_highest_severity(self, sample_scan_result):
        assert sample_scan_result.highest_severity() == Severity.HIGH

    def test_highest_severity_empty(self):
        result = ScanResult(target_path="/tmp")
        assert result.highest_severity() is None

    def test_has_findings_at_or_above_true(self, sample_scan_result):
        assert sample_scan_result.has_findings_at_or_above(Severity.HIGH)
        assert sample_scan_result.has_findings_at_or_above(Severity.MEDIUM)
        assert sample_scan_result.has_findings_at_or_above(Severity.LOW)

    def test_has_findings_at_or_above_false(self, sample_scan_result):
        assert not sample_scan_result.has_findings_at_or_above(Severity.CRITICAL)

    def test_has_findings_at_or_above_empty(self):
        result = ScanResult(target_path="/tmp")
        assert not result.has_findings_at_or_above(Severity.INFO)
