"""Tests for JSON and SARIF reporters."""

from __future__ import annotations

import json

from cyberguard.models import ScanResult
from cyberguard.reporters.json_reporter import JsonReporter
from cyberguard.reporters.sarif_reporter import SarifReporter


class TestJsonReporter:
    def setup_method(self):
        self.reporter = JsonReporter()

    def test_render_returns_valid_json(self, sample_scan_result):
        rendered = self.reporter.render(sample_scan_result)
        data = json.loads(rendered)
        assert isinstance(data, dict)

    def test_render_contains_findings(self, sample_scan_result):
        data = json.loads(self.reporter.render(sample_scan_result))
        assert len(data["findings"]) == 1
        assert data["findings"][0]["rule_id"] == "TEST-001"

    def test_render_empty_result(self):
        result = ScanResult(target_path="/tmp")
        data = json.loads(self.reporter.render(result))
        assert data["findings"] == []
        assert data["scanned_files"] == 0

    def test_write_to_file(self, tmp_path, sample_scan_result):
        out = tmp_path / "report.json"
        self.reporter.write(sample_scan_result, output_path=out)
        assert out.exists()
        data = json.loads(out.read_text())
        assert "findings" in data

    def test_scan_result_fields_present(self, sample_scan_result):
        data = json.loads(self.reporter.render(sample_scan_result))
        assert "scan_id" in data
        assert "target_path" in data
        assert "engines_used" in data
        assert "scanned_files" in data
        assert "scan_duration_ms" in data


class TestSarifReporter:
    def setup_method(self):
        self.reporter = SarifReporter()

    def test_render_returns_valid_json(self, sample_scan_result):
        rendered = self.reporter.render(sample_scan_result)
        json.loads(rendered)  # must not raise

    def test_sarif_schema_version(self, sample_scan_result):
        data = json.loads(self.reporter.render(sample_scan_result))
        assert data["version"] == "2.1.0"
        assert "$schema" in data

    def test_sarif_has_runs(self, sample_scan_result):
        data = json.loads(self.reporter.render(sample_scan_result))
        assert len(data["runs"]) == 1

    def test_tool_name_is_cyberguard(self, sample_scan_result):
        data = json.loads(self.reporter.render(sample_scan_result))
        assert data["runs"][0]["tool"]["driver"]["name"] == "CyberGuard"

    def test_results_count_matches_findings(self, sample_scan_result):
        data = json.loads(self.reporter.render(sample_scan_result))
        assert len(data["runs"][0]["results"]) == 1

    def test_rules_are_deduplicated(self, sample_scan_result):
        # Duplicate the finding — rules list should still have only 1 entry.
        f = sample_scan_result.findings[0]
        result_with_dupes = sample_scan_result.model_copy(
            update={"findings": [f, f.model_copy(update={"id": "other-id"})]}
        )
        data = json.loads(self.reporter.render(result_with_dupes))
        assert len(data["runs"][0]["tool"]["driver"]["rules"]) == 1

    def test_result_has_physical_location(self, sample_scan_result):
        data = json.loads(self.reporter.render(sample_scan_result))
        result = data["runs"][0]["results"][0]
        loc = result["locations"][0]["physicalLocation"]
        assert "artifactLocation" in loc
        assert "region" in loc

    def test_sarif_severity_levels(self, sample_scan_result):
        data = json.loads(self.reporter.render(sample_scan_result))
        result = data["runs"][0]["results"][0]
        # HIGH → "error" in SARIF
        assert result["level"] == "error"

    def test_write_to_file(self, tmp_path, sample_scan_result):
        out = tmp_path / "report.sarif"
        self.reporter.write(sample_scan_result, output_path=out)
        assert out.exists()
        data = json.loads(out.read_text())
        assert data["version"] == "2.1.0"

    def test_empty_result(self):
        result = ScanResult(target_path="/tmp")
        data = json.loads(self.reporter.render(result))
        assert data["runs"][0]["results"] == []
        assert data["runs"][0]["tool"]["driver"]["rules"] == []
