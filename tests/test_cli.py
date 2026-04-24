"""Tests for the CyberGuard CLI."""

from __future__ import annotations

import json

from typer.testing import CliRunner

from cyberguard.cli import app

runner = CliRunner()

# Flags used in every scan invocation to keep tests fast and network-free.
_NO_SLOW = ["--no-ai", "--no-deps"]


class TestScanCommand:
    def test_scan_json_output(self, fixtures_dir):
        result = runner.invoke(
            app,
            ["scan", str(fixtures_dir), "--format", "json", "--fail-on", "none"] + _NO_SLOW,
        )
        assert result.exit_code == 0, result.output
        data = json.loads(result.stdout)
        assert "findings" in data
        assert isinstance(data["findings"], list)

    def test_scan_sarif_output(self, fixtures_dir):
        result = runner.invoke(
            app,
            ["scan", str(fixtures_dir), "--format", "sarif", "--fail-on", "none"] + _NO_SLOW,
        )
        assert result.exit_code == 0, result.output
        data = json.loads(result.stdout)
        assert data["version"] == "2.1.0"

    def test_scan_finds_vulnerabilities_in_fixture(self, fixtures_dir):
        result = runner.invoke(
            app,
            ["scan", str(fixtures_dir), "--format", "json", "--fail-on", "none"] + _NO_SLOW,
        )
        assert result.exit_code == 0, result.output
        data = json.loads(result.stdout)
        assert len(data["findings"]) > 0

    def test_fail_on_high_exits_1_when_high_findings(self, fixtures_dir):
        result = runner.invoke(
            app,
            ["scan", str(fixtures_dir), "--format", "json", "--fail-on", "high"] + _NO_SLOW,
        )
        # The vulnerable fixtures contain HIGH findings → should exit 1
        assert result.exit_code == 1

    def test_fail_on_none_always_exits_0(self, fixtures_dir):
        result = runner.invoke(
            app,
            ["scan", str(fixtures_dir), "--format", "json", "--fail-on", "none"] + _NO_SLOW,
        )
        assert result.exit_code == 0

    def test_fail_on_critical_exits_0_when_no_critical(self, tmp_path):
        safe = tmp_path / "safe.py"
        safe.write_text("def add(a, b):\n    return a + b\n")
        result = runner.invoke(
            app,
            ["scan", str(safe), "--format", "json", "--fail-on", "critical"] + _NO_SLOW,
        )
        assert result.exit_code == 0

    def test_output_to_file(self, tmp_path, fixtures_dir):
        out = tmp_path / "report.json"
        result = runner.invoke(
            app,
            [
                "scan",
                str(fixtures_dir),
                "--format",
                "json",
                "--output",
                str(out),
                "--fail-on",
                "none",
            ]
            + _NO_SLOW,
        )
        assert result.exit_code == 0
        assert out.exists()
        data = json.loads(out.read_text())
        assert "findings" in data

    def test_invalid_format_exits_2(self, fixtures_dir):
        result = runner.invoke(
            app,
            ["scan", str(fixtures_dir), "--format", "xml"],
        )
        assert result.exit_code == 2

    def test_invalid_fail_on_exits_2(self, fixtures_dir):
        result = runner.invoke(
            app,
            ["scan", str(fixtures_dir), "--fail-on", "extreme"],
        )
        assert result.exit_code == 2

    def test_nonexistent_path_exits_nonzero(self, tmp_path):
        result = runner.invoke(
            app,
            ["scan", str(tmp_path / "nonexistent")],
        )
        assert result.exit_code != 0

    def test_version_flag(self):
        result = runner.invoke(app, ["--version"])
        assert result.exit_code == 0
        assert "CyberGuard" in result.output

    def test_no_pattern_skips_pattern_engine(self, fixtures_dir):
        result = runner.invoke(
            app,
            [
                "scan",
                str(fixtures_dir),
                "--format",
                "json",
                "--fail-on",
                "none",
                "--no-pattern",
            ]
            + _NO_SLOW,
        )
        assert result.exit_code == 0
        data = json.loads(result.stdout)
        # No pattern engine → no CG-PY* or CG-JS* findings
        rule_ids = [f["rule_id"] for f in data["findings"]]
        assert not any(r.startswith("CG-") for r in rule_ids)

    def test_quiet_mode(self, fixtures_dir):
        result = runner.invoke(
            app,
            [
                "scan",
                str(fixtures_dir),
                "--format",
                "json",
                "--fail-on",
                "none",
                "--quiet",
            ]
            + _NO_SLOW,
        )
        assert result.exit_code == 0
        # In quiet mode the output should still be valid JSON on stdout
        data = json.loads(result.stdout)
        assert "findings" in data

    def test_scan_single_python_file(self, vulnerable_py):
        result = runner.invoke(
            app,
            ["scan", str(vulnerable_py), "--format", "json", "--fail-on", "none"] + _NO_SLOW,
        )
        assert result.exit_code == 0
        data = json.loads(result.stdout)
        assert len(data["findings"]) > 0

    def test_scan_single_js_file(self, vulnerable_js):
        result = runner.invoke(
            app,
            [
                "scan",
                str(vulnerable_js),
                "--format",
                "json",
                "--fail-on",
                "none",
                "--no-bandit",
            ]
            + _NO_SLOW,
        )
        assert result.exit_code == 0
        data = json.loads(result.stdout)
        assert len(data["findings"]) > 0

    def test_no_deps_flag_accepted(self, fixtures_dir):
        result = runner.invoke(
            app,
            [
                "scan",
                str(fixtures_dir),
                "--format",
                "json",
                "--fail-on",
                "none",
                "--no-deps",
            ]
            + _NO_SLOW,
        )
        assert result.exit_code == 0
        data = json.loads(result.stdout)
        # Dependency engine disabled → no DEP-* findings
        rule_ids = [f["rule_id"] for f in data["findings"]]
        assert not any(r.startswith("DEP-") for r in rule_ids)
