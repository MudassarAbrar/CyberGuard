"""Pytest fixtures shared across the test suite."""

from __future__ import annotations

from pathlib import Path

import pytest

from cyberguard.models import Finding, Location, ScanResult, Severity


@pytest.fixture
def fixtures_dir() -> Path:
    return Path(__file__).parent / "fixtures"


@pytest.fixture
def vulnerable_py(fixtures_dir: Path) -> Path:
    return fixtures_dir / "vulnerable.py"


@pytest.fixture
def vulnerable_js(fixtures_dir: Path) -> Path:
    return fixtures_dir / "vulnerable.js"


@pytest.fixture
def sample_finding() -> Finding:
    return Finding(
        rule_id="TEST-001",
        title="Test Finding",
        description="A test security finding.",
        severity=Severity.HIGH,
        location=Location(
            file_path="/tmp/test.py",
            line_start=10,
            line_end=10,
            code_snippet="eval(user_input)",
        ),
        engine="test",
        cwe="CWE-95",
        fix_suggestion="Do not use eval().",
    )


@pytest.fixture
def sample_scan_result(sample_finding: Finding) -> ScanResult:
    return ScanResult(
        target_path="/tmp/test",
        findings=[sample_finding],
        engines_used=["test"],
        scanned_files=1,
        scan_duration_ms=42.0,
    )
