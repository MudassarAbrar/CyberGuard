"""Tests for scanner orchestration."""

from __future__ import annotations

import pytest

from cyberguard.scanner import Scanner


class TestScanner:
    def test_scan_fixtures_dir(self, fixtures_dir):
        scanner = Scanner(use_bandit=True, use_pattern=True, use_ai=False, use_deps=False)
        result = scanner.scan(str(fixtures_dir))
        assert result.scanned_files >= 2  # vulnerable.py + vulnerable.js
        assert len(result.findings) > 0

    def test_engines_used_populated(self, fixtures_dir):
        scanner = Scanner(use_bandit=True, use_pattern=True, use_ai=False, use_deps=False)
        result = scanner.scan(str(fixtures_dir))
        assert "bandit" in result.engines_used
        assert "pattern" in result.engines_used

    def test_deduplication(self, vulnerable_py):
        # Both bandit and pattern may report the same location; duplicates
        # should be removed.
        scanner = Scanner(use_bandit=True, use_pattern=True, use_ai=False, use_deps=False)
        result = scanner.scan(str(vulnerable_py))
        keys = [
            (f.rule_id, f.location.file_path, f.location.line_start)
            for f in result.findings
        ]
        assert len(keys) == len(set(keys))

    def test_scan_duration_positive(self, fixtures_dir):
        scanner = Scanner(use_bandit=False, use_pattern=True, use_ai=False, use_deps=False)
        result = scanner.scan(str(fixtures_dir))
        assert result.scan_duration_ms >= 0

    def test_nonexistent_path_raises(self, tmp_path):
        scanner = Scanner(use_bandit=False, use_pattern=True, use_ai=False, use_deps=False)
        with pytest.raises(FileNotFoundError):
            scanner.scan(str(tmp_path / "no_such_path"))

    def test_only_pattern_engine(self, fixtures_dir):
        scanner = Scanner(use_bandit=False, use_pattern=True, use_ai=False, use_deps=False)
        result = scanner.scan(str(fixtures_dir))
        assert result.engines_used == ["pattern"]

    def test_target_path_is_absolute(self, fixtures_dir):
        scanner = Scanner(use_bandit=False, use_pattern=True, use_ai=False, use_deps=False)
        result = scanner.scan(str(fixtures_dir))
        assert result.target_path == str(fixtures_dir.resolve())
