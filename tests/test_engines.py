"""Tests for scan engines."""

from __future__ import annotations

from cyberguard.engines.bandit_engine import BanditEngine
from cyberguard.engines.pattern_engine import PatternEngine
from cyberguard.models import Severity


class TestPatternEngine:
    """PatternEngine has no external dependencies — test it directly."""

    def setup_method(self):
        self.engine = PatternEngine()

    def test_can_scan_python(self, vulnerable_py):
        assert self.engine.can_scan(vulnerable_py)

    def test_can_scan_javascript(self, vulnerable_js):
        assert self.engine.can_scan(vulnerable_js)

    def test_cannot_scan_unsupported_extension(self, tmp_path):
        binary = tmp_path / "image.png"
        binary.write_bytes(b"\x89PNG\r\n")
        assert not self.engine.can_scan(binary)

    def test_detects_hardcoded_credential_py(self, vulnerable_py):
        findings = self.engine.scan_file(vulnerable_py)
        rule_ids = [f.rule_id for f in findings]
        assert "CG-PY003" in rule_ids, "Should detect hardcoded credential in Python"

    def test_detects_eval_py(self, vulnerable_py):
        findings = self.engine.scan_file(vulnerable_py)
        rule_ids = [f.rule_id for f in findings]
        assert "CG-PY004" in rule_ids, "Should detect eval() in Python"

    def test_detects_weak_hash_py(self, vulnerable_py):
        findings = self.engine.scan_file(vulnerable_py)
        rule_ids = [f.rule_id for f in findings]
        assert "CG-PY006" in rule_ids, "Should detect weak hash (MD5/SHA1) in Python"

    def test_detects_insecure_random_py(self, vulnerable_py):
        findings = self.engine.scan_file(vulnerable_py)
        rule_ids = [f.rule_id for f in findings]
        assert "CG-PY007" in rule_ids, "Should detect insecure random in Python"

    def test_detects_command_injection_py(self, vulnerable_py):
        findings = self.engine.scan_file(vulnerable_py)
        rule_ids = [f.rule_id for f in findings]
        assert "CG-PY002" in rule_ids, "Should detect command injection in Python"

    def test_detects_pickle_py(self, vulnerable_py):
        findings = self.engine.scan_file(vulnerable_py)
        rule_ids = [f.rule_id for f in findings]
        assert "CG-PY005" in rule_ids, "Should detect insecure pickle in Python"

    def test_detects_eval_js(self, vulnerable_js):
        findings = self.engine.scan_file(vulnerable_js)
        rule_ids = [f.rule_id for f in findings]
        assert "CG-JS001" in rule_ids, "Should detect eval() in JavaScript"

    def test_detects_inner_html_js(self, vulnerable_js):
        findings = self.engine.scan_file(vulnerable_js)
        rule_ids = [f.rule_id for f in findings]
        assert "CG-JS002" in rule_ids, "Should detect innerHTML in JavaScript"

    def test_detects_hardcoded_credential_js(self, vulnerable_js):
        findings = self.engine.scan_file(vulnerable_js)
        rule_ids = [f.rule_id for f in findings]
        assert "CG-JS004" in rule_ids, "Should detect hardcoded credential in JavaScript"

    def test_detects_insecure_http_js(self, vulnerable_js):
        findings = self.engine.scan_file(vulnerable_js)
        rule_ids = [f.rule_id for f in findings]
        assert "CG-JS007" in rule_ids, "Should detect insecure HTTP URL in JavaScript"

    def test_detects_math_random_js(self, vulnerable_js):
        findings = self.engine.scan_file(vulnerable_js)
        rule_ids = [f.rule_id for f in findings]
        assert "CG-JS008" in rule_ids, "Should detect Math.random() in JavaScript"

    def test_finding_has_required_fields(self, vulnerable_py):
        findings = self.engine.scan_file(vulnerable_py)
        assert findings, "Expected at least one finding"
        f = findings[0]
        assert f.rule_id
        assert f.title
        assert f.description
        assert f.severity in list(Severity)
        assert f.location.file_path
        assert f.location.line_start >= 1
        assert f.engine == "pattern"

    def test_scan_path_directory(self, fixtures_dir):
        findings = self.engine.scan_path(fixtures_dir)
        rule_ids = {f.rule_id for f in findings}
        # Should pick up both Python and JS patterns
        assert any(r.startswith("CG-PY") for r in rule_ids)
        assert any(r.startswith("CG-JS") for r in rule_ids)

    def test_empty_file_returns_no_findings(self, tmp_path):
        empty = tmp_path / "empty.py"
        empty.write_text("")
        findings = self.engine.scan_file(empty)
        assert findings == []

    def test_clean_python_file_no_false_positives(self, tmp_path):
        clean = tmp_path / "clean.py"
        clean.write_text(
            "import hashlib\n"
            "def greet(name: str) -> str:\n"
            "    return f'Hello, {name}'\n"
        )
        findings = self.engine.scan_file(clean)
        rule_ids = [f.rule_id for f in findings]
        # None of the dangerous patterns should fire
        dangerous = {"CG-PY001", "CG-PY002", "CG-PY004", "CG-PY005"}
        assert not (dangerous & set(rule_ids))


class TestBanditEngine:
    """BanditEngine invokes bandit as a subprocess; test with the fixture file."""

    def setup_method(self):
        self.engine = BanditEngine()

    def test_engine_name(self):
        assert self.engine.name == "bandit"

    def test_supported_extensions(self):
        assert ".py" in self.engine.supported_extensions

    def test_cannot_scan_js(self, vulnerable_js):
        assert not self.engine.can_scan(vulnerable_js)

    def test_scan_vulnerable_python_file(self, vulnerable_py):
        findings = self.engine.scan_file(vulnerable_py)
        assert len(findings) > 0, "Bandit should find issues in the vulnerable fixture"

    def test_findings_have_bandit_rule_ids(self, vulnerable_py):
        findings = self.engine.scan_file(vulnerable_py)
        assert all(f.rule_id.startswith("bandit.") for f in findings)

    def test_findings_have_engine_name(self, vulnerable_py):
        findings = self.engine.scan_file(vulnerable_py)
        assert all(f.engine == "bandit" for f in findings)

    def test_nonexistent_file_returns_empty(self, tmp_path):
        missing = tmp_path / "no_such_file.py"
        findings = self.engine.scan_file(missing)
        assert findings == []

    def test_clean_python_returns_no_findings(self, tmp_path):
        clean = tmp_path / "clean.py"
        clean.write_text("def add(a, b):\n    return a + b\n")
        findings = self.engine.scan_file(clean)
        assert findings == []
