"""Tests for scan engines."""

from __future__ import annotations

from pathlib import Path
from typing import Any, Dict
from unittest.mock import patch

import pytest

from cyberguard.engines.bandit_engine import BanditEngine
from cyberguard.engines.dependency_engine import (
    DependencyEngine,
    _parse_go_sum,
    _parse_package_lock_json,
    _parse_pipfile_lock,
    _parse_poetry_lock,
    _parse_requirements_txt,
)
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


# ---------------------------------------------------------------------------
# Java and Go pattern fixtures
# ---------------------------------------------------------------------------


@pytest.fixture
def vulnerable_java(fixtures_dir: Path) -> Path:
    return fixtures_dir / "vulnerable.java"


@pytest.fixture
def vulnerable_go(fixtures_dir: Path) -> Path:
    return fixtures_dir / "vulnerable.go"


@pytest.fixture
def requirements_txt(fixtures_dir: Path) -> Path:
    return fixtures_dir / "requirements.txt"


# ---------------------------------------------------------------------------
# Java pattern tests
# ---------------------------------------------------------------------------


class TestPatternEngineJava:
    """PatternEngine Java pattern tests."""

    def setup_method(self):
        self.engine = PatternEngine()

    def test_can_scan_java(self, vulnerable_java):
        assert self.engine.can_scan(vulnerable_java)

    def test_detects_sql_injection_java(self, vulnerable_java):
        findings = self.engine.scan_file(vulnerable_java)
        rule_ids = [f.rule_id for f in findings]
        assert "CG-JA001" in rule_ids, "Should detect SQL injection in Java"

    def test_detects_hardcoded_credential_java(self, vulnerable_java):
        findings = self.engine.scan_file(vulnerable_java)
        rule_ids = [f.rule_id for f in findings]
        assert "CG-JA002" in rule_ids, "Should detect hardcoded credential in Java"

    def test_detects_command_injection_java(self, vulnerable_java):
        findings = self.engine.scan_file(vulnerable_java)
        rule_ids = [f.rule_id for f in findings]
        assert "CG-JA003" in rule_ids, "Should detect command injection in Java"

    def test_detects_insecure_deserialization_java(self, vulnerable_java):
        findings = self.engine.scan_file(vulnerable_java)
        rule_ids = [f.rule_id for f in findings]
        assert "CG-JA004" in rule_ids, "Should detect insecure deserialization in Java"

    def test_detects_weak_hash_java(self, vulnerable_java):
        findings = self.engine.scan_file(vulnerable_java)
        rule_ids = [f.rule_id for f in findings]
        assert "CG-JA005" in rule_ids, "Should detect weak hash (MD5/SHA-1) in Java"

    def test_detects_xxe_java(self, vulnerable_java):
        findings = self.engine.scan_file(vulnerable_java)
        rule_ids = [f.rule_id for f in findings]
        assert "CG-JA006" in rule_ids, "Should detect XXE risk in Java"

    def test_detects_insecure_random_java(self, vulnerable_java):
        findings = self.engine.scan_file(vulnerable_java)
        rule_ids = [f.rule_id for f in findings]
        assert "CG-JA007" in rule_ids, "Should detect insecure random in Java"

    def test_detects_stack_trace_java(self, vulnerable_java):
        findings = self.engine.scan_file(vulnerable_java)
        rule_ids = [f.rule_id for f in findings]
        assert "CG-JA009" in rule_ids, "Should detect printStackTrace in Java"

    def test_java_findings_have_correct_engine(self, vulnerable_java):
        findings = self.engine.scan_file(vulnerable_java)
        assert all(f.engine == "pattern" for f in findings)

    def test_java_findings_have_cwe(self, vulnerable_java):
        findings = self.engine.scan_file(vulnerable_java)
        cwe_findings = [f for f in findings if f.cwe]
        assert len(cwe_findings) > 0, "Java findings should carry CWE references"


# ---------------------------------------------------------------------------
# Go pattern tests
# ---------------------------------------------------------------------------


class TestPatternEngineGo:
    """PatternEngine Go pattern tests."""

    def setup_method(self):
        self.engine = PatternEngine()

    def test_can_scan_go(self, vulnerable_go):
        assert self.engine.can_scan(vulnerable_go)

    def test_detects_hardcoded_credential_go(self, vulnerable_go):
        findings = self.engine.scan_file(vulnerable_go)
        rule_ids = [f.rule_id for f in findings]
        assert "CG-GO002" in rule_ids, "Should detect hardcoded credential in Go"

    def test_detects_command_injection_go(self, vulnerable_go):
        findings = self.engine.scan_file(vulnerable_go)
        rule_ids = [f.rule_id for f in findings]
        assert "CG-GO003" in rule_ids, "Should detect command injection in Go"

    def test_detects_weak_hash_go(self, vulnerable_go):
        findings = self.engine.scan_file(vulnerable_go)
        rule_ids = [f.rule_id for f in findings]
        assert "CG-GO004" in rule_ids, "Should detect weak hash (MD5) import in Go"

    def test_detects_insecure_random_go(self, vulnerable_go):
        findings = self.engine.scan_file(vulnerable_go)
        rule_ids = [f.rule_id for f in findings]
        assert "CG-GO005" in rule_ids, "Should detect math/rand import in Go"

    def test_detects_tls_skip_verify_go(self, vulnerable_go):
        findings = self.engine.scan_file(vulnerable_go)
        rule_ids = [f.rule_id for f in findings]
        assert "CG-GO007" in rule_ids, "Should detect InsecureSkipVerify in Go"

    def test_detects_insecure_http_go(self, vulnerable_go):
        findings = self.engine.scan_file(vulnerable_go)
        rule_ids = [f.rule_id for f in findings]
        assert "CG-GO010" in rule_ids, "Should detect hardcoded HTTP URL in Go"

    def test_detects_unsafe_package_go(self, vulnerable_go):
        findings = self.engine.scan_file(vulnerable_go)
        rule_ids = [f.rule_id for f in findings]
        assert "CG-GO009" in rule_ids, "Should detect unsafe package import in Go"

    def test_detects_listen_without_timeout_go(self, vulnerable_go):
        findings = self.engine.scan_file(vulnerable_go)
        rule_ids = [f.rule_id for f in findings]
        assert "CG-GO008" in rule_ids, "Should detect http.ListenAndServe in Go"

    def test_go_findings_have_correct_engine(self, vulnerable_go):
        findings = self.engine.scan_file(vulnerable_go)
        assert all(f.engine == "pattern" for f in findings)

    def test_scan_path_picks_up_all_languages(self, fixtures_dir):
        findings = self.engine.scan_path(fixtures_dir)
        rule_ids = {f.rule_id for f in findings}
        assert any(r.startswith("CG-PY") for r in rule_ids)
        assert any(r.startswith("CG-JS") for r in rule_ids)
        assert any(r.startswith("CG-JA") for r in rule_ids)
        assert any(r.startswith("CG-GO") for r in rule_ids)


# ---------------------------------------------------------------------------
# Dependency engine — parser unit tests
# ---------------------------------------------------------------------------


class TestDependencyParsers:
    """Unit-test the lock-file parsers without any network calls."""

    def test_parse_requirements_txt_pinned(self):
        content = "requests==2.28.0\nurllib3==1.26.14\n"
        deps = _parse_requirements_txt(content)
        assert ("requests", "2.28.0", "PyPI") in deps
        assert ("urllib3", "1.26.14", "PyPI") in deps

    def test_parse_requirements_txt_skips_unpinned(self):
        content = "requests>=2.0.0\nurllib3\n"
        deps = _parse_requirements_txt(content)
        assert deps == []

    def test_parse_requirements_txt_skips_comments(self):
        content = "# This is a comment\nrequests==2.28.0\n"
        deps = _parse_requirements_txt(content)
        assert len(deps) == 1
        assert deps[0][0] == "requests"

    def test_parse_requirements_txt_strips_env_markers(self):
        content = 'requests==2.28.0; python_version >= "3.6"\n'
        deps = _parse_requirements_txt(content)
        assert len(deps) == 1
        assert deps[0] == ("requests", "2.28.0", "PyPI")

    def test_parse_package_lock_v1(self):
        data = {
            "dependencies": {
                "lodash": {"version": "4.17.20"},
                "express": {"version": "4.18.2"},
            }
        }
        import json

        deps = _parse_package_lock_json(json.dumps(data))
        assert ("lodash", "4.17.20", "npm") in deps
        assert ("express", "4.18.2", "npm") in deps

    def test_parse_package_lock_v2(self):
        data = {
            "packages": {
                "": {},  # root — should be skipped
                "node_modules/lodash": {"version": "4.17.20"},
                "node_modules/express": {"version": "4.18.2"},
            }
        }
        import json

        deps = _parse_package_lock_json(json.dumps(data))
        assert ("lodash", "4.17.20", "npm") in deps
        assert ("express", "4.18.2", "npm") in deps

    def test_parse_package_lock_invalid_json(self):
        deps = _parse_package_lock_json("not valid json")
        assert deps == []

    def test_parse_pipfile_lock(self):
        data = {
            "default": {
                "requests": {"version": "==2.28.0"},
                "certifi": {"version": "==2023.7.22"},
            },
            "develop": {
                "pytest": {"version": "==7.4.0"},
            },
        }
        import json

        deps = _parse_pipfile_lock(json.dumps(data))
        names = {d[0] for d in deps}
        assert "requests" in names
        assert "certifi" in names
        assert "pytest" in names

    def test_parse_go_sum(self):
        content = (
            "github.com/pkg/errors v0.9.1 h1:abc=\n"
            "github.com/pkg/errors v0.9.1/go.mod h1:def=\n"
            "golang.org/x/net v0.14.0 h1:xyz=\n"
        )
        deps = _parse_go_sum(content)
        names = {d[0] for d in deps}
        assert "github.com/pkg/errors" in names
        assert "golang.org/x/net" in names
        # go.mod entries should be deduplicated — only one entry per module@version
        errors_entries = [d for d in deps if d[0] == "github.com/pkg/errors"]
        assert len(errors_entries) == 1

    def test_parse_poetry_lock(self):
        content = (
            "[[package]]\n"
            'name = "requests"\n'
            'version = "2.28.0"\n'
            "\n"
            "[[package]]\n"
            'name = "urllib3"\n'
            'version = "1.26.14"\n'
        )
        deps = _parse_poetry_lock(content)
        assert ("requests", "2.28.0", "PyPI") in deps
        assert ("urllib3", "1.26.14", "PyPI") in deps


# ---------------------------------------------------------------------------
# Dependency engine — integration tests (network mocked)
# ---------------------------------------------------------------------------


class TestDependencyEngine:
    """Tests for DependencyEngine that mock out OSV network calls."""

    def setup_method(self):
        self.engine = DependencyEngine()

    def test_engine_name(self):
        assert self.engine.name == "dependency"

    def test_can_scan_requirements_txt(self, tmp_path):
        req = tmp_path / "requirements.txt"
        req.write_text("requests==2.28.0\n")
        assert self.engine.can_scan(req)

    def test_can_scan_package_lock_json(self, tmp_path):
        pkg = tmp_path / "package-lock.json"
        pkg.write_text("{}")
        assert self.engine.can_scan(pkg)

    def test_cannot_scan_python_file(self, vulnerable_py):
        assert not self.engine.can_scan(vulnerable_py)

    def test_cannot_scan_arbitrary_txt(self, tmp_path):
        notes = tmp_path / "notes.txt"
        notes.write_text("hello")
        assert not self.engine.can_scan(notes)

    def test_empty_requirements_returns_no_findings(self, tmp_path):
        req = tmp_path / "requirements.txt"
        req.write_text("# no pinned deps\n")
        findings = self.engine.scan_file(req)
        assert findings == []

    def test_network_failure_returns_empty(self, tmp_path):
        """OSV API failure should not raise; it should return an empty list."""
        req = tmp_path / "requirements.txt"
        req.write_text("requests==2.28.0\n")

        import urllib.error

        with patch(
            "cyberguard.engines.dependency_engine._query_osv_batch",
            side_effect=urllib.error.URLError("simulated network error"),
        ):
            findings = self.engine.scan_file(req)
        assert findings == []

    def test_osv_vulnerability_is_converted_to_finding(self, tmp_path):
        """When OSV returns a vuln, it should be represented as a Finding."""
        req = tmp_path / "requirements.txt"
        req.write_text("urllib3==1.24.1\n")

        mock_vuln: Dict[str, Any] = {
            "id": "PYSEC-2019-132",
            "summary": "CRLF injection in urllib3",
            "aliases": ["CVE-2019-11324"],
            "database_specific": {"severity": "HIGH"},
            "affected": [
                {
                    "ranges": [
                        {"events": [{"fixed": "1.24.2"}]},
                    ]
                }
            ],
        }

        with patch(
            "cyberguard.engines.dependency_engine._query_osv_batch",
            return_value=[[mock_vuln]],
        ):
            findings = self.engine.scan_file(req)

        assert len(findings) == 1
        f = findings[0]
        assert f.rule_id == "DEP-PYSEC-2019-132"
        assert f.severity == Severity.HIGH
        assert f.engine == "dependency"
        assert "urllib3" in f.title
        assert f.fix_suggestion is not None
        assert "1.24.2" in (f.fix_suggestion or "")

    def test_finding_includes_cve_tag(self, tmp_path):
        req = tmp_path / "requirements.txt"
        req.write_text("urllib3==1.24.1\n")

        mock_vuln: Dict[str, Any] = {
            "id": "PYSEC-TEST-001",
            "summary": "Test vulnerability",
            "aliases": ["CVE-2019-99999"],
            "database_specific": {"severity": "MEDIUM"},
            "affected": [],
        }

        with patch(
            "cyberguard.engines.dependency_engine._query_osv_batch",
            return_value=[[mock_vuln]],
        ):
            findings = self.engine.scan_file(req)

        assert findings
        assert "CVE-2019-99999" in findings[0].tags

    def test_cvss_vector_stored_on_finding(self, tmp_path):
        req = tmp_path / "requirements.txt"
        req.write_text("requests==2.25.0\n")

        vector = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
        mock_vuln: Dict[str, Any] = {
            "id": "PYSEC-TEST-002",
            "summary": "Remote code execution",
            "aliases": [],
            "severity": [{"type": "CVSS_V3", "score": vector}],
            "database_specific": {},
            "affected": [],
        }

        with patch(
            "cyberguard.engines.dependency_engine._query_osv_batch",
            return_value=[[mock_vuln]],
        ):
            findings = self.engine.scan_file(req)

        assert findings
        assert findings[0].cvss_vector == vector
        assert findings[0].severity == Severity.CRITICAL

    def test_scan_path_finds_lock_files(self, tmp_path):
        """scan_path should discover and scan lock files in a directory."""
        req = tmp_path / "requirements.txt"
        req.write_text("requests==2.28.0\n")

        mock_vuln: Dict[str, Any] = {
            "id": "PYSEC-TEST-003",
            "summary": "Test",
            "aliases": ["CVE-2023-99999"],
            "database_specific": {"severity": "LOW"},
            "affected": [],
        }

        with patch(
            "cyberguard.engines.dependency_engine._query_osv_batch",
            return_value=[[mock_vuln]],
        ):
            findings = self.engine.scan_path(tmp_path)

        assert any(f.engine == "dependency" for f in findings)

