"""Dependency scanning engine.

Parses common lockfile formats, queries the OSV and NVD APIs for known
CVEs, and emits :class:`~cyberguard.models.DependencyFinding` objects.

Supported lockfile formats
--------------------------
* ``requirements.txt`` (pip)
* ``Pipfile.lock`` (pipenv)
* ``pyproject.toml`` (PEP 621 / poetry)
* ``package-lock.json`` (npm v2/v3)
* ``yarn.lock`` (Yarn v1/v2)
* ``go.sum`` (Go modules)
* ``Gemfile.lock`` (Bundler)

For each dependency the engine:

1. Looks up known vulnerabilities via the OSV API.
2. Enriches HIGH/CRITICAL findings with CVSS data from NVD.
3. Produces an upgrade suggestion pointing to the first fixed version.
"""

from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Dict, List, Optional, Tuple

from ..models import DependencyFinding, Location, Severity
from ..services import nvd_client, osv_client
from .base import BaseEngine

# File names recognised as lockfiles / dependency manifests.
_LOCKFILE_NAMES = frozenset(
    {
        "requirements.txt",
        "Pipfile.lock",
        "pyproject.toml",
        "package-lock.json",
        "yarn.lock",
        "go.sum",
        "Gemfile.lock",
    }
)

# Map lockfile name → (parser function name, OSV ecosystem string)
_ECOSYSTEM_MAP: Dict[str, str] = {
    "requirements.txt": "PyPI",
    "Pipfile.lock": "PyPI",
    "pyproject.toml": "PyPI",
    "package-lock.json": "npm",
    "yarn.lock": "npm",
    "go.sum": "Go",
    "Gemfile.lock": "RubyGems",
}


def _parse_requirements_txt(text: str) -> List[Tuple[str, str]]:
    """Return [(name, version)] from a requirements.txt file."""
    deps: List[Tuple[str, str]] = []
    for line in text.splitlines():
        line = line.strip()
        if not line or line.startswith("#") or line.startswith("-"):
            continue
        # Match  name==version  or  name>=version  etc.
        m = re.match(r"^([A-Za-z0-9_.\-]+)\s*[=><~!]+\s*([^\s;#,]+)", line)
        if m:
            deps.append((m.group(1), m.group(2)))
    return deps


def _parse_pipfile_lock(text: str) -> List[Tuple[str, str]]:
    """Return [(name, version)] from a Pipfile.lock file."""
    deps: List[Tuple[str, str]] = []
    try:
        data = json.loads(text)
    except json.JSONDecodeError:
        return deps
    for section in ("default", "develop"):
        for name, info in data.get(section, {}).items():
            version = info.get("version", "").lstrip("=")
            if version:
                deps.append((name, version))
    return deps


def _parse_pyproject_toml(text: str) -> List[Tuple[str, str]]:
    """Return [(name, version)] from pyproject.toml dependencies."""
    deps: List[Tuple[str, str]] = []
    # Simple regex approach — avoids requiring a TOML parser dependency.
    for line in text.splitlines():
        line = line.strip().strip('"').strip("'").rstrip(",")
        m = re.match(r'^([A-Za-z0-9_.\-]+)\s*[=><~!^]+\s*([^\s"\']+)', line)
        if m:
            deps.append((m.group(1), m.group(2)))
    return deps


def _parse_package_lock_json(text: str) -> List[Tuple[str, str]]:
    """Return [(name, version)] from package-lock.json (npm v2/v3)."""
    deps: List[Tuple[str, str]] = []
    try:
        data = json.loads(text)
    except json.JSONDecodeError:
        return deps

    # npm v2/v3 uses "packages" key; v1 uses "dependencies"
    packages = data.get("packages") or data.get("dependencies") or {}
    for key, info in packages.items():
        if not isinstance(info, dict):
            continue
        name = key.lstrip("node_modules/") if key else info.get("name", "")
        if not name:
            continue
        version = info.get("version", "")
        if version:
            deps.append((name, version))
    return deps


def _parse_yarn_lock(text: str) -> List[Tuple[str, str]]:
    """Return [(name, version)] from a yarn.lock file."""
    deps: List[Tuple[str, str]] = []
    current_name: Optional[str] = None
    for line in text.splitlines():
        # Package header line: "lodash@^4.17.0, lodash@^4.17.21:"
        m_header = re.match(r'^"?([^@"]+)@[^:]+:', line)
        if m_header and not line.startswith(" ") and not line.startswith("#"):
            current_name = m_header.group(1)
        m_version = re.match(r'^\s+version\s+"?([^"]+)"?', line)
        if m_version and current_name:
            deps.append((current_name, m_version.group(1)))
            current_name = None
    return deps


def _parse_go_sum(text: str) -> List[Tuple[str, str]]:
    """Return [(module, version)] from a go.sum file."""
    seen: Dict[Tuple[str, str], bool] = {}
    deps: List[Tuple[str, str]] = []
    for line in text.splitlines():
        parts = line.split()
        if len(parts) < 2:
            continue
        module = parts[0]
        version = parts[1].split("/")[0].lstrip("v")  # strip /go.mod suffix and 'v' prefix
        key = (module, version)
        if key not in seen:
            seen[key] = True
            deps.append((module, version))
    return deps


def _parse_gemfile_lock(text: str) -> List[Tuple[str, str]]:
    """Return [(name, version)] from a Gemfile.lock."""
    deps: List[Tuple[str, str]] = []
    in_gems = False
    for line in text.splitlines():
        if line.strip() in ("GEM", "GEMS"):
            in_gems = True
            continue
        if in_gems and line and not line.startswith(" "):
            in_gems = False
        m = re.match(r"^\s{4}([A-Za-z0-9_.\-]+)\s+\(([^)]+)\)", line)
        if m:
            deps.append((m.group(1), m.group(2)))
    return deps


_PARSERS = {
    "requirements.txt": _parse_requirements_txt,
    "Pipfile.lock": _parse_pipfile_lock,
    "pyproject.toml": _parse_pyproject_toml,
    "package-lock.json": _parse_package_lock_json,
    "yarn.lock": _parse_yarn_lock,
    "go.sum": _parse_go_sum,
    "Gemfile.lock": _parse_gemfile_lock,
}


class DependencyEngine(BaseEngine):
    """Scans dependency manifest/lockfiles for known CVEs via OSV and NVD."""

    name = "dependency"
    # No file extension filter — we match by exact filename instead.
    supported_extensions: List[str] = []

    def can_scan(self, file_path: Path) -> bool:
        return file_path.name in _LOCKFILE_NAMES

    def scan_file(self, file_path: Path) -> List[DependencyFinding]:  # type: ignore[override]
        filename = file_path.name
        ecosystem = _ECOSYSTEM_MAP.get(filename, "PyPI")
        parser = _PARSERS.get(filename)
        if parser is None:
            return []

        try:
            text = file_path.read_text(encoding="utf-8", errors="replace")
        except OSError:
            return []

        packages = parser(text)
        findings: List[DependencyFinding] = []

        for pkg_name, pkg_version in packages:
            if not pkg_name or not pkg_version:
                continue
            vulns = osv_client.query_package(pkg_name, pkg_version, ecosystem)
            for vuln in vulns:
                finding = self._vuln_to_finding(
                    vuln, pkg_name, pkg_version, ecosystem, file_path
                )
                if finding:
                    findings.append(finding)

        return findings

    # ------------------------------------------------------------------
    # Private helpers
    # ------------------------------------------------------------------

    def _vuln_to_finding(
        self,
        vuln: dict,
        pkg_name: str,
        pkg_version: str,
        ecosystem: str,
        file_path: Path,
    ) -> Optional[DependencyFinding]:
        vuln_id: str = vuln.get("id", "")
        aliases: List[str] = vuln.get("aliases", [])
        cve_ids = [a for a in [vuln_id] + aliases if a.startswith("CVE-")]

        summary: str = vuln.get("summary") or vuln.get("details") or "Vulnerable dependency"
        details: str = vuln.get("details") or summary

        severity = self._osv_severity(vuln)
        fixed_version = osv_client.extract_fixed_version(vuln, ecosystem)

        # Enrich with NVD CVSS when we have a CVE ID
        cvss_score: Optional[float] = None
        cvss_vector: Optional[str] = None
        for cve_id in cve_ids:
            cve_data = nvd_client.get_cve(cve_id)
            if cve_data:
                cvss_score = nvd_client.extract_cvss_score(cve_data)
                cvss_vector = nvd_client.extract_cvss_vector(cve_data)
                if cvss_score is not None:
                    severity = self._cvss_to_severity(cvss_score)
                break

        if fixed_version:
            upgrade_cmd = self._upgrade_suggestion(pkg_name, fixed_version, ecosystem)
        else:
            upgrade_cmd = f"Update {pkg_name} to the latest version."

        rule_id = f"DEP-{vuln_id.replace('/', '-')}"

        return DependencyFinding(
            rule_id=rule_id,
            title=f"Vulnerable dependency: {pkg_name} {pkg_version}",
            description=f"{summary}\n\n{details}".strip(),
            severity=severity,
            location=Location(
                file_path=str(file_path),
                line_start=1,
                line_end=1,
            ),
            engine=self.name,
            cwe=self._extract_cwe(vuln),
            fix_suggestion=upgrade_cmd,
            tags=["dependency", ecosystem.lower()],
            cve_ids=cve_ids,
            cvss_score=cvss_score,
            cvss_vector=cvss_vector,
            package_name=pkg_name,
            installed_version=pkg_version,
            fixed_version=fixed_version,
            ecosystem=ecosystem,
        )

    @staticmethod
    def _osv_severity(vuln: dict) -> Severity:
        """Derive a Severity from OSV severity array or database_specific fields."""
        for entry in vuln.get("severity", []):
            score_str = entry.get("score", "")
            # CVSS vectors encode base score; try to extract
            m = re.search(r"CVSS:[\d.]+/[^/]+/[^/]+/[^/]+/[^/]+/[^/]+/([^/]+)", score_str)
            if m:
                try:
                    score = float(m.group(1))
                    return DependencyEngine._cvss_to_severity(score)
                except ValueError:
                    pass
        # Fall back to severity type string
        for entry in vuln.get("severity", []):
            t = entry.get("type", "").upper()
            if "CRITICAL" in t:
                return Severity.CRITICAL
            if "HIGH" in t:
                return Severity.HIGH
            if "MODERATE" in t or "MEDIUM" in t:
                return Severity.MEDIUM
            if "LOW" in t:
                return Severity.LOW
        return Severity.MEDIUM

    @staticmethod
    def _cvss_to_severity(score: float) -> Severity:
        if score >= 9.0:
            return Severity.CRITICAL
        if score >= 7.0:
            return Severity.HIGH
        if score >= 4.0:
            return Severity.MEDIUM
        if score > 0.0:
            return Severity.LOW
        return Severity.INFO

    @staticmethod
    def _extract_cwe(vuln: dict) -> Optional[str]:
        for db in vuln.get("database_specific", {}).values():
            if isinstance(db, str) and db.startswith("CWE-"):
                return db
        # Try top-level
        cwes = vuln.get("database_specific", {}).get("cwe_ids", [])
        if cwes:
            return cwes[0]
        return None

    @staticmethod
    def _upgrade_suggestion(name: str, fixed: str, ecosystem: str) -> str:
        if ecosystem == "PyPI":
            return f"Upgrade {name} to >= {fixed}:  pip install '{name}>={fixed}'"
        if ecosystem == "npm":
            return f"Upgrade {name} to >= {fixed}:  npm install {name}@{fixed}"
        if ecosystem == "Go":
            return f"Upgrade {name} to {fixed}:  go get {name}@v{fixed}"
        if ecosystem == "RubyGems":
            return f"Upgrade {name} to >= {fixed} in your Gemfile, then run: bundle update {name}"
        return f"Update {name} to >= {fixed}."
