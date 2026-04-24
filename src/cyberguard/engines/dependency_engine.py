"""Dependency scanning engine — parses lock files and queries the OSV database."""

from __future__ import annotations

import json
import re
import urllib.error
import urllib.request
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

from ..models import Finding, Location, Severity
from .base import BaseEngine

# OSV batch query endpoint.
_OSV_BATCH_URL = "https://api.osv.dev/v1/querybatch"

# Maximum dependencies per OSV batch request (OSV recommends ≤ 1000, but
# keeping smaller batches for reliability).
_BATCH_SIZE = 100

# Timeout for each HTTP request to the OSV API (seconds).
_HTTP_TIMEOUT = 15

# Lock / manifest files recognised by this engine (matched by filename).
_LOCK_FILE_NAMES: frozenset[str] = frozenset(
    {
        "requirements.txt",
        "requirements-dev.txt",
        "requirements-test.txt",
        "requirements-prod.txt",
        "package-lock.json",
        "yarn.lock",
        "Pipfile.lock",
        "poetry.lock",
        "go.sum",
    }
)


# ---------------------------------------------------------------------------
# Lock-file parsers
# ---------------------------------------------------------------------------


def _parse_requirements_txt(content: str) -> List[Tuple[str, str, str]]:
    """Parse a pip requirements file.

    Returns a list of ``(name, version, ecosystem)`` tuples for pinned packages
    (``==`` specifier only; unpinned entries are skipped).
    """
    deps: List[Tuple[str, str, str]] = []
    for raw in content.splitlines():
        line = raw.strip()
        if not line or line.startswith(("#", "-", "git+", "http")):
            continue
        # Strip inline comments and environment markers.
        line = re.split(r"\s*[;#]", line)[0].strip()
        match = re.match(r"^([A-Za-z0-9_\-\.]+)\s*==\s*([^\s,]+)", line)
        if match:
            deps.append((match.group(1), match.group(2), "PyPI"))
    return deps


def _parse_package_lock_json(content: str) -> List[Tuple[str, str, str]]:
    """Parse npm's ``package-lock.json`` (v1, v2, and v3 formats)."""
    try:
        data = json.loads(content)
    except json.JSONDecodeError:
        return []

    deps: List[Tuple[str, str, str]] = []

    # npm lockfileVersion 2/3 — packages dict keyed by "node_modules/<name>".
    for pkg_path, pkg_info in data.get("packages", {}).items():
        if not pkg_path:
            continue  # root package entry
        name = pkg_path.removeprefix("node_modules/").rsplit("node_modules/", 1)[-1]
        version = pkg_info.get("version", "")
        if name and version and not pkg_info.get("dev", False):
            deps.append((name, version, "npm"))

    # npm lockfileVersion 1 fallback.
    if not deps:
        for name, pkg_info in data.get("dependencies", {}).items():
            version = pkg_info.get("version", "")
            if name and version:
                deps.append((name, version, "npm"))

    return deps


def _parse_yarn_lock(content: str) -> List[Tuple[str, str, str]]:
    """Parse Yarn classic (v1) or berry (v2+) lock files."""
    deps: List[Tuple[str, str, str]] = []
    # Yarn lock format uses blocks like:  "pkg@^1.0.0":\n  version "1.2.3"
    for version_match in re.finditer(
        r'^"?([A-Za-z0-9@/_\-\.]+)@[^:]+:.*?\n\s+version\s+"([^"]+)"',
        content,
        re.MULTILINE | re.DOTALL,
    ):
        name = version_match.group(1).lstrip("@")
        # Restore scoped packages that had their leading @ stripped.
        raw_name = version_match.group(1)
        if raw_name.startswith("@"):
            name = raw_name
        version = version_match.group(2)
        deps.append((name, version, "npm"))

    return deps


def _parse_pipfile_lock(content: str) -> List[Tuple[str, str, str]]:
    """Parse Pipfile.lock."""
    try:
        data = json.loads(content)
    except json.JSONDecodeError:
        return []

    deps: List[Tuple[str, str, str]] = []
    for section in ("default", "develop"):
        for name, info in data.get(section, {}).items():
            version_spec = info.get("version", "")
            match = re.match(r"==(.+)", version_spec)
            if match:
                deps.append((name, match.group(1), "PyPI"))
    return deps


def _parse_poetry_lock(content: str) -> List[Tuple[str, str, str]]:
    """Parse poetry.lock (TOML format, parsed with simple regex)."""
    deps: List[Tuple[str, str, str]] = []
    # Each package block:
    # [[package]]
    # name = "requests"
    # version = "2.28.0"
    for block in re.split(r"\[\[package\]\]", content):
        name_m = re.search(r'^name\s*=\s*"([^"]+)"', block, re.MULTILINE)
        ver_m = re.search(r'^version\s*=\s*"([^"]+)"', block, re.MULTILINE)
        if name_m and ver_m:
            deps.append((name_m.group(1), ver_m.group(1), "PyPI"))
    return deps


def _parse_go_sum(content: str) -> List[Tuple[str, str, str]]:
    """Parse go.sum."""
    deps: List[Tuple[str, str, str]] = []
    seen: set[Tuple[str, str]] = set()
    for line in content.splitlines():
        line = line.strip()
        if not line:
            continue
        # Format: "module/path v1.2.3 h1:hash=" or "module/path v1.2.3/go.mod h1:hash="
        match = re.match(r"^(\S+)\s+v([^\s/]+)(?:/go\.mod)?\s+", line)
        if match:
            name, version = match.group(1), match.group(2)
            key = (name, version)
            if key not in seen:
                seen.add(key)
                deps.append((name, version, "Go"))
    return deps


# ---------------------------------------------------------------------------
# OSV API helpers
# ---------------------------------------------------------------------------


def _build_osv_queries(
    deps: List[Tuple[str, str, str]]
) -> List[Dict[str, Any]]:
    """Convert (name, version, ecosystem) tuples to OSV query objects."""
    return [
        {"package": {"name": name, "ecosystem": ecosystem}, "version": version}
        for name, version, ecosystem in deps
    ]


def _query_osv_batch(queries: List[Dict[str, Any]]) -> List[List[Dict[str, Any]]]:
    """Call the OSV batch query endpoint.

    Returns a list of result lists, one per input query (preserving order).
    Network or API errors return an empty list per failing query.
    """
    payload = json.dumps({"queries": queries}).encode()
    req = urllib.request.Request(
        _OSV_BATCH_URL,
        data=payload,
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    try:
        with urllib.request.urlopen(req, timeout=_HTTP_TIMEOUT) as resp:
            body = resp.read()
        data = json.loads(body)
    except (urllib.error.URLError, json.JSONDecodeError, OSError):
        return [[] for _ in queries]

    results = data.get("results", [])
    # Ensure we always return the same length as the input.
    output: List[List[Dict[str, Any]]] = []
    for entry in results:
        output.append(entry.get("vulns", []))
    # Pad if the API returned fewer results than expected.
    while len(output) < len(queries):
        output.append([])
    return output


# ---------------------------------------------------------------------------
# Severity helpers
# ---------------------------------------------------------------------------


def _cvss_vector_to_severity(vector: str) -> Optional[Severity]:
    """Heuristic: map a CVSS v3 vector string to a CyberGuard severity.

    This does not compute the full CVSS formula; instead it checks the
    most impactful metrics (Confidentiality / Integrity / Availability impact
    combined with Attack Vector and Privileges Required) to produce a
    directionally-correct severity bucket.
    """
    av_network = "/AV:N" in vector
    pr_none = "/PR:N" in vector
    ui_none = "/UI:N" in vector
    c_high = "/C:H" in vector
    i_high = "/I:H" in vector
    a_high = "/A:H" in vector

    high_impact = sum([c_high, i_high, a_high])

    if av_network and pr_none and ui_none and high_impact >= 2:
        return Severity.CRITICAL
    if av_network and high_impact >= 1:
        return Severity.HIGH
    if high_impact >= 1:
        return Severity.MEDIUM
    return Severity.LOW


def _osv_vuln_to_severity(vuln: Dict[str, Any]) -> Tuple[Severity, Optional[float], Optional[str]]:
    """Return ``(severity, cvss_score, cvss_vector)`` for an OSV vulnerability.

    Checks, in order:
    1. ``database_specific.severity`` string (e.g. "HIGH").
    2. ``severity[].type == "CVSS_V3"`` vector string.
    3. Presence of CVE aliases (→ HIGH default).
    4. Falls back to MEDIUM.
    """
    # --- database_specific.severity ---
    db_specific = vuln.get("database_specific", {})
    sev_str = str(db_specific.get("severity", "")).upper()
    sev_map = {
        "CRITICAL": Severity.CRITICAL,
        "HIGH": Severity.HIGH,
        "MODERATE": Severity.MEDIUM,
        "MEDIUM": Severity.MEDIUM,
        "LOW": Severity.LOW,
    }
    if sev_str in sev_map:
        # Still try to extract CVSS data for richer output.
        cvss_score, cvss_vec = _extract_cvss(vuln)
        return sev_map[sev_str], cvss_score, cvss_vec

    # --- CVSS_V3 vector ---
    cvss_score, cvss_vec = _extract_cvss(vuln)
    if cvss_vec:
        sev = _cvss_vector_to_severity(cvss_vec) or Severity.MEDIUM
        return sev, cvss_score, cvss_vec

    # --- CVE alias fallback ---
    aliases = vuln.get("aliases", [])
    if any(a.startswith("CVE-") for a in aliases):
        return Severity.HIGH, None, None

    return Severity.MEDIUM, None, None


def _extract_cvss(vuln: Dict[str, Any]) -> Tuple[Optional[float], Optional[str]]:
    """Return ``(cvss_base_score, cvss_vector)`` from an OSV vuln object."""
    for sev_entry in vuln.get("severity", []):
        if sev_entry.get("type") == "CVSS_V3":
            vec = sev_entry.get("score", "")
            if vec:
                # Some databases embed the numeric score in database_specific.
                db_score = vuln.get("database_specific", {}).get("cvss_score")
                score = float(db_score) if db_score is not None else None
                return score, vec
    return None, None


# ---------------------------------------------------------------------------
# Engine
# ---------------------------------------------------------------------------


class DependencyEngine(BaseEngine):
    """Scans dependency lock files and reports known CVEs via the OSV database.

    Supported files:
    * ``requirements.txt`` / ``requirements-*.txt`` (PyPI)
    * ``package-lock.json`` (npm)
    * ``yarn.lock`` (npm)
    * ``Pipfile.lock`` (PyPI)
    * ``poetry.lock`` (PyPI)
    * ``go.sum`` (Go)
    """

    name = "dependency"
    # No extension filtering — we match by filename in can_scan().
    supported_extensions: List[str] = []

    def can_scan(self, file_path: Path) -> bool:  # type: ignore[override]
        return file_path.name in _LOCK_FILE_NAMES

    # ------------------------------------------------------------------
    # BaseEngine interface
    # ------------------------------------------------------------------

    def scan_file(self, file_path: Path) -> List[Finding]:
        """Scan a single lock file for known-vulnerable dependencies."""
        try:
            content = file_path.read_text(encoding="utf-8", errors="replace")
        except OSError:
            return []

        deps = self._parse_lock_file(file_path.name, content)
        if not deps:
            return []

        return self._query_and_build_findings(deps, file_path)

    # ------------------------------------------------------------------
    # Private helpers
    # ------------------------------------------------------------------

    def _parse_lock_file(
        self, filename: str, content: str
    ) -> List[Tuple[str, str, str]]:
        """Dispatch to the appropriate parser based on *filename*."""
        if filename.startswith("requirements") and filename.endswith(".txt"):
            return _parse_requirements_txt(content)
        if filename == "package-lock.json":
            return _parse_package_lock_json(content)
        if filename == "yarn.lock":
            return _parse_yarn_lock(content)
        if filename == "Pipfile.lock":
            return _parse_pipfile_lock(content)
        if filename == "poetry.lock":
            return _parse_poetry_lock(content)
        if filename == "go.sum":
            return _parse_go_sum(content)
        return []

    def _query_and_build_findings(
        self,
        deps: List[Tuple[str, str, str]],
        lock_file: Path,
    ) -> List[Finding]:
        """Batch-query OSV and convert vulnerabilities to Finding objects."""
        findings: List[Finding] = []

        # Process in batches.
        for batch_start in range(0, len(deps), _BATCH_SIZE):
            batch = deps[batch_start : batch_start + _BATCH_SIZE]
            queries = _build_osv_queries(batch)
            try:
                results = _query_osv_batch(queries)
            except Exception:  # noqa: BLE001
                # Any unhandled network / parse error: skip this batch gracefully.
                results = [[] for _ in batch]

            for (name, version, ecosystem), vulns in zip(batch, results):
                for vuln in vulns:
                    finding = self._vuln_to_finding(vuln, name, version, lock_file)
                    if finding:
                        findings.append(finding)

        return findings

    def _vuln_to_finding(
        self,
        vuln: Dict[str, Any],
        pkg_name: str,
        pkg_version: str,
        lock_file: Path,
    ) -> Optional[Finding]:
        """Convert a single OSV vulnerability object to a Finding."""
        vuln_id = vuln.get("id", "UNKNOWN")
        aliases = vuln.get("aliases", [])
        cve_ids = [a for a in aliases if a.startswith("CVE-")]
        primary_cve = cve_ids[0] if cve_ids else None

        summary = vuln.get("summary", "") or vuln.get("details", "") or ""
        if not summary:
            summary = f"Known vulnerability in {pkg_name} {pkg_version}"

        severity, cvss_score, cvss_vector = _osv_vuln_to_severity(vuln)

        title = f"Vulnerable dependency: {pkg_name} {pkg_version}"
        description = (
            f"{summary}\n\n"
            f"Package: {pkg_name} {pkg_version}\n"
            f"Advisory: {vuln_id}"
        )
        if cve_ids:
            description += f"\nCVE: {', '.join(cve_ids)}"

        # Build a fix suggestion from affected ranges.
        fix_suggestion = self._build_fix_suggestion(vuln, pkg_name)

        tags = ["dependency", "osv"]
        if primary_cve:
            tags.append(primary_cve)

        return Finding(
            rule_id=f"DEP-{vuln_id}",
            title=title,
            description=description,
            severity=severity,
            location=Location(
                file_path=str(lock_file),
                line_start=1,
                line_end=1,
            ),
            engine=self.name,
            cwe=self._extract_cwe(vuln),
            cvss_score=cvss_score,
            cvss_vector=cvss_vector,
            fix_suggestion=fix_suggestion,
            tags=tags,
        )

    @staticmethod
    def _build_fix_suggestion(vuln: Dict[str, Any], pkg_name: str) -> Optional[str]:
        """Return a 'upgrade to version X' message when fix data is available."""
        fixed_versions: List[str] = []
        for affected in vuln.get("affected", []):
            for rng in affected.get("ranges", []):
                for event in rng.get("events", []):
                    fixed = event.get("fixed")
                    if fixed:
                        fixed_versions.append(fixed)
        if fixed_versions:
            return f"Upgrade {pkg_name} to version {fixed_versions[0]} or later."
        return f"Check the advisory for {pkg_name} and upgrade to a patched version."

    @staticmethod
    def _extract_cwe(vuln: Dict[str, Any]) -> Optional[str]:
        """Best-effort CWE extraction from OSV database_specific fields."""
        db = vuln.get("database_specific", {})
        cwe = db.get("cwe_ids") or db.get("cwe")
        if isinstance(cwe, list) and cwe:
            return str(cwe[0])
        if isinstance(cwe, str) and cwe:
            return cwe
        return None
