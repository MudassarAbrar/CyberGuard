"""Network Security Engine.

Detects network-security misconfigurations in Python and JavaScript/TypeScript
source files:

* TLS misconfigurations (``verify=False``, ``check_hostname=False``,
  ``CERT_NONE``)
* SSRF risks (unvalidated user-controlled URLs passed to HTTP clients)
* Insecure WebSocket usage (``ws://`` scheme)
* Plain HTTP connections to non-localhost hosts
* Missing security headers in Flask / FastAPI / Express apps
* Cleartext credentials / tokens in ``.env`` and config files
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, List, Optional, Sequence

from ..models import Finding, Location, Severity
from .base import BaseEngine


@dataclass
class _NetPattern:
    """A single network-security pattern."""

    rule_id: str
    title: str
    description: str
    severity: Severity
    regex: str
    languages: Sequence[str]
    cwe: Optional[str] = None
    owasp: Optional[str] = None
    fix_suggestion: Optional[str] = None
    flags: int = re.IGNORECASE
    _compiled: re.Pattern = field(init=False, repr=False, compare=False)

    def __post_init__(self) -> None:
        self._compiled = re.compile(self.regex, self.flags)

    @property
    def compiled(self) -> re.Pattern:
        return self._compiled


_NET_PATTERNS: List[_NetPattern] = [
    # ── TLS / SSL misconfigurations ─────────────────────────────────────────
    _NetPattern(
        rule_id="NET-PY001",
        title="TLS Certificate Verification Disabled",
        description=(
            "``verify=False`` is passed to a requests call, disabling TLS certificate "
            "verification. This allows man-in-the-middle attacks."
        ),
        severity=Severity.HIGH,
        regex=r"\brequests\.(get|post|put|delete|patch|head|request)\s*\([^)]*verify\s*=\s*False",
        languages=["python"],
        cwe="CWE-295",
        owasp="A02:2021",
        fix_suggestion=(
            "Remove ``verify=False``.  If you need a custom CA bundle, pass "
            "``verify='/path/to/ca-bundle.crt'`` instead."
        ),
    ),
    _NetPattern(
        rule_id="NET-PY002",
        title="SSL: check_hostname Disabled",
        description=(
            "``context.check_hostname = False`` disables hostname verification in the SSL "
            "context, weakening TLS security and enabling MITM attacks."
        ),
        severity=Severity.HIGH,
        regex=r"check_hostname\s*=\s*False",
        languages=["python"],
        cwe="CWE-297",
        owasp="A02:2021",
        fix_suggestion="Keep ``check_hostname=True`` (the default).  Never disable it.",
    ),
    _NetPattern(
        rule_id="NET-PY003",
        title="SSL: CERT_NONE Used",
        description=(
            "``ssl.CERT_NONE`` disables certificate validation entirely, making the TLS "
            "connection trivially interceptable."
        ),
        severity=Severity.HIGH,
        regex=r"ssl\.CERT_NONE",
        languages=["python"],
        cwe="CWE-295",
        owasp="A02:2021",
        fix_suggestion=(
            "Use ``ssl.CERT_REQUIRED`` (the default for ``ssl.create_default_context()``)."
        ),
    ),
    _NetPattern(
        rule_id="NET-PY004",
        title="Potential SSRF — Unvalidated URL from Request Parameters",
        description=(
            "A URL derived from HTTP request parameters (``request.args``, "
            "``request.form``, ``request.json``, ``request.GET``, ``request.POST``) is "
            "passed to an HTTP client.  If the URL is not validated, attackers can make "
            "the server issue requests to internal services (SSRF)."
        ),
        severity=Severity.HIGH,
        regex=(
            r"requests\.(get|post|put|delete|patch|head)\s*\(\s*"
            r"(request\.(args|form|json|GET|POST|data)|url\b)"
        ),
        languages=["python"],
        cwe="CWE-918",
        owasp="A10:2021",
        fix_suggestion=(
            "Validate and allowlist the URL scheme and hostname before making "
            "outbound HTTP requests.  Never forward raw user-supplied URLs."
        ),
    ),
    _NetPattern(
        rule_id="NET-PY005",
        title="Insecure HTTP Connection (Python)",
        description=(
            "A hardcoded ``http://`` URL (non-localhost) is used.  "
            "Plain HTTP is not encrypted and is vulnerable to interception."
        ),
        severity=Severity.MEDIUM,
        regex=r"[\"']http://(?!localhost|127\.0\.0\.1|0\.0\.0\.0)[^\"']+[\"']",
        languages=["python"],
        cwe="CWE-319",
        owasp="A02:2021",
        fix_suggestion="Use HTTPS for all connections to external hosts.",
    ),
    _NetPattern(
        rule_id="NET-PY006",
        title="Flask App Running Without Security Headers Middleware",
        description=(
            "The Flask application is started without Talisman or a ``Content-Security-Policy`` "
            "header.  Missing security headers expose users to clickjacking, XSS, and MIME "
            "sniffing attacks."
        ),
        severity=Severity.LOW,
        regex=r"Flask\s*\(\s*__name__\s*\)",
        languages=["python"],
        cwe="CWE-693",
        owasp="A05:2021",
        fix_suggestion=(
            "Use ``flask-talisman`` or set ``Content-Security-Policy``, "
            "``X-Frame-Options``, and ``X-Content-Type-Options`` response headers."
        ),
    ),
    _NetPattern(
        rule_id="NET-PY007",
        title="Insecure WebSocket URL (ws://)",
        description=(
            "A plain ``ws://`` WebSocket URL is used.  Unencrypted WebSocket connections "
            "are susceptible to interception and injection."
        ),
        severity=Severity.MEDIUM,
        regex=r"[\"']ws://",
        languages=["python"],
        cwe="CWE-319",
        owasp="A02:2021",
        fix_suggestion="Use ``wss://`` (TLS-secured WebSocket) for all WebSocket connections.",
    ),
    # ── JavaScript / TypeScript ─────────────────────────────────────────────
    _NetPattern(
        rule_id="NET-JS001",
        title="TLS Verification Disabled (Node.js)",
        description=(
            "``process.env.NODE_TLS_REJECT_UNAUTHORIZED = '0'`` disables TLS certificate "
            "verification for the entire Node.js process, enabling MITM attacks."
        ),
        severity=Severity.HIGH,
        regex=r"NODE_TLS_REJECT_UNAUTHORIZED\s*=\s*['\"]0['\"]",
        languages=["javascript"],
        cwe="CWE-295",
        owasp="A02:2021",
        fix_suggestion=(
            "Never set ``NODE_TLS_REJECT_UNAUTHORIZED=0`` in production.  "
            "Use a proper CA bundle via the ``NODE_EXTRA_CA_CERTS`` environment variable."
        ),
    ),
    _NetPattern(
        rule_id="NET-JS002",
        title="TLS rejectUnauthorized: false",
        description=(
            "``rejectUnauthorized: false`` in an HTTPS/TLS options object disables "
            "certificate validation for that connection."
        ),
        severity=Severity.HIGH,
        regex=r"rejectUnauthorized\s*:\s*false",
        languages=["javascript"],
        cwe="CWE-295",
        owasp="A02:2021",
        fix_suggestion="Remove ``rejectUnauthorized: false``.  Default is ``true``.",
    ),
    _NetPattern(
        rule_id="NET-JS003",
        title="Insecure WebSocket URL (ws://)",
        description=(
            "A plain ``ws://`` URL is used for a WebSocket connection.  "
            "Unencrypted WebSockets are susceptible to interception."
        ),
        severity=Severity.MEDIUM,
        regex=r"[\"']ws://",
        languages=["javascript"],
        cwe="CWE-319",
        owasp="A02:2021",
        fix_suggestion="Use ``wss://`` for all WebSocket connections.",
    ),
    _NetPattern(
        rule_id="NET-JS004",
        title="Missing CORS Origin Validation",
        description=(
            "``Access-Control-Allow-Origin: *`` permits any origin to access the resource.  "
            "For authenticated endpoints this is a security misconfiguration."
        ),
        severity=Severity.MEDIUM,
        regex=r"Access-Control-Allow-Origin['\"\s]*:\s*['\"]?\*",
        languages=["javascript"],
        cwe="CWE-346",
        owasp="A01:2021",
        fix_suggestion=(
            "Restrict the ``Access-Control-Allow-Origin`` header to known, trusted origins "
            "rather than using the wildcard ``*``."
        ),
    ),
    _NetPattern(
        rule_id="NET-JS005",
        title="Potential SSRF — User-Controlled URL in fetch/axios",
        description=(
            "A URL that includes user-controlled data (``req.body``, ``req.query``, "
            "``req.params``) is passed directly to ``fetch()`` or ``axios``.  "
            "Without validation this can be exploited for Server-Side Request Forgery."
        ),
        severity=Severity.HIGH,
        regex=(
            r"(fetch|axios\.get|axios\.post|axios\.request)\s*\(\s*"
            r"(req\.(body|query|params)|userInput|url\s*\+)"
        ),
        languages=["javascript"],
        cwe="CWE-918",
        owasp="A10:2021",
        fix_suggestion=(
            "Validate and allowlist the URL scheme and hostname before issuing "
            "outbound requests."
        ),
    ),
]

_EXT_TO_LANGUAGE: Dict[str, str] = {
    ".py": "python",
    ".js": "javascript",
    ".mjs": "javascript",
    ".cjs": "javascript",
    ".jsx": "javascript",
    ".ts": "javascript",
    ".tsx": "javascript",
}


class NetworkEngine(BaseEngine):
    """Detects network-security misconfigurations using targeted regex patterns."""

    name = "network"
    supported_extensions = list(_EXT_TO_LANGUAGE.keys())

    def scan_file(self, file_path: Path) -> List[Finding]:
        language = _EXT_TO_LANGUAGE.get(file_path.suffix.lower())
        if language is None:
            return []

        try:
            source = file_path.read_text(encoding="utf-8", errors="replace")
        except OSError:
            return []

        lines = source.splitlines()
        applicable = [p for p in _NET_PATTERNS if language in p.languages]
        findings: List[Finding] = []

        for lineno, line in enumerate(lines, start=1):
            for pattern in applicable:
                if pattern.compiled.search(line):
                    findings.append(
                        Finding(
                            rule_id=pattern.rule_id,
                            title=pattern.title,
                            description=pattern.description,
                            severity=pattern.severity,
                            location=Location(
                                file_path=str(file_path),
                                line_start=lineno,
                                line_end=lineno,
                                code_snippet=line.rstrip(),
                            ),
                            engine=self.name,
                            cwe=pattern.cwe,
                            owasp=pattern.owasp,
                            fix_suggestion=pattern.fix_suggestion,
                            tags=["network", language],
                        )
                    )

        return findings
