"""Regex-based pattern-matching engine covering Python and JavaScript."""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, List, Optional, Sequence

from ..models import Finding, Location, Severity
from .base import BaseEngine


@dataclass
class Pattern:
    """A single security pattern matched against source-code lines."""

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

    # Compiled regex is built lazily on first access.
    _compiled: re.Pattern = field(init=False, repr=False, compare=False)

    def __post_init__(self) -> None:
        self._compiled = re.compile(self.regex, self.flags)

    @property
    def compiled(self) -> re.Pattern:
        return self._compiled


# ---------------------------------------------------------------------------
# Pattern library
# ---------------------------------------------------------------------------

_PATTERNS: List[Pattern] = [
    # ── Python ──────────────────────────────────────────────────────────────
    Pattern(
        rule_id="CG-PY001",
        title="SQL Injection via String Formatting",
        description=(
            "A SQL query is constructed using string formatting or concatenation. "
            "If user-supplied data is embedded, this allows SQL injection attacks."
        ),
        severity=Severity.HIGH,
        regex=r"(execute|executemany)\s*\(\s*[\"\'f].*?(\+|%[sd]|\.format\(|f[\"'])",
        languages=["python"],
        cwe="CWE-89",
        owasp="A03:2021",
        fix_suggestion=(
            "Use parameterized queries with placeholders (?, %s) "
            "instead of string formatting."
        ),
    ),
    Pattern(
        rule_id="CG-PY002",
        title="OS Command Injection Risk",
        description=(
            "os.system() or subprocess with shell=True is used. "
            "If user input reaches this call it enables OS command injection."
        ),
        severity=Severity.HIGH,
        regex=r"os\.system\s*\(|subprocess\.(call|run|Popen|check_output)\s*\([^)]*shell\s*=\s*True",
        languages=["python"],
        cwe="CWE-78",
        owasp="A03:2021",
        fix_suggestion=(
            "Avoid shell=True. Pass arguments as a list to subprocess functions. "
            "Validate and sanitize all external input before use."
        ),
    ),
    Pattern(
        rule_id="CG-PY003",
        title="Hardcoded Credential",
        description=(
            "A variable whose name suggests it holds a password, secret, or API key "
            "is assigned a string literal. Hardcoded credentials can be extracted from "
            "source code or version history."
        ),
        severity=Severity.HIGH,
        regex=r"(?i)(password|passwd|pwd|secret|api_key|apikey|token|auth_token)\s*=\s*[\"'][^\"']{4,}[\"']",
        languages=["python"],
        cwe="CWE-259",
        owasp="A07:2021",
        fix_suggestion=(
            "Store secrets in environment variables or a dedicated secrets manager "
            "(e.g. AWS Secrets Manager, HashiCorp Vault). Never commit them to source."
        ),
    ),
    Pattern(
        rule_id="CG-PY004",
        title="Use of eval() / exec()",
        description=(
            "eval() or exec() can execute arbitrary Python code. "
            "When called with untrusted input this leads to remote code execution."
        ),
        severity=Severity.HIGH,
        regex=r"\b(eval|exec)\s*\(",
        languages=["python"],
        cwe="CWE-95",
        owasp="A03:2021",
        fix_suggestion=(
            "Use ast.literal_eval() for safe evaluation of simple expressions. "
            "Refactor to eliminate dynamic code execution wherever possible."
        ),
    ),
    Pattern(
        rule_id="CG-PY005",
        title="Insecure Deserialization (pickle)",
        description=(
            "pickle.loads() / pickle.load() can execute arbitrary code when "
            "deserializing data from an untrusted source."
        ),
        severity=Severity.HIGH,
        regex=r"\bpickle\.(loads?|Unpickler)\s*\(",
        languages=["python"],
        cwe="CWE-502",
        owasp="A08:2021",
        fix_suggestion=(
            "Use JSON or another safe format for untrusted data. "
            "If pickle is required, ensure the data source is fully trusted and signed."
        ),
    ),
    Pattern(
        rule_id="CG-PY006",
        title="Weak Cryptographic Hash (MD5 / SHA-1)",
        description=(
            "MD5 and SHA-1 are cryptographically broken. "
            "They must not be used for password hashing or data integrity verification."
        ),
        severity=Severity.MEDIUM,
        regex=r"hashlib\.(md5|sha1)\s*\(",
        languages=["python"],
        cwe="CWE-327",
        owasp="A02:2021",
        fix_suggestion=(
            "Use SHA-256 or stronger: hashlib.sha256(). "
            "For passwords, use bcrypt, scrypt, or argon2 via passlib."
        ),
    ),
    Pattern(
        rule_id="CG-PY007",
        title="Insecure Random Number Generation",
        description=(
            "The random module is not cryptographically secure and must not be used "
            "for security-sensitive purposes such as tokens, nonces, or session IDs."
        ),
        severity=Severity.MEDIUM,
        regex=r"\brandom\.(random|randint|choice|randrange|shuffle)\s*\(",
        languages=["python"],
        cwe="CWE-338",
        owasp="A02:2021",
        fix_suggestion=(
            "Use the secrets module: secrets.token_hex(), secrets.token_bytes(), "
            "or secrets.randbelow()."
        ),
    ),
    Pattern(
        rule_id="CG-PY008",
        title="Potential Path Traversal",
        description=(
            "A file path appears to be constructed from request or user-supplied data "
            "without sanitization, which may allow path traversal (../../) attacks."
        ),
        severity=Severity.MEDIUM,
        regex=r"open\s*\(\s*(request\.|input\(|os\.path\.join\([^)]*request\.)",
        languages=["python"],
        cwe="CWE-22",
        owasp="A01:2021",
        fix_suggestion=(
            "Resolve the path with os.path.realpath() and verify it starts with "
            "the expected base directory before opening."
        ),
    ),
    Pattern(
        rule_id="CG-PY009",
        title="XML External Entity (XXE) Risk",
        description=(
            "Standard XML parsers (xml.etree, lxml) enable external entity processing "
            "by default, which can expose local files or enable SSRF attacks."
        ),
        severity=Severity.MEDIUM,
        regex=r"xml\.etree\.ElementTree\.(parse|fromstring)|lxml\.etree\.(parse|fromstring)",
        languages=["python"],
        cwe="CWE-611",
        owasp="A05:2021",
        fix_suggestion=(
            "Use the defusedxml library for safe XML parsing, "
            "or explicitly disable external entity processing."
        ),
    ),
    Pattern(
        rule_id="CG-PY010",
        title="Debug Mode Enabled",
        description=(
            "debug=True is set, which may expose stack traces, environment variables, "
            "and an interactive debugger to end users in production."
        ),
        severity=Severity.LOW,
        regex=r"(?i)(app\.run|\.run)\s*\([^)]*\bDebug\s*=\s*True|\bDEBUG\s*=\s*True",
        languages=["python"],
        cwe="CWE-215",
        owasp="A05:2021",
        fix_suggestion=(
            "Disable debug mode in production. "
            "Control the setting via an environment variable."
        ),
    ),
    # ── JavaScript / TypeScript ─────────────────────────────────────────────
    Pattern(
        rule_id="CG-JS001",
        title="Use of eval()",
        description=(
            "eval() executes the string it receives as JavaScript code. "
            "If user-controlled data reaches eval(), this is a code injection vulnerability."
        ),
        severity=Severity.HIGH,
        regex=r"\beval\s*\(",
        languages=["javascript"],
        cwe="CWE-95",
        owasp="A03:2021",
        fix_suggestion=(
            "Avoid eval(). Use JSON.parse() for JSON data or refactor to eliminate "
            "dynamic code execution."
        ),
    ),
    Pattern(
        rule_id="CG-JS002",
        title="DOM-based XSS via innerHTML",
        description=(
            "Assigning to element.innerHTML renders HTML directly into the page. "
            "If the value originates from user input, this causes Cross-Site Scripting (XSS)."
        ),
        severity=Severity.HIGH,
        regex=r"\.innerHTML\s*=",
        languages=["javascript"],
        cwe="CWE-79",
        owasp="A03:2021",
        fix_suggestion=(
            "Use textContent instead of innerHTML for plain text, "
            "or sanitize HTML with DOMPurify before assignment."
        ),
    ),
    Pattern(
        rule_id="CG-JS003",
        title="document.write() Usage",
        description=(
            "document.write() can overwrite the entire page and introduce XSS "
            "when called with user-supplied data."
        ),
        severity=Severity.MEDIUM,
        regex=r"\bdocument\.write\s*\(",
        languages=["javascript"],
        cwe="CWE-79",
        owasp="A03:2021",
        fix_suggestion=(
            "Use DOM manipulation methods (createElement / appendChild) "
            "instead of document.write()."
        ),
    ),
    Pattern(
        rule_id="CG-JS004",
        title="Hardcoded Credential",
        description=(
            "A variable whose name suggests it holds a password, secret, or API key "
            "is assigned a string literal. Hardcoded credentials can be extracted from "
            "source code or version history."
        ),
        severity=Severity.HIGH,
        regex=r"(?i)(password|passwd|pwd|secret|api_key|apiKey|token|auth_token)\s*[=:]\s*[\"'][^\"']{4,}[\"']",
        languages=["javascript"],
        cwe="CWE-259",
        owasp="A07:2021",
        fix_suggestion=(
            "Store secrets in environment variables (process.env) "
            "or a secrets manager. Never commit them to source."
        ),
    ),
    Pattern(
        rule_id="CG-JS005",
        title="SQL Injection via String Concatenation",
        description=(
            "A SQL query is built by concatenating strings with a variable. "
            "If the variable contains user input, SQL injection is possible."
        ),
        severity=Severity.HIGH,
        regex=r"(?i)(SELECT|INSERT|UPDATE|DELETE|FROM|WHERE)\s+[^;\"'`]*[+]\s*[a-zA-Z_$\`]",
        languages=["javascript"],
        cwe="CWE-89",
        owasp="A03:2021",
        fix_suggestion=(
            "Use parameterized queries or an ORM "
            "instead of string concatenation."
        ),
    ),
    Pattern(
        rule_id="CG-JS006",
        title="OS Command Injection Risk",
        description=(
            "exec() / execSync() / spawn() is called with a string that includes "
            "a concatenated variable. If user-controlled data is present, "
            "OS command injection is possible."
        ),
        severity=Severity.HIGH,
        regex=r"\b(exec|execSync|spawn|spawnSync)\s*\([^)]*\+",
        languages=["javascript"],
        cwe="CWE-78",
        owasp="A03:2021",
        fix_suggestion=(
            "Use execFile() with a separate arguments array "
            "and never include user input directly in the command string."
        ),
    ),
    Pattern(
        rule_id="CG-JS007",
        title="Insecure HTTP Connection",
        description=(
            "A hardcoded HTTP (not HTTPS) URL was detected. "
            "Connections over plain HTTP are not encrypted and susceptible to "
            "man-in-the-middle attacks."
        ),
        severity=Severity.LOW,
        regex=r"[\"']http://(?!localhost|127\.0\.0\.1|0\.0\.0\.0)",
        languages=["javascript"],
        cwe="CWE-319",
        owasp="A02:2021",
        fix_suggestion="Use HTTPS for all external connections.",
    ),
    Pattern(
        rule_id="CG-JS008",
        title="Insecure Random Number Generation",
        description=(
            "Math.random() is not cryptographically secure and must not be used "
            "for tokens, nonces, session IDs, or other security-sensitive values."
        ),
        severity=Severity.MEDIUM,
        regex=r"\bMath\.random\s*\(",
        languages=["javascript"],
        cwe="CWE-338",
        owasp="A02:2021",
        fix_suggestion=(
            "Use crypto.getRandomValues() or crypto.randomUUID() "
            "for cryptographically secure random values."
        ),
    ),
    Pattern(
        rule_id="CG-JS009",
        title="Prototype Pollution Risk",
        description=(
            "Direct access to __proto__ or constructor.prototype can allow "
            "attackers to inject properties into Object.prototype (prototype pollution)."
        ),
        severity=Severity.MEDIUM,
        regex=r"\b(__proto__|constructor\s*\[\s*[\"']prototype[\"']\s*\])",
        languages=["javascript"],
        cwe="CWE-1321",
        owasp="A08:2021",
        fix_suggestion=(
            "Validate object keys against an allowlist. "
            "Use Object.create(null) for plain dictionaries. "
            "Avoid __proto__ assignments."
        ),
    ),
    Pattern(
        rule_id="CG-JS010",
        title="Dynamic require() Path",
        description=(
            "require() is called with a dynamically constructed path. "
            "If the path includes user-supplied data, an attacker may load "
            "arbitrary modules."
        ),
        severity=Severity.MEDIUM,
        regex=r"\brequire\s*\(\s*[^\"'`\)]+\s*\+",
        languages=["javascript"],
        cwe="CWE-706",
        owasp="A01:2021",
        fix_suggestion=(
            "Avoid dynamic require() calls. "
            "Use a static allowlist of permitted module names."
        ),
    ),
]

# Map file extension → language name used in pattern filtering.
_EXT_TO_LANGUAGE: Dict[str, str] = {
    ".py": "python",
    ".js": "javascript",
    ".mjs": "javascript",
    ".cjs": "javascript",
    ".jsx": "javascript",
    ".ts": "javascript",  # TypeScript shares most JS patterns
    ".tsx": "javascript",
}


class PatternEngine(BaseEngine):
    """Scans files by matching a library of regex patterns line-by-line."""

    name = "pattern"
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
        applicable = [p for p in _PATTERNS if language in p.languages]
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
                            tags=["pattern", language],
                        )
                    )

        return findings
