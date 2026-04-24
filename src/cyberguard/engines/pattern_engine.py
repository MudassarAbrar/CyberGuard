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
    # ── Java ────────────────────────────────────────────────────────────────
    Pattern(
        rule_id="CG-JA001",
        title="SQL Injection via String Concatenation",
        description=(
            "A SQL query is built by concatenating a string with a variable. "
            "If the variable contains user input, SQL injection is possible. "
            "Use PreparedStatement with parameterized queries instead."
        ),
        severity=Severity.HIGH,
        regex=r'(createStatement|executeQuery|executeUpdate)\s*\([^)]*\+',
        languages=["java"],
        cwe="CWE-89",
        owasp="A03:2021",
        fix_suggestion=(
            "Replace Statement with PreparedStatement and use '?' placeholders "
            "instead of string concatenation."
        ),
    ),
    Pattern(
        rule_id="CG-JA002",
        title="Hardcoded Credential",
        description=(
            "A variable whose name suggests it holds a password, secret, or API key "
            "is assigned a string literal. Hardcoded credentials can be extracted from "
            "source code or version history."
        ),
        severity=Severity.HIGH,
        regex=r'(?i)(password|passwd|pwd|secret|apiKey|api_key|token|authToken)\s*=\s*"[^"]{4,}"',
        languages=["java"],
        cwe="CWE-259",
        owasp="A07:2021",
        fix_suggestion=(
            "Store secrets in environment variables or a secrets manager. "
            "Use System.getenv() or a vault integration. Never commit them to source."
        ),
    ),
    Pattern(
        rule_id="CG-JA003",
        title="OS Command Injection Risk",
        description=(
            "Runtime.exec() or ProcessBuilder is used with a string that includes "
            "concatenated user data. This may allow OS command injection."
        ),
        severity=Severity.HIGH,
        regex=r'(Runtime\.getRuntime\(\)\.exec|new\s+ProcessBuilder)\s*\([^)]*\+',
        languages=["java"],
        cwe="CWE-78",
        owasp="A03:2021",
        fix_suggestion=(
            "Pass command arguments as a String[] array to avoid shell interpretation. "
            "Validate and allowlist all external input before use."
        ),
    ),
    Pattern(
        rule_id="CG-JA004",
        title="Insecure Deserialization (ObjectInputStream)",
        description=(
            "ObjectInputStream.readObject() deserializes arbitrary Java objects. "
            "If the stream originates from an untrusted source, this enables "
            "remote code execution via gadget chains."
        ),
        severity=Severity.HIGH,
        regex=r'\bnew\s+ObjectInputStream\s*\(',
        languages=["java"],
        cwe="CWE-502",
        owasp="A08:2021",
        fix_suggestion=(
            "Avoid Java serialization for untrusted data. "
            "Use JSON/XML with strict schema validation, or apply a serialization filter "
            "(JEP 290) to restrict allowed classes."
        ),
    ),
    Pattern(
        rule_id="CG-JA005",
        title="Weak Cryptographic Hash (MD5 / SHA-1)",
        description=(
            "MD5 and SHA-1 are cryptographically broken and must not be used for "
            "password hashing, digital signatures, or integrity verification."
        ),
        severity=Severity.MEDIUM,
        regex=r'MessageDigest\.getInstance\s*\(\s*"(MD5|SHA-?1)"',
        languages=["java"],
        cwe="CWE-327",
        owasp="A02:2021",
        fix_suggestion=(
            "Use SHA-256 or stronger: MessageDigest.getInstance(\"SHA-256\"). "
            "For passwords, use BCrypt, SCrypt, or Argon2 via a security library."
        ),
    ),
    Pattern(
        rule_id="CG-JA006",
        title="XML External Entity (XXE) Risk",
        description=(
            "DocumentBuilderFactory, SAXParserFactory, or XMLInputFactory is used "
            "without explicitly disabling external entity and DTD processing, which "
            "may allow XXE attacks that expose local files or enable SSRF."
        ),
        severity=Severity.HIGH,
        regex=r'\b(DocumentBuilderFactory|SAXParserFactory|XMLInputFactory)\.newInstance\s*\(',
        languages=["java"],
        cwe="CWE-611",
        owasp="A05:2021",
        fix_suggestion=(
            "Disable external entities: "
            "factory.setFeature(\"http://apache.org/xml/features/disallow-doctype-decl\", true). "
            "Or use a safe XML library."
        ),
    ),
    Pattern(
        rule_id="CG-JA007",
        title="Insecure Random Number Generation (java.util.Random)",
        description=(
            "java.util.Random is not cryptographically secure. "
            "It must not be used for security-sensitive values such as tokens, "
            "nonces, session IDs, or cryptographic keys."
        ),
        severity=Severity.MEDIUM,
        regex=r'\bnew\s+Random\s*\(',
        languages=["java"],
        cwe="CWE-338",
        owasp="A02:2021",
        fix_suggestion=(
            "Use java.security.SecureRandom instead: new SecureRandom(). "
            "For UUID generation, use UUID.randomUUID()."
        ),
    ),
    Pattern(
        rule_id="CG-JA008",
        title="Potential Path Traversal",
        description=(
            "A File or Path object is constructed by concatenating a variable, "
            "which may allow path traversal (../../) if user input is involved."
        ),
        severity=Severity.MEDIUM,
        regex=r'new\s+File\s*\([^)]*\+|Paths\.get\s*\([^)]*\+',
        languages=["java"],
        cwe="CWE-22",
        owasp="A01:2021",
        fix_suggestion=(
            "Resolve and canonicalize the path with file.getCanonicalPath() "
            "and verify it starts with the expected base directory."
        ),
    ),
    Pattern(
        rule_id="CG-JA009",
        title="printStackTrace() Leaks Stack Trace",
        description=(
            "Calling e.printStackTrace() may expose internal implementation details, "
            "library versions, and file paths in production logs or error responses."
        ),
        severity=Severity.LOW,
        regex=r'\.printStackTrace\s*\(',
        languages=["java"],
        cwe="CWE-209",
        owasp="A05:2021",
        fix_suggestion=(
            "Use a structured logger (SLF4J / Logback / Log4j2) with "
            "logger.error(\"message\", e) instead of e.printStackTrace()."
        ),
    ),
    Pattern(
        rule_id="CG-JA010",
        title="Disabled SSL/TLS Certificate Validation",
        description=(
            "A TrustManager or HostnameVerifier that accepts all certificates is "
            "present. This disables TLS validation and exposes the application to "
            "man-in-the-middle attacks."
        ),
        severity=Severity.HIGH,
        regex=(
            r'(TrustManager|X509TrustManager|HostnameVerifier|ALLOW_ALL_HOSTNAME_VERIFIER)'
            r'.*?(checkClientTrusted|checkServerTrusted|verify)\s*\([^)]*\)\s*\{'
            r'|setDefaultHostnameVerifier\s*\(\s*SSLConnectionSocketFactory\.ALLOW_ALL'
        ),
        languages=["java"],
        cwe="CWE-295",
        owasp="A02:2021",
        fix_suggestion=(
            "Never override TLS validation. Use a valid CA-signed certificate and "
            "rely on the default trust managers."
        ),
    ),
    # ── Go ──────────────────────────────────────────────────────────────────
    Pattern(
        rule_id="CG-GO001",
        title="SQL Injection via String Formatting",
        description=(
            "A SQL query is built with fmt.Sprintf or string concatenation. "
            "If user-supplied data is embedded, this allows SQL injection."
        ),
        severity=Severity.HIGH,
        regex=r'(db\.(Query|Exec|QueryRow)|Sprintf)\s*\([^)]*\+|\bfmt\.Sprintf\s*\([^)]*SELECT',
        languages=["go"],
        cwe="CWE-89",
        owasp="A03:2021",
        fix_suggestion=(
            "Use parameterized queries with '?' or '$N' placeholders instead of "
            "fmt.Sprintf or string concatenation."
        ),
    ),
    Pattern(
        rule_id="CG-GO002",
        title="Hardcoded Credential",
        description=(
            "A variable whose name suggests it holds a password, secret, or API key "
            "is assigned a string literal. Hardcoded credentials can be extracted from "
            "source code or version history."
        ),
        severity=Severity.HIGH,
        regex=r'(?i)(password|passwd|pwd|secret|apiKey|api_key|token|authToken)\s*:?=\s*"[^"]{4,}"',
        languages=["go"],
        cwe="CWE-259",
        owasp="A07:2021",
        fix_suggestion=(
            "Read secrets from environment variables with os.Getenv() or a "
            "secrets manager. Never commit them to source."
        ),
    ),
    Pattern(
        rule_id="CG-GO003",
        title="OS Command Injection Risk",
        description=(
            "exec.Command is called with a shell interpreter (sh, bash, cmd) "
            "and a user-controlled string, which enables OS command injection."
        ),
        severity=Severity.HIGH,
        regex=r'exec\.Command\s*\(\s*"(sh|bash|cmd|/bin/sh|/bin/bash)"\s*,\s*"-c"',
        languages=["go"],
        cwe="CWE-78",
        owasp="A03:2021",
        fix_suggestion=(
            "Avoid shell invocation. Pass arguments directly to exec.Command "
            "without a shell intermediary, and validate all inputs."
        ),
    ),
    Pattern(
        rule_id="CG-GO004",
        title="Weak Cryptographic Hash (MD5 / SHA-1)",
        description=(
            "The crypto/md5 or crypto/sha1 package is imported. "
            "These algorithms are cryptographically broken and must not be used "
            "for security-sensitive purposes."
        ),
        severity=Severity.MEDIUM,
        regex=r'"crypto/(md5|sha1)"',
        languages=["go"],
        cwe="CWE-327",
        owasp="A02:2021",
        fix_suggestion=(
            "Use crypto/sha256 or crypto/sha512 instead. "
            "For passwords, use golang.org/x/crypto/bcrypt or argon2."
        ),
    ),
    Pattern(
        rule_id="CG-GO005",
        title="Insecure Random Number Generation (math/rand)",
        description=(
            "The math/rand package is not cryptographically secure. "
            "It must not be used for tokens, nonces, session IDs, or key material."
        ),
        severity=Severity.MEDIUM,
        regex=r'"math/rand"',
        languages=["go"],
        cwe="CWE-338",
        owasp="A02:2021",
        fix_suggestion=(
            "Use crypto/rand for cryptographically secure random data. "
            "For integer ranges, use crypto/rand with big.Int."
        ),
    ),
    Pattern(
        rule_id="CG-GO006",
        title="Potential Path Traversal",
        description=(
            "filepath.Join or os.Open is called with a variable that may include "
            "user-supplied data, potentially allowing path traversal attacks."
        ),
        severity=Severity.MEDIUM,
        regex=r'(os\.Open|os\.Create|ioutil\.ReadFile|os\.ReadFile)\s*\([^)]*\+',
        languages=["go"],
        cwe="CWE-22",
        owasp="A01:2021",
        fix_suggestion=(
            "Use filepath.Clean() and verify the cleaned path starts with the "
            "expected base directory before opening any file."
        ),
    ),
    Pattern(
        rule_id="CG-GO007",
        title="TLS Certificate Verification Disabled",
        description=(
            "InsecureSkipVerify: true disables TLS certificate validation, "
            "exposing the application to man-in-the-middle attacks."
        ),
        severity=Severity.HIGH,
        regex=r'InsecureSkipVerify\s*:\s*true',
        languages=["go"],
        cwe="CWE-295",
        owasp="A02:2021",
        fix_suggestion=(
            "Remove InsecureSkipVerify or set it to false. "
            "Use a valid CA certificate chain and rely on default TLS verification."
        ),
    ),
    Pattern(
        rule_id="CG-GO008",
        title="HTTP Server Without Timeouts",
        description=(
            "http.ListenAndServe or an http.Server is used without configuring "
            "ReadTimeout and WriteTimeout, making the server vulnerable to "
            "slow-loris and resource exhaustion attacks."
        ),
        severity=Severity.LOW,
        regex=r'http\.ListenAndServe\s*\(',
        languages=["go"],
        cwe="CWE-400",
        owasp="A05:2021",
        fix_suggestion=(
            "Use http.Server{ReadTimeout: ..., WriteTimeout: ...} "
            "instead of the convenience http.ListenAndServe function."
        ),
    ),
    Pattern(
        rule_id="CG-GO009",
        title="Unsafe Pointer Usage",
        description=(
            "The unsafe package is imported, allowing direct memory manipulation "
            "that bypasses Go's type safety and can cause security vulnerabilities."
        ),
        severity=Severity.MEDIUM,
        regex=r'"unsafe"',
        languages=["go"],
        cwe="CWE-119",
        owasp="A03:2021",
        fix_suggestion=(
            "Avoid the unsafe package unless absolutely necessary. "
            "Document the rationale and ensure thorough testing."
        ),
    ),
    Pattern(
        rule_id="CG-GO010",
        title="Hardcoded HTTP (Non-HTTPS) URL",
        description=(
            "A hardcoded HTTP (non-HTTPS) URL was detected. "
            "Connections over plain HTTP are unencrypted and susceptible to "
            "man-in-the-middle attacks."
        ),
        severity=Severity.LOW,
        regex=r'"http://(?!localhost|127\.0\.0\.1|0\.0\.0\.0)[^"]{4,}"',
        languages=["go"],
        cwe="CWE-319",
        owasp="A02:2021",
        fix_suggestion="Use HTTPS for all external connections.",
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
    ".java": "java",
    ".go": "go",
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
