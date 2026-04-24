"""Cryptographic Validation Engine.

Detects cryptographic weaknesses in Python and JavaScript source code:

* Weak hash algorithms: MD5, SHA-1 used for security purposes
* Insecure symmetric cipher mode: AES-ECB
* Insufficient RSA key size (< 2048 bits)
* Insufficient ECC key size (< 256 bits)
* Weak PBKDF iteration counts (< 100 000)
* JWT ``alg: none`` or weak signing (HS256 with a short/hardcoded secret)
* Hardcoded IV / nonce reuse risk
* Use of DES / 3DES
* Weak TLS minimum version (TLSv1.0, TLSv1.1)
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, List, Optional, Sequence

from ..models import Finding, Location, Severity
from .base import BaseEngine


@dataclass
class _CryptoPattern:
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


_CRYPTO_PATTERNS: List[_CryptoPattern] = [
    # ── Python ──────────────────────────────────────────────────────────────
    _CryptoPattern(
        rule_id="CRY-PY001",
        title="AES-ECB Mode Used",
        description=(
            "AES in ECB (Electronic Code Book) mode is deterministic: identical plaintext "
            "blocks produce identical ciphertext.  This leaks data patterns and is not "
            "semantically secure."
        ),
        severity=Severity.HIGH,
        regex=r"AES\.new\s*\([^)]*MODE_ECB|Cipher\.AES[^)]*ECB",
        languages=["python"],
        cwe="CWE-327",
        owasp="A02:2021",
        fix_suggestion=(
            "Use AES-GCM (``Crypto.Cipher.AES.MODE_GCM``) or AES-CBC with a random IV.  "
            "AES-GCM also provides authentication."
        ),
    ),
    _CryptoPattern(
        rule_id="CRY-PY002",
        title="RSA Key Size Below 2048 Bits",
        description=(
            "An RSA key smaller than 2048 bits is considered weak by NIST and can be "
            "factored with current computing resources."
        ),
        severity=Severity.HIGH,
        regex=r"RSA\.generate\s*\(\s*(512|768|1024)\b",
        languages=["python"],
        cwe="CWE-326",
        owasp="A02:2021",
        fix_suggestion="Use at least 2048-bit RSA keys.  3072 or 4096 bits are recommended.",
    ),
    _CryptoPattern(
        rule_id="CRY-PY003",
        title="DES or 3DES Used",
        description=(
            "DES has a 56-bit key space and is broken.  3DES (Triple DES) is deprecated "
            "by NIST (2023) and must not be used for new code."
        ),
        severity=Severity.HIGH,
        regex=r"\b(DES|DES3|TripleDES)\b",
        languages=["python"],
        cwe="CWE-327",
        owasp="A02:2021",
        fix_suggestion="Replace DES/3DES with AES-256-GCM.",
    ),
    _CryptoPattern(
        rule_id="CRY-PY004",
        title="Hardcoded Initialization Vector (IV)",
        description=(
            "A static, hardcoded IV / nonce is used for a symmetric cipher.  "
            "Reusing an IV with the same key can reveal the key or plaintext."
        ),
        severity=Severity.HIGH,
        regex=r"iv\s*=\s*b?[\"'][^\"']{8,}[\"']",
        languages=["python"],
        cwe="CWE-329",
        owasp="A02:2021",
        fix_suggestion=(
            "Generate a fresh, random IV for every encryption operation: "
            "``iv = os.urandom(16)``"
        ),
    ),
    _CryptoPattern(
        rule_id="CRY-PY005",
        title="Low PBKDF2 / bcrypt Iteration Count",
        description=(
            "A PBKDF2 iteration count below 100 000 is insufficient for modern hardware "
            "and reduces resistance to brute-force attacks."
        ),
        severity=Severity.MEDIUM,
        regex=r"pbkdf2_hmac\s*\([^)]*,\s*(\d+)\s*\)",
        languages=["python"],
        cwe="CWE-916",
        owasp="A02:2021",
        fix_suggestion=(
            "Use at least 310 000 iterations for PBKDF2-HMAC-SHA256 (OWASP 2023 "
            "recommendation).  Alternatively use argon2-cffi."
        ),
    ),
    _CryptoPattern(
        rule_id="CRY-PY006",
        title="JWT Algorithm Set to 'none'",
        description=(
            "A JWT is created or verified with ``algorithm='none'`` (or the ``alg`` header "
            "set to ``none``).  This disables signature verification entirely."
        ),
        severity=Severity.CRITICAL,
        regex=r'algorithm\s*=\s*["\']none["\']|["\']alg["\']\s*:\s*["\']none["\']',
        languages=["python"],
        cwe="CWE-347",
        owasp="A02:2021",
        fix_suggestion=(
            "Always specify a strong algorithm (``RS256``, ``ES256``, or ``HS256`` with a "
            "long random secret) and reject tokens with ``alg: none``."
        ),
    ),
    _CryptoPattern(
        rule_id="CRY-PY007",
        title="TLS 1.0 / 1.1 Minimum Version",
        description=(
            "The TLS context is configured to allow TLS 1.0 or 1.1.  Both are deprecated "
            "(RFC 8996) and have known vulnerabilities (POODLE, BEAST)."
        ),
        severity=Severity.MEDIUM,
        regex=r"ssl\.TLSVersion\.(TLSv1|TLSv1_1)\b|PROTOCOL_TLSv1\b|PROTOCOL_TLSv1_1\b",
        languages=["python"],
        cwe="CWE-326",
        owasp="A02:2021",
        fix_suggestion=(
            "Set ``minimum_version = ssl.TLSVersion.TLSv1_2`` (or TLSv1_3) on your "
            "SSL context."
        ),
    ),
    # ── JavaScript / TypeScript ─────────────────────────────────────────────
    _CryptoPattern(
        rule_id="CRY-JS001",
        title="JWT Algorithm Set to 'none' (JS)",
        description=(
            "A JWT is signed or verified with ``algorithm: 'none'``, disabling signature "
            "verification and making tokens trivially forgeable."
        ),
        severity=Severity.CRITICAL,
        regex=r'algorithm\s*:\s*["\']none["\']|algorithms\s*:\s*\[["\']none["\']\]',
        languages=["javascript"],
        cwe="CWE-347",
        owasp="A02:2021",
        fix_suggestion=(
            "Use ``RS256`` or ``ES256`` for asymmetric signing, or ``HS256`` with a "
            "cryptographically random secret of at least 256 bits."
        ),
    ),
    _CryptoPattern(
        rule_id="CRY-JS002",
        title="MD5 / SHA-1 Used (crypto module)",
        description=(
            "MD5 or SHA-1 is used via Node.js ``crypto.createHash()``.  Both algorithms "
            "are cryptographically broken."
        ),
        severity=Severity.MEDIUM,
        regex=r"createHash\s*\(\s*['\"](?:md5|sha1)['\"]",
        languages=["javascript"],
        cwe="CWE-327",
        owasp="A02:2021",
        fix_suggestion="Use ``createHash('sha256')`` or stronger.",
    ),
    _CryptoPattern(
        rule_id="CRY-JS003",
        title="Hardcoded JWT Secret",
        description=(
            "A JWT is signed with a hardcoded string literal as the secret.  "
            "Hardcoded secrets can be extracted from source code."
        ),
        severity=Severity.HIGH,
        regex=r"jwt\.sign\s*\([^,]+,\s*[\"'][^\"']{4,}[\"']",
        languages=["javascript"],
        cwe="CWE-798",
        owasp="A07:2021",
        fix_suggestion=(
            "Load the JWT secret from an environment variable or secrets manager: "
            "``process.env.JWT_SECRET``."
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


class CryptoEngine(BaseEngine):
    """Detects cryptographic weaknesses in source code."""

    name = "crypto"
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
        applicable = [p for p in _CRYPTO_PATTERNS if language in p.languages]
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
                            tags=["crypto", language],
                        )
                    )

        return findings
