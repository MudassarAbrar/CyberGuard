"""MITRE ATT&CK mapping client.

Provides a static CWE → MITRE ATT&CK technique mapping used by the
Predictive Attack Engine.  The mapping is derived from published ATT&CK
relationships and NVD CWE data.

Only the most commonly exploited CWEs are mapped here; the mapping is
intentionally conservative to avoid false associations.
"""

from __future__ import annotations

from typing import Dict, List

# CWE ID (without "CWE-" prefix) → list of ATT&CK Technique IDs
# Source: MITRE ATT&CK v14 + NVD CWE mappings
_CWE_TO_ATTACK: Dict[str, List[str]] = {
    # Injection
    "89": ["T1190"],   # SQL Injection → Exploit Public-Facing Application
    "78": ["T1059"],   # OS Command Injection → Command and Scripting Interpreter
    "77": ["T1059"],   # Command Injection
    "94": ["T1059"],   # Code Injection
    "95": ["T1059"],   # Eval Injection
    "79": ["T1059.007"],  # XSS → JavaScript
    "611": ["T1190"],  # XXE → Exploit Public-Facing Application
    "918": ["T1190"],  # SSRF
    # Authentication & Access Control
    "287": ["T1078"],  # Improper Authentication → Valid Accounts
    "306": ["T1078"],  # Missing Authentication
    "285": ["T1078"],  # Improper Authorization
    "269": ["T1068"],  # Privilege Escalation
    "284": ["T1068"],  # Improper Access Control
    # Cryptography
    "327": ["T1600"],  # Weak Crypto → Weaken Encryption
    "326": ["T1600"],  # Inadequate Encryption Strength
    "330": ["T1600"],  # Insufficient Random Values
    "338": ["T1600"],  # Insecure PRNG
    "261": ["T1552"],  # Weak Password Encoding
    # Secrets & Credentials
    "259": ["T1552.001"],  # Hardcoded Password → Credentials In Files
    "798": ["T1552.001"],  # Hard-coded Credentials
    "312": ["T1552"],  # Cleartext Storage of Sensitive Information
    "319": ["T1040"],  # Cleartext Transmission → Network Sniffing
    # Deserialization
    "502": ["T1059"],  # Insecure Deserialization → code execution
    # Path Traversal / File Operations
    "22": ["T1083"],   # Path Traversal → File and Directory Discovery
    "73": ["T1083"],   # External Control of File Name
    # Memory safety
    "120": ["T1203"],  # Buffer Overflow → Exploitation for Client Execution
    "125": ["T1203"],  # Out-of-bounds Read
    "787": ["T1203"],  # Out-of-bounds Write
    # Supply chain
    "1357": ["T1195"],  # Reliance on Untrusted Component → Supply Chain Compromise
    "494": ["T1195"],   # Download of Code Without Integrity Check
}


def cwe_to_attack_techniques(cwe: str) -> List[str]:
    """Return MITRE ATT&CK technique IDs for the given CWE string.

    Parameters
    ----------
    cwe:
        CWE string in any of these formats: ``"CWE-89"``, ``"89"``.

    Returns
    -------
    list[str]
        Technique IDs (e.g. ``["T1190"]``), or empty list if unmapped.
    """
    cwe_id = cwe.upper().replace("CWE-", "").strip()
    return list(_CWE_TO_ATTACK.get(cwe_id, []))
