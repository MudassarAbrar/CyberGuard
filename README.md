# 🛡 CyberGuard

> **AI-powered cybersecurity code scanner for Python, JavaScript, Java, and Go projects.**

[![CI](https://github.com/MudassarAbrar/CyberGuard/actions/workflows/ci.yml/badge.svg)](https://github.com/MudassarAbrar/CyberGuard/actions/workflows/ci.yml)
[![Python](https://img.shields.io/badge/python-3.9%2B-blue)](https://www.python.org/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)

CyberGuard combines **static analysis (Bandit)**, a **50-pattern regex library** covering OWASP
Top 10 vulnerabilities across four languages, an **AI semantic engine** (powered by the free-tier
Groq API), and a **dependency scanning engine** that checks your lock files against the
[OSV vulnerability database](https://osv.dev/) — all in a single, cloud-friendly CLI that
produces **JSON** and **SARIF** output.

---

## Features

| Capability | Details |
|---|---|
| 🐍 Python scanning | Bandit AST analysis + 10 regex patterns |
| 🌐 JavaScript / TypeScript | 10 regex patterns covering XSS, injection, hardcoded secrets, and more |
| ☕ Java | 10 regex patterns: SQL injection, deserialization, XXE, weak crypto, and more |
| 🐹 Go | 10 regex patterns: command injection, TLS bypass, weak crypto, unsafe, and more |
| 🤖 AI semantic analysis | Groq (`llama3-8b-8192`) or any OpenAI-compatible API — **free tier friendly** |
| 📦 Dependency scanning | Scans requirements.txt, package-lock.json, yarn.lock, Pipfile.lock, poetry.lock, go.sum against the OSV CVE database |
| 📄 JSON output | Machine-readable, pipe-friendly — includes `cvss_score` and `cvss_vector` |
| 🔬 SARIF output | Compatible with GitHub Security tab and IDE integrations |
| ⚡ CI-ready | Single `pip install`, no local LLM required |
| 🚦 Severity gating | `--fail-on high` exits non-zero to break the build |

---

## Quickstart

### 1 — Install

```bash
pip install cyberguard
```

Or install from source:

```bash
git clone https://github.com/MudassarAbrar/CyberGuard.git
cd CyberGuard
pip install -e ".[dev]"
```

### 2 — Scan your project

```bash
# Scan a directory (JSON output to stdout)
cyberguard scan ./src

# Write SARIF output to a file
cyberguard scan ./src --format sarif --output results.sarif

# Fail the build if HIGH or CRITICAL issues are found
cyberguard scan ./src --fail-on high
```

### 3 — Enable AI analysis (optional, free)

Sign up for a **free** [Groq](https://console.groq.com/) account and set your API key:

```bash
export GROQ_API_KEY="gsk_..."
cyberguard scan ./src
```

Or use OpenAI:

```bash
export OPENAI_API_KEY="sk-..."
cyberguard scan ./src
```

---

## CLI Reference

```
Usage: cyberguard scan [OPTIONS] PATH

  Scan a file or directory for security vulnerabilities.

Arguments:
  PATH  File or directory to scan.  [required]

Options:
  -f, --format TEXT        Output format: json or sarif.  [default: json]
  -o, --output PATH        Write output to this file.
      --fail-on TEXT       Exit 1 if findings at or above this severity.
                           Values: critical, high, medium, low, none.
                           [default: high]
      --no-ai              Disable the AI semantic analysis engine.
      --no-bandit          Disable the Bandit engine (Python only).
      --no-pattern         Disable the regex pattern-matching engine.
      --no-deps            Disable the dependency scanning engine (lock-file CVE lookup).
  -q, --quiet              Suppress informational console output.
  -V, --version            Print version and exit.
  --help                   Show this message and exit.
```

### Exit codes

| Code | Meaning |
|------|---------|
| `0` | Scan completed, no findings above the `--fail-on` threshold |
| `1` | Findings at or above the `--fail-on` threshold were found |
| `2` | Invalid arguments or path not found |

---

## Examples

```bash
# Scan a single file
cyberguard scan app/auth.py

# Scan a directory, write SARIF, never fail the build
cyberguard scan . --format sarif --output cg.sarif --fail-on none

# Pattern engine only (no Bandit, no AI — fastest)
cyberguard scan ./src --no-bandit --no-ai

# Only fail on CRITICAL findings
cyberguard scan . --fail-on critical --no-ai

# Quiet mode: output JSON only (no decorations)
cyberguard scan . --quiet --no-ai | jq '.findings | length'
```

---

## GitHub Actions Integration

Add the following workflow to automatically scan your repository on every push and
surface results in the **Security → Code scanning** tab:

```yaml
# .github/workflows/security.yml
name: Security Scan

on: [push, pull_request]

jobs:
  cyberguard:
    runs-on: ubuntu-latest
    permissions:
      security-events: write
      contents: read

    steps:
      - uses: actions/checkout@v4

      - uses: actions/setup-python@v5
        with:
          python-version: "3.11"

      - run: pip install cyberguard

      - name: Run CyberGuard
        run: |
          cyberguard scan . \
            --format sarif \
            --output cyberguard.sarif \
            --fail-on high
        env:
          GROQ_API_KEY: ${{ secrets.GROQ_API_KEY }}   # optional — enables AI engine

      - name: Upload SARIF
        uses: github/codeql-action/upload-sarif@v3
        if: always()
        with:
          sarif_file: cyberguard.sarif
```

> **Tip**: Add `GROQ_API_KEY` as a repository secret to enable semantic AI analysis in CI.

---

## Configuration

### AI provider selection

CyberGuard checks environment variables in order:

| Variable | Effect |
|----------|--------|
| `GROQ_API_KEY` | Enable Groq provider (free tier, preferred) |
| `OPENAI_API_KEY` | Enable OpenAI or compatible provider |
| `CYBERGUARD_AI_MODEL` | Override model name |
| `CYBERGUARD_AI_BASE_URL` | Override API base URL (any OpenAI-compatible endpoint) |

If neither API key is set, the AI engine is silently skipped and the other engines
(Bandit + Pattern) continue to run.

### Using a custom OpenAI-compatible endpoint

```bash
export OPENAI_API_KEY="my-key"
export CYBERGUARD_AI_BASE_URL="https://api.together.xyz/v1"
export CYBERGUARD_AI_MODEL="mistralai/Mixtral-8x7B-Instruct-v0.1"
cyberguard scan .
```

---

## Output Formats

### JSON

```json
{
  "scan_id": "3f2b...",
  "target_path": "/home/user/project",
  "findings": [
    {
      "id": "a1b2...",
      "rule_id": "CG-PY004",
      "title": "Use of eval() / exec()",
      "description": "eval() or exec() can execute arbitrary Python code...",
      "severity": "high",
      "location": {
        "file_path": "/home/user/project/utils.py",
        "line_start": 42,
        "line_end": 42,
        "code_snippet": "    result = eval(user_expr)"
      },
      "engine": "pattern",
      "cwe": "CWE-95",
      "owasp": "A03:2021",
      "fix_suggestion": "Use ast.literal_eval() for safe evaluation...",
      "tags": ["pattern", "python"]
    }
  ],
  "engines_used": ["bandit", "pattern"],
  "scanned_files": 12,
  "scan_duration_ms": 340
}
```

### SARIF

SARIF 2.1.0 output is compatible with:
- [GitHub Code Scanning](https://docs.github.com/en/code-security/code-scanning)
- [VS Code SARIF Viewer](https://marketplace.visualstudio.com/items?itemName=MS-SarifVSCode.sarif-viewer)
- Any SARIF-compliant tool

---

## Architecture

See [docs/architecture.md](docs/architecture.md) for a full technical overview.

**High-level pipeline:**

```
cyberguard scan <path>
    │
    ├─► Bandit Engine       (Python AST analysis via bandit)
    ├─► Pattern Engine      (Regex patterns: Python + JS + Java + Go)
    ├─► AI Engine           (LLM semantic analysis, Groq/OpenAI)
    └─► Dependency Engine   (lock-file CVE lookup via OSV API)
              │
              ▼
         ScanResult  (deduplicated findings)
              │
    ┌─────────┴──────────┐
    ▼                    ▼
 JSON output        SARIF output
```

---

## Vulnerability Coverage

### Python patterns (CG-PY*)

| Rule | Title | CWE |
|------|-------|-----|
| CG-PY001 | SQL Injection via String Formatting | CWE-89 |
| CG-PY002 | OS Command Injection Risk | CWE-78 |
| CG-PY003 | Hardcoded Credential | CWE-259 |
| CG-PY004 | Use of eval() / exec() | CWE-95 |
| CG-PY005 | Insecure Deserialization (pickle) | CWE-502 |
| CG-PY006 | Weak Cryptographic Hash (MD5/SHA-1) | CWE-327 |
| CG-PY007 | Insecure Random Number Generation | CWE-338 |
| CG-PY008 | Potential Path Traversal | CWE-22 |
| CG-PY009 | XML External Entity (XXE) Risk | CWE-611 |
| CG-PY010 | Debug Mode Enabled | CWE-215 |

### JavaScript / TypeScript patterns (CG-JS*)

| Rule | Title | CWE |
|------|-------|-----|
| CG-JS001 | Use of eval() | CWE-95 |
| CG-JS002 | DOM-based XSS via innerHTML | CWE-79 |
| CG-JS003 | document.write() Usage | CWE-79 |
| CG-JS004 | Hardcoded Credential | CWE-259 |
| CG-JS005 | SQL Injection via String Concatenation | CWE-89 |
| CG-JS006 | OS Command Injection Risk | CWE-78 |
| CG-JS007 | Insecure HTTP Connection | CWE-319 |
| CG-JS008 | Insecure Random Number Generation | CWE-338 |
| CG-JS009 | Prototype Pollution Risk | CWE-1321 |
| CG-JS010 | Dynamic require() Path | CWE-706 |

### Java patterns (CG-JA*)

| Rule | Title | CWE |
|------|-------|-----|
| CG-JA001 | SQL Injection via String Concatenation | CWE-89 |
| CG-JA002 | Hardcoded Credential | CWE-259 |
| CG-JA003 | OS Command Injection Risk | CWE-78 |
| CG-JA004 | Insecure Deserialization (ObjectInputStream) | CWE-502 |
| CG-JA005 | Weak Cryptographic Hash (MD5 / SHA-1) | CWE-327 |
| CG-JA006 | XML External Entity (XXE) Risk | CWE-611 |
| CG-JA007 | Insecure Random Number Generation (java.util.Random) | CWE-338 |
| CG-JA008 | Potential Path Traversal | CWE-22 |
| CG-JA009 | printStackTrace() Leaks Stack Trace | CWE-209 |
| CG-JA010 | Disabled SSL/TLS Certificate Validation | CWE-295 |

### Go patterns (CG-GO*)

| Rule | Title | CWE |
|------|-------|-----|
| CG-GO001 | SQL Injection via String Formatting | CWE-89 |
| CG-GO002 | Hardcoded Credential | CWE-259 |
| CG-GO003 | OS Command Injection Risk | CWE-78 |
| CG-GO004 | Weak Cryptographic Hash (MD5 / SHA-1) | CWE-327 |
| CG-GO005 | Insecure Random Number Generation (math/rand) | CWE-338 |
| CG-GO006 | Potential Path Traversal | CWE-22 |
| CG-GO007 | TLS Certificate Verification Disabled | CWE-295 |
| CG-GO008 | HTTP Server Without Timeouts | CWE-400 |
| CG-GO009 | Unsafe Pointer Usage | CWE-119 |
| CG-GO010 | Hardcoded HTTP (Non-HTTPS) URL | CWE-319 |

### Dependency scanning (DEP-*)

The dependency engine generates findings with rule IDs of the form `DEP-<OSV-ID>` (e.g.
`DEP-PYSEC-2019-132`, `DEP-GHSA-xxxx-xxxx-xxxx`).  Each finding includes:

* **CVE alias(es)** in the tags and description.
* **CVSS score / vector** when available from the OSV database.
* **Fix suggestion** with the first available patched version.

---

## Development

```bash
# Install with dev extras
pip install -e ".[dev]"

# Run tests
pytest

# Run tests with coverage
pytest --cov=cyberguard

# Lint
ruff check src/ tests/
```

---

## License

[MIT](LICENSE) © CyberGuard Contributors
