# CyberGuard Architecture

## Overview

CyberGuard is a cloud-native, AI-augmented **Static Application Security Testing (SAST)** tool.
It is designed to run in CI/CD pipelines (GitHub Actions) without any local LLM infrastructure.

```
cyberguard scan <path>
        │
        ▼
┌───────────────────────────────────────────────────────────────────────┐
│                              Scanner                                  │
│   Orchestrates engines, deduplicates findings, builds ScanResult      │
└────────┬──────────────┬──────────────┬──────────────┬────────────────┘
         │              │              │              │
         ▼              ▼              ▼              ▼
 ┌─────────────┐ ┌────────────┐ ┌──────────────┐ ┌──────────────────┐
 │   Bandit    │ │  Pattern   │ │  AI Engine   │ │   Dependency     │
 │   Engine    │ │  Engine    │ │  (Groq / OAI)│ │   Engine (OSV)   │
 │  (Python)   │ │ Py+JS+Java │ │  Py + JS     │ │  lock-file CVEs  │
 └─────────────┘ │    +Go     │ └──────────────┘ └──────────────────┘
                 └────────────┘
         │              │              │              │
         └──────────────┴──────────────┴──────────────┘
                                │
                         List[Finding]
                                │
                                ▼
                ┌──────────────────────────┐
                │        Reporter          │
                │   JsonReporter (default) │
                │   SarifReporter          │
                └──────────────────────────┘
                                │
                        stdout / file
```

---

## Components

### CLI (`cyberguard.cli`)

Built with [Typer](https://typer.tiangolo.com/) and [Rich](https://rich.readthedocs.io/).
Provides the `cyberguard scan` command with options for format, output file, severity
threshold, and per-engine toggles (`--no-bandit`, `--no-pattern`, `--no-ai`, `--no-deps`).

### Scanner (`cyberguard.scanner`)

The `Scanner` class:

1. Resolves the target path.
2. Instantiates requested engines.
3. Runs each engine's `scan_path()` method.
4. Merges and deduplicates findings by `(rule_id, file_path, line_start)`.
5. Returns a `ScanResult`.

### Engines

| Engine | Language(s) / Files | Approach | External Dependency |
|--------|---------------------|----------|---------------------|
| `BanditEngine` | Python | Static AST analysis | `bandit` (PyPI) |
| `PatternEngine` | Python, JavaScript/TypeScript, Java, Go | Regex line-by-line | None |
| `AIEngine` | Python, JavaScript/TypeScript | LLM semantic analysis | `groq` / `openai` SDK |
| `DependencyEngine` | requirements.txt, package-lock.json, yarn.lock, Pipfile.lock, poetry.lock, go.sum | OSV API CVE lookup | None (stdlib only) |

#### Bandit Engine
Invokes `bandit -r -f json` as a subprocess.  The JSON output is parsed into
`Finding` objects, preserving CWE references where Bandit provides them.

#### Pattern Engine
A curated library of 50 regex patterns covering:

* **Python** (CG-PY001–010): SQL injection, command injection, hardcoded secrets,
  eval/exec, insecure deserialization, weak crypto, insecure random, path traversal,
  XXE, and debug mode.
* **JavaScript / TypeScript** (CG-JS001–010): eval, innerHTML XSS, document.write,
  hardcoded secrets, SQL injection, command injection, insecure HTTP, Math.random,
  prototype pollution, and dynamic require.
* **Java** (CG-JA001–010): SQL injection, hardcoded credentials, command injection,
  ObjectInputStream deserialization, weak hash (MD5/SHA-1), XXE (DocumentBuilderFactory),
  insecure Random, path traversal, printStackTrace leak, and disabled TLS validation.
* **Go** (CG-GO001–010): SQL injection via Sprintf, hardcoded credentials, shell
  command injection, MD5/SHA-1 imports, math/rand import, path traversal via os.Open,
  InsecureSkipVerify, http.ListenAndServe without timeouts, unsafe package, and
  hardcoded HTTP URLs.

Each pattern carries a `cwe`, `owasp`, and `fix_suggestion` field.

#### AI Engine
Calls an LLM via the Groq or OpenAI SDK:

* **Provider selection**: Groq when `GROQ_API_KEY` is set (preferred — free tier);
  fallback to OpenAI when `OPENAI_API_KEY` is set.
* **Model**: `llama3-8b-8192` (Groq default) or `gpt-4o-mini` (OpenAI default).
  Override with `CYBERGUARD_AI_MODEL`.
* **Custom base URL**: Set `CYBERGUARD_AI_BASE_URL` to point at any OpenAI-compatible
  endpoint (Together AI, Mistral, self-hosted vLLM, etc.).
* **File size limit**: Files larger than 20 KB are truncated before sending.
* **Graceful degradation**: If no API key is configured the engine is silently
  skipped and a warning is printed.

#### Dependency Engine
Scans lock/manifest files for packages with known CVEs by querying the
[OSV (Open Source Vulnerabilities)](https://osv.dev/) database:

* **Supported files**: `requirements.txt`, `package-lock.json`, `yarn.lock`,
  `Pipfile.lock`, `poetry.lock`, `go.sum`.
* **Ecosystems**: PyPI, npm, Go.
* **Network**: Single HTTPS POST to `https://api.osv.dev/v1/querybatch` per batch of
  up to 100 packages. No API key required.
* **Severity**: Derived from `database_specific.severity` or CVSS v3 vector.
* **Graceful degradation**: Network failures return empty findings (no exception raised).
* **CVSS fields**: `cvss_score` and `cvss_vector` are populated on the `Finding` object
  when the OSV response includes CVSS data.

### Models (`cyberguard.models`)

```
Severity (enum)  ──► SEVERITY_RANK (dict)
                           │
Finding                    │   ScanResult
  ├─ rule_id               │     ├─ findings: List[Finding]
  ├─ title                 │     ├─ engines_used
  ├─ description           │     ├─ scanned_files
  ├─ severity ─────────────┘     └─ scan_duration_ms
  ├─ location: Location
  ├─ engine
  ├─ cwe
  ├─ owasp
  ├─ cvss_score   ← new
  ├─ cvss_vector  ← new
  ├─ fix_suggestion
  └─ tags
```

### Reporters

| Reporter | Format | Use case |
|----------|--------|----------|
| `JsonReporter` | JSON | Machine-readable results, further processing |
| `SarifReporter` | SARIF 2.1.0 | GitHub Security tab, IDE integration |

SARIF output includes:
* `runs[].tool.driver.rules` — deduplicated rule descriptors with CWE relationships.
* `runs[].results` — one entry per finding with physical location and fix advice.
* `security-severity` property — enables GitHub Advanced Security severity bucketing.

---

## Data Flow

```
Target path
    │
    ▼ Scanner._collect_files()
List[Path] (vendor dirs excluded)
    │
    ▼ engine.scan_path(path) × N engines
List[Finding] (raw, may contain duplicates)
    │
    ▼ Scanner._deduplicate()
List[Finding] (unique by rule_id + file + line)
    │
    ▼ ScanResult
    │
    ▼ Reporter.render()
str (JSON or SARIF)
    │
    ▼ stdout / file
```

---

## CI Integration

```yaml
- name: Run CyberGuard
  run: cyberguard scan . --format sarif --output results.sarif --fail-on high

- name: Upload to GitHub Security
  uses: github/codeql-action/upload-sarif@v3
  with:
    sarif_file: results.sarif
```

Set the `GROQ_API_KEY` GitHub Actions secret to enable AI analysis in CI.

---

## Extension Points

* **New engine**: Subclass `BaseEngine`, implement `scan_file()`, add to `Scanner.__init__`.
* **New reporter**: Subclass `BaseReporter`, implement `render()`.
* **New pattern**: Add a `Pattern` instance to the `_PATTERNS` list in `pattern_engine.py`.
* **New lock-file format**: Add a parser function and register the filename in
  `_LOCK_FILE_NAMES` inside `dependency_engine.py`.
