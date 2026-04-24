# CyberGuard Architecture

## Overview

CyberGuard is a cloud-native, AI-augmented **Static Application Security Testing (SAST)** tool.
It is designed to run in CI/CD pipelines (GitHub Actions) without any local LLM infrastructure.

```
cyberguard scan <path>
        │
        ▼
┌───────────────────────────────────────────────────────────┐
│                         Scanner                           │
│   Orchestrates engines, deduplicates, builds ScanResult   │
└───────────┬──────────────┬──────────────┬─────────────────┘
            │              │              │
            ▼              ▼              ▼
    ┌─────────────┐ ┌────────────┐ ┌──────────────┐
    │   Bandit    │ │  Pattern   │ │  AI Engine   │
    │   Engine    │ │  Engine    │ │  (Groq / OAI)│
    │  (Python)   │ │  (Py + JS) │ │  (Py + JS)   │
    └─────────────┘ └────────────┘ └──────────────┘
            │              │              │
            └──────────────┴──────────────┘
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
Provides the `cyberguard scan` command with options for format, output file, and severity threshold.

### Scanner (`cyberguard.scanner`)

The `Scanner` class:

1. Resolves the target path.
2. Instantiates requested engines.
3. Runs each engine's `scan_path()` method.
4. Merges and deduplicates findings by `(rule_id, file_path, line_start)`.
5. Returns a `ScanResult`.

### Engines

| Engine | Language(s) | Approach | External Dependency |
|--------|-------------|----------|---------------------|
| `BanditEngine` | Python | Static AST analysis | `bandit` (PyPI) |
| `PatternEngine` | Python, JavaScript/TypeScript | Regex line-by-line matching | None |
| `AIEngine` | Python, JavaScript/TypeScript | LLM semantic analysis | `groq` / `openai` SDK |

#### Bandit Engine
Invokes `bandit -r -f json` as a subprocess.  The JSON output is parsed into
`Finding` objects, preserving CWE references where Bandit provides them.

#### Pattern Engine
A curated library of 20 regex patterns (10 Python, 10 JavaScript) covering OWASP
Top 10 categories: injection, hardcoded secrets, weak crypto, insecure deserialization,
XXE, and more.  Each pattern carries a `cwe`, `owasp`, and `fix_suggestion` field.

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

### Models (`cyberguard.models`)

```
Severity (enum)  ──► SEVERITY_RANK (dict)
                          │
Finding                   │   ScanResult
  ├─ rule_id              │     ├─ findings: List[Finding]
  ├─ title                │     ├─ engines_used
  ├─ description          │     ├─ scanned_files
  ├─ severity ────────────┘     └─ scan_duration_ms
  ├─ location: Location
  ├─ engine
  ├─ cwe
  ├─ owasp
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
