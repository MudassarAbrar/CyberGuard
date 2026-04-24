"""AI-powered semantic analysis engine using Groq or any OpenAI-compatible API."""

from __future__ import annotations

import json
import os
from pathlib import Path
from typing import Any, Dict, List, Optional

from ..models import Finding, Location, Severity
from .base import BaseEngine

# File extensions this engine supports, mapped to a friendly language name.
_SUPPORTED_EXTENSIONS: Dict[str, str] = {
    ".py": "Python",
    ".js": "JavaScript",
    ".mjs": "JavaScript",
    ".cjs": "JavaScript",
    ".jsx": "JavaScript",
    ".ts": "TypeScript",
    ".tsx": "TypeScript",
}

# Maximum bytes read per file to avoid exceeding LLM token limits.
_MAX_FILE_BYTES = 20_000

_SYSTEM_PROMPT = """\
You are an expert application security engineer.
Analyse the source code provided by the user and return a JSON array of security findings.

Each finding MUST be a JSON object with these exact keys:
  rule_id      – string like "AI-001"
  title        – short descriptive title (max 60 chars)
  description  – detailed explanation of the vulnerability
  severity     – one of: "critical", "high", "medium", "low", "info"
  line_start   – integer: 1-based line number where the issue starts
  line_end     – integer: 1-based line number where the issue ends
  cwe          – CWE identifier string like "CWE-89", or null
  fix_suggestion – concrete, actionable fix recommendation

Return ONLY a raw JSON array (no markdown fences, no prose).
If there are no vulnerabilities, return an empty array: []
Focus exclusively on real security vulnerabilities — not style, performance, or formatting.\
"""

_USER_PROMPT_TEMPLATE = """\
Analyse the following {language} file for security vulnerabilities.

File: {filename}

```{lang_tag}
{code}
```\
"""


class AIEngine(BaseEngine):
    """Uses an LLM (Groq by default, or any OpenAI-compatible endpoint) for
    semantic security analysis.

    Configuration via environment variables:

    * ``GROQ_API_KEY``            – enables Groq provider (preferred, free tier).
    * ``OPENAI_API_KEY``          – enables OpenAI / OpenAI-compatible provider.
    * ``CYBERGUARD_AI_BASE_URL``  – override the API base URL (OpenAI path only).
    * ``CYBERGUARD_AI_MODEL``     – override the model name.
    """

    name = "ai"
    supported_extensions = list(_SUPPORTED_EXTENSIONS.keys())

    def __init__(self) -> None:
        self._client: Optional[Any] = None
        self._model: str = ""
        self._available: bool = False
        self._setup()

    def _setup(self) -> None:
        groq_key = os.environ.get("GROQ_API_KEY", "").strip()
        openai_key = os.environ.get("OPENAI_API_KEY", "").strip()

        if groq_key:
            try:
                from groq import Groq  # type: ignore[import]

                self._client = Groq(api_key=groq_key)
                self._model = os.environ.get("CYBERGUARD_AI_MODEL", "llama3-8b-8192")
                self._available = True
            except ImportError:
                pass
        elif openai_key:
            try:
                from openai import OpenAI  # type: ignore[import]

                base_url: Optional[str] = os.environ.get("CYBERGUARD_AI_BASE_URL") or None
                self._client = OpenAI(api_key=openai_key, base_url=base_url)
                self._model = os.environ.get("CYBERGUARD_AI_MODEL", "gpt-4o-mini")
                self._available = True
            except ImportError:
                pass

    @property
    def is_available(self) -> bool:
        """Return ``True`` if an LLM provider has been successfully configured."""
        return self._available

    # ------------------------------------------------------------------
    # BaseEngine interface
    # ------------------------------------------------------------------

    def scan_file(self, file_path: Path) -> List[Finding]:
        if not self._available:
            return []

        language = _SUPPORTED_EXTENSIONS.get(file_path.suffix.lower())
        if language is None:
            return []

        try:
            raw = file_path.read_bytes()
            if len(raw) > _MAX_FILE_BYTES:
                raw = raw[:_MAX_FILE_BYTES]
            code = raw.decode("utf-8", errors="replace")
        except OSError:
            return []

        if not code.strip():
            return []

        user_prompt = _USER_PROMPT_TEMPLATE.format(
            language=language,
            filename=file_path.name,
            lang_tag=language.lower(),
            code=code,
        )

        try:
            response = self._client.chat.completions.create(
                model=self._model,
                messages=[
                    {"role": "system", "content": _SYSTEM_PROMPT},
                    {"role": "user", "content": user_prompt},
                ],
                temperature=0.1,
                max_tokens=2048,
            )
            content: str = response.choices[0].message.content or ""
        except Exception:  # noqa: BLE001
            return []

        return self._parse_response(content, str(file_path))

    # ------------------------------------------------------------------
    # Private helpers
    # ------------------------------------------------------------------

    def _parse_response(self, content: str, file_path: str) -> List[Finding]:
        content = content.strip()

        # Strip markdown code fences that some models wrap around JSON.
        if content.startswith("```"):
            lines = content.splitlines()
            # Drop first line (```json / ```) and last line (```)
            inner = lines[1:-1] if lines and lines[-1].strip() == "```" else lines[1:]
            content = "\n".join(inner)

        # Try to parse the cleaned content directly.
        try:
            data = json.loads(content)
        except json.JSONDecodeError:
            # Fall back: locate the first JSON array in the response.
            start = content.find("[")
            end = content.rfind("]")
            if start != -1 and end > start:
                try:
                    data = json.loads(content[start : end + 1])
                except json.JSONDecodeError:
                    return []
            else:
                return []

        if not isinstance(data, list):
            return []

        findings: List[Finding] = []
        for idx, item in enumerate(data):
            if not isinstance(item, dict):
                continue
            try:
                severity_raw = str(item.get("severity", "medium")).lower()
                try:
                    severity = Severity(severity_raw)
                except ValueError:
                    severity = Severity.MEDIUM

                findings.append(
                    Finding(
                        rule_id=item.get("rule_id", f"AI-{idx + 1:03d}"),
                        title=str(item.get("title", "Security Issue"))[:120],
                        description=str(item.get("description", "")),
                        severity=severity,
                        location=Location(
                            file_path=file_path,
                            line_start=max(1, int(item.get("line_start", 1))),
                            line_end=max(1, int(item.get("line_end", 1))),
                        ),
                        engine=self.name,
                        cwe=item.get("cwe") or None,
                        fix_suggestion=item.get("fix_suggestion") or None,
                        tags=["ai"],
                    )
                )
            except (KeyError, TypeError, ValueError):
                continue

        return findings
