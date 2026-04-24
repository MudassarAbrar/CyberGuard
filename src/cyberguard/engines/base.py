"""Base engine interface for all CyberGuard scan engines."""

from __future__ import annotations

from abc import ABC, abstractmethod
from pathlib import Path
from typing import List

from ..models import Finding


class BaseEngine(ABC):
    """Abstract base class that every scan engine must implement."""

    #: Short machine-readable name used in reports and CLI flags.
    name: str = "base"

    #: File extensions this engine can process (e.g. ``[".py"]``).
    #: An empty list means the engine handles all file types.
    supported_extensions: List[str] = []

    def can_scan(self, file_path: Path) -> bool:
        """Return ``True`` if this engine can process *file_path*."""
        if not self.supported_extensions:
            return True
        return file_path.suffix.lower() in self.supported_extensions

    @abstractmethod
    def scan_file(self, file_path: Path) -> List[Finding]:
        """Scan a single file and return a list of findings."""

    def scan_path(self, target_path: Path) -> List[Finding]:
        """Scan a file or a directory tree and return all findings.

        Directories are walked recursively; files not supported by this
        engine (as determined by :meth:`can_scan`) are silently skipped.
        """
        findings: List[Finding] = []
        if target_path.is_file():
            if self.can_scan(target_path):
                findings.extend(self.scan_file(target_path))
        elif target_path.is_dir():
            for file_path in sorted(target_path.rglob("*")):
                if file_path.is_file() and self.can_scan(file_path):
                    findings.extend(self.scan_file(file_path))
        return findings
