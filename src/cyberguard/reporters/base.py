"""Base reporter interface."""

from __future__ import annotations

from abc import ABC, abstractmethod
from pathlib import Path
from typing import Optional

from ..models import ScanResult


class BaseReporter(ABC):
    """Abstract base class for output reporters."""

    format_name: str = "base"

    @abstractmethod
    def render(self, result: ScanResult) -> str:
        """Render *result* to a string in this reporter's format."""

    def write(self, result: ScanResult, output_path: Optional[Path] = None) -> str:
        """Render the result and optionally persist it to *output_path*.

        Returns the rendered string in all cases so callers can also print it.
        """
        rendered = self.render(result)
        if output_path is not None:
            output_path.parent.mkdir(parents=True, exist_ok=True)
            output_path.write_text(rendered, encoding="utf-8")
        return rendered
