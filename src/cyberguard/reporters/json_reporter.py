"""JSON output reporter."""

from __future__ import annotations

import json

from ..models import ScanResult
from .base import BaseReporter


class JsonReporter(BaseReporter):
    """Renders :class:`~cyberguard.models.ScanResult` as a JSON document."""

    format_name = "json"

    def __init__(self, indent: int = 2) -> None:
        self.indent = indent

    def render(self, result: ScanResult) -> str:
        return json.dumps(result.model_dump(mode="json"), indent=self.indent)
