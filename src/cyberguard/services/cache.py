"""Simple disk-backed TTL cache for external API responses.

Responses are stored as JSON files under ``~/.cyberguard/cache/``.
Each entry stores the payload alongside an expiry timestamp; stale
entries are silently ignored and re-fetched.
"""

from __future__ import annotations

import json
import time
from pathlib import Path
from typing import Any, Optional


# Default cache directory — respects XDG conventions on Linux, falls back to ~/.cyberguard.
_CACHE_DIR = Path.home() / ".cyberguard" / "cache"


class DiskCache:
    """Key/value TTL cache backed by flat JSON files on disk.

    Parameters
    ----------
    namespace:
        Sub-directory name used to isolate different cache domains
        (e.g. ``"osv"``, ``"nvd"``, ``"kev"``).
    ttl_seconds:
        Time-to-live in seconds.  Default is 24 hours.
    base_dir:
        Root directory for all cache entries.  Defaults to
        ``~/.cyberguard/cache``.
    """

    def __init__(
        self,
        namespace: str,
        ttl_seconds: int = 86_400,
        base_dir: Optional[Path] = None,
    ) -> None:
        self._dir = (base_dir or _CACHE_DIR) / namespace
        self._ttl = ttl_seconds

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def get(self, key: str) -> Optional[Any]:
        """Return the cached value for *key*, or ``None`` if absent/stale."""
        path = self._path(key)
        if not path.exists():
            return None
        try:
            entry = json.loads(path.read_text(encoding="utf-8"))
            if time.time() < entry.get("expires_at", 0):
                return entry["payload"]
            path.unlink(missing_ok=True)
        except (OSError, json.JSONDecodeError, KeyError):
            pass
        return None

    def set(self, key: str, value: Any) -> None:
        """Store *value* under *key* with the configured TTL."""
        self._dir.mkdir(parents=True, exist_ok=True)
        path = self._path(key)
        entry = {"expires_at": time.time() + self._ttl, "payload": value}
        try:
            path.write_text(json.dumps(entry), encoding="utf-8")
        except OSError:
            pass

    def clear(self) -> None:
        """Remove all entries in this namespace."""
        if self._dir.exists():
            for f in self._dir.glob("*.json"):
                f.unlink(missing_ok=True)

    # ------------------------------------------------------------------
    # Private helpers
    # ------------------------------------------------------------------

    def _path(self, key: str) -> Path:
        # Sanitise the key so it is safe as a filename.
        safe = "".join(c if c.isalnum() or c in "-_." else "_" for c in key)
        return self._dir / f"{safe}.json"
