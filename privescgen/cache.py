"""
FeasibilityCache: Content-addressable cache for LLM feasibility classification.

Avoids redundant LLM calls across interrupted pipeline runs by persisting
classification results keyed by a stable identifier plus a content hash.

Cache layout (JSON on disk):
  {
    "cache_version": "1.0",
    "entries": {
      "exploitdb:12345": {
        "hash": "<sha256 of title+cve+description>",
        "level": "L1",
        "reasoning": "...",
        "docker_run_args": [],
        "timestamp": "2026-04-05T10:30:00Z"
      },
      ...
    }
  }

Design choices:
- Append-only: entries are never invalidated unless the user deletes the file.
- Atomic writes: each `put` writes to a .tmp sibling then renames.
- Graceful recovery: malformed JSON is logged and replaced with an empty cache.
"""

from __future__ import annotations

import hashlib
import json
import logging
import os
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

logger = logging.getLogger(__name__)

CACHE_VERSION = "1.0"


def content_hash(*parts: str) -> str:
    """Compute a stable sha256 hash over the concatenation of string parts.

    None values are treated as empty strings; non-str values are str()-ified.
    """
    h = hashlib.sha256()
    for p in parts:
        if p is None:
            p = ""
        h.update(str(p).encode("utf-8"))
        h.update(b"\x00")  # Separator to avoid ambiguity
    return h.hexdigest()


class FeasibilityCache:
    """Simple persistent cache for feasibility classification results."""

    def __init__(self, cache_path: Path):
        self.cache_path = Path(cache_path)
        self._hits = 0
        self._misses = 0
        self._writes = 0
        self.data = self._load()

    # ------------------------------------------------------------------
    # Persistence
    # ------------------------------------------------------------------

    def _load(self) -> dict:
        """Load cache from disk, recovering gracefully from corruption."""
        if not self.cache_path.exists():
            return {"cache_version": CACHE_VERSION, "entries": {}}
        try:
            raw = self.cache_path.read_text(encoding="utf-8")
            data = json.loads(raw)
            if not isinstance(data, dict) or "entries" not in data:
                raise ValueError("cache missing 'entries' key")
            if not isinstance(data["entries"], dict):
                raise ValueError("cache 'entries' is not a dict")
            data.setdefault("cache_version", CACHE_VERSION)
            logger.info(
                f"FeasibilityCache: loaded {len(data['entries'])} entries "
                f"from {self.cache_path}"
            )
            return data
        except (json.JSONDecodeError, OSError, ValueError) as e:
            logger.warning(
                f"FeasibilityCache: malformed cache at {self.cache_path} ({e}); "
                f"starting fresh"
            )
            return {"cache_version": CACHE_VERSION, "entries": {}}

    def _persist(self) -> None:
        """Atomically persist the cache to disk (write tmp, then rename)."""
        self.cache_path.parent.mkdir(parents=True, exist_ok=True)
        tmp_path = self.cache_path.with_suffix(self.cache_path.suffix + ".tmp")
        try:
            tmp_path.write_text(
                json.dumps(self.data, indent=2, ensure_ascii=False),
                encoding="utf-8",
            )
            os.replace(tmp_path, self.cache_path)
        except OSError as e:
            logger.error(f"FeasibilityCache: failed to persist cache: {e}")
            # Best-effort cleanup of tmp file
            try:
                if tmp_path.exists():
                    tmp_path.unlink()
            except OSError:
                pass

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def get(self, key: str, content_hash: str) -> Optional[dict]:
        """Return cached entry if key exists and its hash matches, else None."""
        entry = self.data["entries"].get(key)
        if entry is None:
            self._misses += 1
            return None
        if entry.get("hash") != content_hash:
            # Content changed since cache was written; treat as a miss.
            self._misses += 1
            return None
        self._hits += 1
        return entry

    def put(self, key: str, content_hash: str, result: dict) -> None:
        """Save result to cache under key and persist immediately."""
        entry = {
            "hash": content_hash,
            "timestamp": datetime.now(timezone.utc).isoformat(),
            **result,
        }
        self.data["entries"][key] = entry
        self._writes += 1
        self._persist()

    def stats(self) -> dict:
        """Return cache statistics (hits, misses, writes, size)."""
        total_lookups = self._hits + self._misses
        hit_rate = (self._hits / total_lookups) if total_lookups else 0.0
        return {
            "entries": len(self.data.get("entries", {})),
            "hits": self._hits,
            "misses": self._misses,
            "writes": self._writes,
            "hit_rate": round(hit_rate, 3),
            "path": str(self.cache_path),
        }
