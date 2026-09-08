"""
GenerationProgress: Append-only JSONL log for tracking per-template pipeline status.

Each line records one template processing event:
  {"timestamp": "...", "template_id": "_auto_xxx", "status": "verified", "duration_seconds": 45.2, "error": null}

Used by --resume to skip completed templates and report progress summaries.
"""

from __future__ import annotations

import json
import logging
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

logger = logging.getLogger(__name__)


class GenerationProgress:
    """Append-only JSONL progress log for pipeline resumption."""

    def __init__(self, log_path: Path):
        self.log_path = Path(log_path)
        self._entries: list[dict] = []
        self._by_template: dict[str, dict] = {}
        self._load()

    def _load(self) -> None:
        """Load existing progress entries, skipping malformed lines."""
        if not self.log_path.exists():
            return
        try:
            lines = self.log_path.read_text(encoding="utf-8").splitlines()
        except OSError as e:
            logger.warning(f"GenerationProgress: cannot read {self.log_path}: {e}")
            return

        good = 0
        bad = 0
        for line in lines:
            line = line.strip()
            if not line:
                continue
            try:
                entry = json.loads(line)
                self._entries.append(entry)
                tid = entry.get("template_id", "")
                if tid:
                    self._by_template[tid] = entry
                good += 1
            except json.JSONDecodeError:
                bad += 1

        if bad:
            logger.warning(
                f"GenerationProgress: {bad} malformed lines skipped in {self.log_path}"
            )
        logger.info(
            f"GenerationProgress: loaded {good} entries from {self.log_path}"
        )

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def append(
        self,
        template_id: str,
        status: str,
        duration_seconds: float = 0.0,
        error: Optional[str] = None,
    ) -> None:
        """Append a progress entry and persist immediately."""
        entry = {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "template_id": template_id,
            "status": status,
            "duration_seconds": round(duration_seconds, 2),
            "error": error,
        }
        self._entries.append(entry)
        self._by_template[template_id] = entry

        self.log_path.parent.mkdir(parents=True, exist_ok=True)
        try:
            import fcntl
            with open(self.log_path, "a", encoding="utf-8") as f:
                fcntl.flock(f, fcntl.LOCK_EX)
                f.write(json.dumps(entry, ensure_ascii=False) + "\n")
                f.flush()
                fcntl.flock(f, fcntl.LOCK_UN)
        except OSError as e:
            logger.error(f"GenerationProgress: failed to write: {e}")

    def get_status(self, template_id: str) -> Optional[str]:
        """Return the latest status for a template, or None if unseen."""
        entry = self._by_template.get(template_id)
        return entry["status"] if entry else None

    def is_complete(self, template_id: str) -> bool:
        """True if template was verified or failed (terminal states)."""
        status = self.get_status(template_id)
        return status in ("verified", "failed")

    def summary(self) -> dict:
        """Return a summary of progress across all templates."""
        total = len(self._by_template)
        verified = sum(
            1 for e in self._by_template.values() if e.get("status") == "verified"
        )
        failed = sum(
            1 for e in self._by_template.values() if e.get("status") == "failed"
        )
        in_progress = total - verified - failed
        return {
            "total": total,
            "verified": verified,
            "failed": failed,
            "in_progress": in_progress,
        }

    @property
    def completed_ids(self) -> set[str]:
        """Set of template IDs in a terminal state (verified or failed)."""
        return {
            tid
            for tid, entry in self._by_template.items()
            if entry.get("status") in ("verified", "failed")
        }

    @property
    def failed_ids(self) -> set[str]:
        """Set of template IDs in failed state."""
        return {
            tid
            for tid, entry in self._by_template.items()
            if entry.get("status") == "failed"
        }
