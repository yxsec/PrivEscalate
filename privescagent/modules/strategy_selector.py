"""
StrategySelector: Ranks candidate strategies and manages auto-pivot.

Uses a data-driven prior from historical success rates across exploitation
patterns. If the top-ranked strategy fails during execution, automatically
pivots to the next candidate without restarting the episode.
"""

from dataclasses import dataclass
from typing import List, Optional

from .category_matcher import ExploitCandidate


# Static category priors used only to break ties between observed candidates.
# Higher values prefer simpler, more direct escalation primitives.
CATEGORY_PRIORS = {
    "T1548.003_sudo_all": 0.98,     # sudo NOPASSWD ALL — near-trivial
    "T1548.003_sudo": 0.85,         # sudo specific binary via GTFOBins
    "T1548.001_suid": 0.75,         # SUID binary via GTFOBins
    "T1548.capabilities": 0.70,     # Linux capabilities
    "T1078_sudoers_write": 0.90,    # Writable sudoers
    "T1078_passwd_write": 0.80,     # Writable /etc/passwd
    "T1053.003_cron": 0.55,         # Cron job exploitation
    "T1078_shadow_write": 0.50,     # Writable /etc/shadow
    "T1574_path_hijack": 0.40,      # PATH hijacking
}

@dataclass
class RankedStrategy:
    """A strategy with a composite score for ranking."""
    candidate: ExploitCandidate
    score: float
    attempted: bool = False
    failed: bool = False
    failure_reason: str = ""


class StrategySelector:
    """
    Ranks candidates and manages strategy pivoting.

    Scoring formula:
      score = candidate.confidence * category_prior * (1 - multi_step_penalty)
    """

    def __init__(self, multi_step_penalty: float = 0.2):
        self._multi_step_penalty = multi_step_penalty
        self._strategies: List[RankedStrategy] = []
        self._current_idx: int = 0

    def rank(self, candidates: List[ExploitCandidate]) -> List[RankedStrategy]:
        """Rank candidates by composite score."""
        strategies = []
        for c in candidates:
            cat_prior = CATEGORY_PRIORS.get(c.category, 0.3)
            ms_penalty = self._multi_step_penalty if c.multi_step else 0.0
            score = c.confidence * cat_prior * (1.0 - ms_penalty)
            strategies.append(RankedStrategy(candidate=c, score=score))

        strategies.sort(key=lambda s: s.score, reverse=True)
        self._strategies = strategies
        self._current_idx = 0
        return strategies

    @property
    def current_strategy(self) -> Optional[RankedStrategy]:
        """Get the current (not-yet-failed) strategy."""
        while self._current_idx < len(self._strategies):
            s = self._strategies[self._current_idx]
            if not s.failed:
                return s
            self._current_idx += 1
        return None

    @property
    def has_alternatives(self) -> bool:
        """Check if there are untried alternatives."""
        remaining = sum(
            1 for s in self._strategies[self._current_idx:]
            if not s.failed
        )
        return remaining > 1

    def mark_attempted(self):
        """Mark current strategy as attempted."""
        if self._current_idx < len(self._strategies):
            self._strategies[self._current_idx].attempted = True

    def pivot(self, reason: str = "") -> Optional[RankedStrategy]:
        """
        Mark current strategy as failed and pivot to next.
        Returns the next strategy, or None if all exhausted.
        """
        if self._current_idx < len(self._strategies):
            self._strategies[self._current_idx].failed = True
            self._strategies[self._current_idx].failure_reason = reason
        self._current_idx += 1
        return self.current_strategy

    def build_hint(self) -> str:
        """Build a hint string from the current strategy for the ReAct agent."""
        current = self.current_strategy
        if current is None:
            return ""

        c = current.candidate
        parts = [
            f"Strategy: {c.category} via {c.binary}",
            f"Exploit command: {c.exploit_cmd}",
        ]
        if c.notes:
            parts.append(f"Notes: {c.notes}")
        if c.multi_step:
            parts.append("This requires multiple steps. Plan carefully.")

        # Also mention alternatives
        alts = [
            s.candidate for s in self._strategies[self._current_idx + 1:]
            if not s.failed
        ][:2]
        if alts:
            alt_strs = [f"{a.binary} ({a.category})" for a in alts]
            parts.append(f"Fallback options: {', '.join(alt_strs)}")

        return "\n".join(parts)

    def summary(self) -> str:
        """Return a summary of all strategies and their status."""
        lines = []
        for i, s in enumerate(self._strategies):
            marker = "→" if i == self._current_idx else " "
            status = "FAILED" if s.failed else ("TRIED" if s.attempted else "pending")
            lines.append(
                f"{marker} [{status}] {s.candidate.category}: "
                f"{s.candidate.binary} (score={s.score:.2f})"
            )
        return "\n".join(lines)
