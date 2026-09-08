"""
PrivEscGen Manager Agent.

Orchestrates Scaffolder, Exploiter, and Verifier sub-agents
to construct verified privilege escalation scenarios.

When LLM is available, uses a feedback-driven retry loop:
  Verify → Diagnose → Fix (Dockerfile or Exploit) → Re-verify

Features:
  - Rich progress bar with per-agent status
  - Colored result dashboard (by category + difficulty)
  - Enhanced JSON report (metadata, timing, cost estimation)
"""

import json
import logging
import time
from collections import defaultdict
from datetime import datetime
from pathlib import Path
from dataclasses import dataclass
from typing import Optional

from .scaffolder import Scaffolder
from .exploiter import Exploiter
from .verifier import Verifier, VerificationResult
from .progress import GenerationProgress

logger = logging.getLogger(__name__)

MAX_RETRIES = 3
MAX_FEEDBACK_RETRIES = 3  # LLM diagnosis → fix → re-verify cycles

# Try importing rich (optional but recommended)
try:
    from rich.console import Console
    from rich.table import Table
    from rich.panel import Panel
    from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn, TaskProgressColumn, TimeElapsedColumn
    HAS_RICH = True
except ImportError:
    HAS_RICH = False


@dataclass
class ScenarioSpec:
    """Specification for a single scenario to build."""
    scenario_id: str
    template_dir: Path
    params: dict
    output_dir: Path
    scenario_type: str = "core"  # "core" or "variant"
    difficulty: str = "medium"
    attack_technique: str = ""
    cwe: str = ""
    description: str = ""
    variant_of: Optional[str] = None
    reference_dockerfile: Optional[Path] = None  # verified Dockerfile as one-shot reference


@dataclass
class BuildResult:
    """Result of building a single scenario."""
    scenario_id: str
    success: bool
    scaffolder_attempts: int = 0
    exploiter_attempts: int = 0
    verifier_result: Optional[VerificationResult] = None
    feedback_attempts: int = 0
    error: Optional[str] = None
    needs_manual_review: bool = False
    duration_seconds: float = 0.0
    # Metadata for reporting
    scenario_type: str = "core"
    difficulty: str = "medium"
    attack_technique: str = ""
    category: str = ""


class Manager:
    """
    Coordinates the PrivEscGen pipeline.

    Pipeline: Scaffolder → Exploiter → Verifier
    With LLM-driven feedback loop: Verify → Diagnose → Fix → Re-verify.
    """

    def __init__(self, project_root: Path, llm_client=None):
        self.project_root = project_root
        self.llm = llm_client  # Optional[LLMClient]
        self.scaffolder = Scaffolder(project_root, llm=llm_client)
        self.exploiter = Exploiter(project_root, llm=llm_client)
        self.verifier = Verifier(project_root, llm=llm_client)
        self.results: list[BuildResult] = []
        self._start_time: float = 0.0
        self.console = Console() if HAS_RICH else None
        # Progress log for checkpoint/resume
        progress_path = project_root / ".cache" / "state" / "generation_progress.jsonl"
        self.progress = GenerationProgress(progress_path)

    # ------------------------------------------------------------------
    # Checkpoint helpers (runtime-only progress log)
    # ------------------------------------------------------------------

    # Status ordering for checkpoint skip logic
    _STATUS_ORDER = {
        "pending": 0,
        "scaffolded": 1,
        "exploited": 2,
        "verified": 3,
        "failed": 3,  # terminal alongside verified
    }

    @classmethod
    def _status_ge(cls, status: str, target: str) -> bool:
        """Return True if status is at-or-past target in the pipeline order."""
        return cls._STATUS_ORDER.get(status, -1) >= cls._STATUS_ORDER.get(target, 0)

    def _read_template_status(self, spec: ScenarioSpec) -> str:
        """Read checkpoint status from the ignored runtime progress log."""
        return self.progress.get_status(spec.template_dir.name) or "pending"

    def _write_template_status(self, spec: ScenarioSpec, status: str) -> None:
        """Retain the API without mutating the published template metadata.

        Terminal and failure states are recorded by ``GenerationProgress`` at
        the call sites below. Intermediate states intentionally remain
        ephemeral so running the generator cannot add process fields to
        ``params.json``.
        """
        return

    def build_scenario(
        self,
        spec: ScenarioSpec,
        skip_failed: bool = True,
    ) -> BuildResult:
        """Build a single scenario through the full pipeline.

        Checkpointed pipeline: terminal phase completion is recorded in the
        ignored runtime progress log. Published template metadata remains
        descriptive and result-free.

        Args:
            spec: Scenario specification.
            skip_failed: If True (default), previously-failed templates are
                skipped. Pass False to retry them.
        """
        t0 = time.time()
        template_id = spec.template_dir.name
        current_status = self._read_template_status(spec)

        # Safety: if output_dir was deleted but status is not pending/failed, reset.
        # Failed templates are preserved — use --retry-failed to explicitly retry.
        if current_status not in ("pending", "", "failed") and not spec.output_dir.exists():
            logger.warning(f"  Output dir missing for {spec.scenario_id} (status={current_status}), resetting to pending")
            self._write_template_status(spec, "pending")
            current_status = "pending"

        # Fast path: already verified or failed
        if current_status == "verified":
            logger.info(f"  SKIP (already verified): {spec.scenario_id}")
            return BuildResult(
                scenario_id=spec.scenario_id,
                success=True,
                scenario_type=spec.scenario_type,
                difficulty=spec.difficulty,
                attack_technique=spec.attack_technique,
                category=spec.params.get("_category", ""),
                duration_seconds=0.0,
            )
        if current_status == "failed" and skip_failed:
            logger.info(f"  SKIP (previously failed): {spec.scenario_id}")
            return BuildResult(
                scenario_id=spec.scenario_id,
                success=False,
                needs_manual_review=True,
                error="Previously failed (use --retry-failed to retry)",
                scenario_type=spec.scenario_type,
                difficulty=spec.difficulty,
                attack_technique=spec.attack_technique,
                category=spec.params.get("_category", ""),
                duration_seconds=0.0,
            )

        logger.info(
            f"Building scenario: {spec.scenario_id} "
            f"(checkpoint status={current_status})"
        )
        result = BuildResult(
            scenario_id=spec.scenario_id,
            success=False,
            scenario_type=spec.scenario_type,
            difficulty=spec.difficulty,
            attack_technique=spec.attack_technique,
            category=spec.params.get("_category", ""),
        )

        # Phase 1: Scaffolder (skip if already scaffolded)
        if self._status_ge(current_status, "scaffolded"):
            logger.info(f"  Scaffolder: SKIP (checkpoint={current_status})")
            result.scaffolder_attempts = 0
        else:
            for attempt in range(1, MAX_RETRIES + 1):
                result.scaffolder_attempts = attempt
                try:
                    scaffold_ok = self.scaffolder.build(spec)
                    if scaffold_ok:
                        logger.info(f"  Scaffolder: PASS (attempt {attempt})")
                        break
                    logger.warning(f"  Scaffolder: FAIL (attempt {attempt})")
                except Exception as e:
                    logger.error(f"  Scaffolder error: {e}")
            else:
                result.error = "Scaffolder failed after max retries"
                result.needs_manual_review = True
                result.duration_seconds = time.time() - t0
                logger.error(f"  {spec.scenario_id}: Scaffolder exhausted retries")
                self._write_template_status(spec, "failed")
                self.progress.append(
                    template_id, "failed", result.duration_seconds,
                    error=result.error,
                )
                return result
            self._write_template_status(spec, "scaffolded")

        # Phase 2: Exploiter (skip if already exploited)
        if self._status_ge(current_status, "exploited"):
            logger.info(f"  Exploiter: SKIP (checkpoint={current_status})")
            result.exploiter_attempts = 0
        else:
            for attempt in range(1, MAX_RETRIES + 1):
                result.exploiter_attempts = attempt
                try:
                    exploit_ok = self.exploiter.build(spec)
                    if exploit_ok:
                        logger.info(f"  Exploiter: PASS (attempt {attempt})")
                        break
                    logger.warning(f"  Exploiter: FAIL (attempt {attempt})")
                except Exception as e:
                    logger.error(f"  Exploiter error: {e}")
            else:
                result.error = "Exploiter failed after max retries"
                result.needs_manual_review = True
                result.duration_seconds = time.time() - t0
                logger.error(f"  {spec.scenario_id}: Exploiter exhausted retries")
                self._write_template_status(spec, "failed")
                self.progress.append(
                    template_id, "failed", result.duration_seconds,
                    error=result.error,
                )
                return result
            self._write_template_status(spec, "exploited")

        # Phase 3: Verify with LLM feedback loop (always run — idempotent)
        result = self._verify_with_feedback(spec, result)
        result.duration_seconds = time.time() - t0

        # Final status update
        final_status = "verified" if result.success else "failed"
        self._write_template_status(spec, final_status)
        self.progress.append(
            template_id, final_status, result.duration_seconds,
            error=result.error,
        )

        # Move failed scenarios to scenarios/failed/ to keep core/ clean
        if not result.success and spec.output_dir.exists():
            import shutil
            failed_dir = self.project_root / "dataset" / "scenarios" / "failed"
            failed_dir.mkdir(parents=True, exist_ok=True)
            dest = failed_dir / spec.output_dir.name
            if dest.exists():
                shutil.rmtree(dest)
            try:
                shutil.move(str(spec.output_dir), str(dest))
                logger.info(f"  Moved failed scenario to: dataset/scenarios/failed/{spec.output_dir.name}")
            except (OSError, shutil.Error) as e:
                logger.warning(f"  Could not move failed scenario: {e}")

        return result

    def _verify_with_feedback(
        self, spec: ScenarioSpec, result: BuildResult
    ) -> BuildResult:
        """
        Verify scenario and, if LLM is available, run a feedback loop:
        Verify → Diagnose → Fix → Re-verify (up to MAX_FEEDBACK_RETRIES).
        """
        for attempt in range(1, MAX_FEEDBACK_RETRIES + 1):
            result.feedback_attempts = attempt
            verification = self.verifier.verify(spec)
            result.verifier_result = verification

            if verification.all_passed:
                result.success = True
                logger.info(f"  Verifier: ALL PASSED (feedback attempt {attempt})")
                return result

            logger.warning(
                f"  Verifier: FAILED (attempt {attempt}) - {verification.failures}"
            )

            # Without LLM, cannot auto-fix → break immediately
            if not self.llm:
                break

            # LLM diagnosis → targeted fix
            diagnosis = self.verifier.diagnose(spec, verification)
            if not diagnosis:
                logger.warning("  LLM diagnosis returned None, cannot auto-fix")
                break

            fix_target = diagnosis.get("fix_target", "")
            root_cause = diagnosis.get("root_cause", "unknown")
            logger.info(f"  LLM diagnosis: fix_target={fix_target}, cause={root_cause}")

            fixed = False
            if "dockerfile" in fix_target or fix_target == "both":
                fixed = self.scaffolder.fix_dockerfile(spec, diagnosis)
            if "exploit" in fix_target or fix_target == "both":
                fixed = self.exploiter.fix_exploit(spec, diagnosis) or fixed

            if not fixed:
                logger.warning("  LLM fix could not be applied, stopping feedback loop")
                break

        # Exhausted retries or no LLM
        if not result.success:
            result.needs_manual_review = True
            result.error = f"Verification failed: {verification.failures}"
            logger.warning(
                f"  {spec.scenario_id}: Verification failed after "
                f"{result.feedback_attempts} feedback attempts"
            )

        return result

    def build_batch(
        self,
        specs: list[ScenarioSpec],
        skip_failed: bool = True,
    ) -> list[BuildResult]:
        """Build a batch of scenarios with Rich progress tracking."""
        self.results = []
        self._start_time = time.time()
        self._batch_skip_failed = skip_failed

        if HAS_RICH and self.console:
            self._build_batch_rich(specs)
        else:
            self._build_batch_plain(specs)

        return self.results

    def _build_batch_rich(self, specs: list[ScenarioSpec]):
        """Build batch with Rich progress bar."""
        skip_failed = getattr(self, "_batch_skip_failed", True)
        with Progress(
            SpinnerColumn(),
            TextColumn("[bold blue]{task.description}"),
            BarColumn(),
            TaskProgressColumn(),
            TimeElapsedColumn(),
            console=self.console,
        ) as progress:
            task = progress.add_task("Building scenarios", total=len(specs))

            for spec in specs:
                progress.update(task, description=f"[bold blue]{spec.scenario_id}")
                result = self.build_scenario(spec, skip_failed=skip_failed)
                self.results.append(result)

                # Update description with result
                if result.success:
                    progress.update(task, description=f"[green]{spec.scenario_id} PASS")
                elif result.needs_manual_review:
                    progress.update(task, description=f"[yellow]{spec.scenario_id} REVIEW")
                else:
                    progress.update(task, description=f"[red]{spec.scenario_id} FAIL")

                progress.advance(task)

        # Show dashboard
        self._show_dashboard()

    def _build_batch_plain(self, specs: list[ScenarioSpec]):
        """Build batch with plain logging (fallback)."""
        skip_failed = getattr(self, "_batch_skip_failed", True)
        for i, spec in enumerate(specs, 1):
            logger.info(f"[{i}/{len(specs)}] {spec.scenario_id}")
            result = self.build_scenario(spec, skip_failed=skip_failed)
            self.results.append(result)

        # Plain summary
        total = len(self.results)
        passed = sum(1 for r in self.results if r.success)
        manual = sum(1 for r in self.results if r.needs_manual_review)
        logger.info("\n=== Batch Summary ===")
        logger.info(f"Total: {total} | Passed: {passed} | Manual Review: {manual}")
        if total > 0:
            logger.info(f"Pass Rate: {passed/total*100:.1f}%")

    def _show_dashboard(self):
        """Display Rich dashboard with build results."""
        if not self.console:
            return

        total = len(self.results)
        passed = sum(1 for r in self.results if r.success)
        failed = sum(1 for r in self.results if not r.success)
        review = sum(1 for r in self.results if r.needs_manual_review)
        duration = time.time() - self._start_time
        rate = f"{passed/total*100:.1f}%" if total > 0 else "N/A"

        # Header panel
        llm_info = f"{self.llm.provider}/{self.llm.model}" if self.llm else "N/A"
        header = (
            f"[bold]Total:[/] {total}  "
            f"[green]Pass:[/] {passed}  "
            f"[red]Fail:[/] {failed}  "
            f"[yellow]Review:[/] {review}  "
            f"[bold]Rate:[/] {rate}\n"
            f"[dim]LLM: {llm_info} | Duration: {duration:.1f}s[/]"
        )
        self.console.print(Panel(header, title="PrivEscGen Build Report", border_style="blue"))

        # Category breakdown table
        cat_stats = defaultdict(lambda: {"total": 0, "passed": 0})
        diff_stats = defaultdict(lambda: {"total": 0, "passed": 0})
        for r in self.results:
            cat = r.category or r.attack_technique or "unknown"
            cat_stats[cat]["total"] += 1
            if r.success:
                cat_stats[cat]["passed"] += 1
            diff_stats[r.difficulty]["total"] += 1
            if r.success:
                diff_stats[r.difficulty]["passed"] += 1

        # Category table
        cat_table = Table(title="By Category", show_lines=False)
        cat_table.add_column("Category", style="cyan")
        cat_table.add_column("Total", justify="right")
        cat_table.add_column("Pass", justify="right", style="green")
        cat_table.add_column("Rate", justify="right")

        for cat in sorted(cat_stats.keys()):
            s = cat_stats[cat]
            r = f"{s['passed']/s['total']*100:.0f}%" if s["total"] > 0 else "-"
            cat_table.add_row(cat, str(s["total"]), str(s["passed"]), r)

        # Difficulty table
        diff_table = Table(title="By Difficulty", show_lines=False)
        diff_table.add_column("Difficulty", style="cyan")
        diff_table.add_column("Total", justify="right")
        diff_table.add_column("Pass", justify="right", style="green")
        diff_table.add_column("Rate", justify="right")

        for diff in ["easy", "medium", "hard"]:
            if diff in diff_stats:
                s = diff_stats[diff]
                r = f"{s['passed']/s['total']*100:.0f}%" if s["total"] > 0 else "-"
                diff_table.add_row(diff, str(s["total"]), str(s["passed"]), r)

        self.console.print(cat_table)
        self.console.print(diff_table)

        # Scenario detail table
        detail_table = Table(title="Scenario Details", show_lines=False)
        detail_table.add_column("Scenario", style="bold")
        detail_table.add_column("Type", justify="center")
        detail_table.add_column("Diff", justify="center")
        detail_table.add_column("S", justify="center")  # Scaffolder
        detail_table.add_column("E", justify="center")  # Exploiter
        detail_table.add_column("V", justify="center")  # Verifier
        detail_table.add_column("Status", justify="center")
        detail_table.add_column("Time", justify="right")

        for r in self.results:
            s_icon = "[green]OK[/]" if r.scaffolder_attempts <= 1 else f"[yellow]x{r.scaffolder_attempts}[/]"
            e_icon = "[green]OK[/]" if r.exploiter_attempts <= 1 else f"[yellow]x{r.exploiter_attempts}[/]"
            if r.success:
                v_icon = "[green]OK[/]"
                status = "[green]PASS[/]"
            elif r.needs_manual_review:
                v_icon = f"[red]x{r.feedback_attempts}[/]"
                status = "[yellow]REVIEW[/]"
            else:
                v_icon = "[red]FAIL[/]"
                status = "[red]FAIL[/]"

            detail_table.add_row(
                r.scenario_id, r.scenario_type, r.difficulty,
                s_icon, e_icon, v_icon, status,
                f"{r.duration_seconds:.1f}s",
            )

        self.console.print(detail_table)

    def export_report(self, output_path: Path):
        """Export enhanced build results as JSON report."""
        duration = time.time() - self._start_time if self._start_time else 0

        # Category and difficulty breakdowns
        by_category = defaultdict(lambda: {"total": 0, "passed": 0, "failed": 0})
        by_difficulty = defaultdict(lambda: {"total": 0, "passed": 0, "failed": 0})

        for r in self.results:
            cat = r.category or r.attack_technique or "unknown"
            by_category[cat]["total"] += 1
            by_difficulty[r.difficulty]["total"] += 1
            if r.success:
                by_category[cat]["passed"] += 1
                by_difficulty[r.difficulty]["passed"] += 1
            else:
                by_category[cat]["failed"] += 1
                by_difficulty[r.difficulty]["failed"] += 1

        report = {
            "metadata": {
                "timestamp": datetime.now().isoformat(),
                "llm_provider": self.llm.provider if self.llm else None,
                "llm_model": self.llm.model if self.llm else None,
                "duration_seconds": round(duration, 1),
            },
            "summary": {
                "total": len(self.results),
                "passed": sum(1 for r in self.results if r.success),
                "failed": sum(1 for r in self.results if not r.success),
                "needs_manual_review": sum(1 for r in self.results if r.needs_manual_review),
                "pass_rate": round(
                    sum(1 for r in self.results if r.success) / len(self.results) * 100, 1
                ) if self.results else 0,
            },
            "by_category": dict(by_category),
            "by_difficulty": dict(by_difficulty),
            "scenarios": [
                {
                    "id": r.scenario_id,
                    "type": r.scenario_type,
                    "difficulty": r.difficulty,
                    "category": r.category,
                    "attack_technique": r.attack_technique,
                    "success": r.success,
                    "scaffolder_attempts": r.scaffolder_attempts,
                    "exploiter_attempts": r.exploiter_attempts,
                    "feedback_attempts": r.feedback_attempts,
                    "duration_seconds": round(r.duration_seconds, 1),
                    "error": r.error,
                    "needs_manual_review": r.needs_manual_review,
                }
                for r in self.results
            ],
        }
        output_path.write_text(json.dumps(report, indent=2, ensure_ascii=False))
        logger.info(f"Report exported to {output_path}")

    def export_html_report(self, output_path: Path):
        """Export build results as a self-contained HTML report."""
        duration = time.time() - self._start_time if self._start_time else 0
        total = len(self.results)
        passed = sum(1 for r in self.results if r.success)
        failed = total - passed
        review = sum(1 for r in self.results if r.needs_manual_review)
        rate = f"{passed/total*100:.1f}" if total > 0 else "0"

        # Category breakdown
        cat_stats = defaultdict(lambda: {"total": 0, "passed": 0})
        diff_stats = defaultdict(lambda: {"total": 0, "passed": 0})
        for r in self.results:
            cat = r.category or r.attack_technique or "unknown"
            cat_stats[cat]["total"] += 1
            if r.success:
                cat_stats[cat]["passed"] += 1
            diff_stats[r.difficulty]["total"] += 1
            if r.success:
                diff_stats[r.difficulty]["passed"] += 1

        # Build category rows
        cat_rows = ""
        for cat in sorted(cat_stats.keys()):
            s = cat_stats[cat]
            sr = f"{s['passed']/s['total']*100:.0f}" if s["total"] > 0 else "0"
            cat_rows += f"<tr><td>{cat}</td><td>{s['total']}</td><td>{s['passed']}</td><td>{sr}%</td></tr>\n"

        # Build difficulty rows
        diff_rows = ""
        for d in ["easy", "medium", "hard"]:
            if d in diff_stats:
                s = diff_stats[d]
                sr = f"{s['passed']/s['total']*100:.0f}" if s["total"] > 0 else "0"
                diff_rows += f"<tr><td>{d}</td><td>{s['total']}</td><td>{s['passed']}</td><td>{sr}%</td></tr>\n"

        # Build scenario rows
        scenario_rows = ""
        for r in self.results:
            if r.success:
                status = '<span class="pass">PASS</span>'
            elif r.needs_manual_review:
                status = '<span class="review">REVIEW</span>'
            else:
                status = '<span class="fail">FAIL</span>'
            scenario_rows += (
                f"<tr><td>{r.scenario_id}</td><td>{r.scenario_type}</td>"
                f"<td>{r.difficulty}</td><td>{r.category}</td>"
                f"<td>{r.scaffolder_attempts}</td><td>{r.exploiter_attempts}</td>"
                f"<td>{r.feedback_attempts}</td><td>{status}</td>"
                f"<td>{r.duration_seconds:.1f}s</td></tr>\n"
            )

        llm_info = f"{self.llm.provider}/{self.llm.model}" if self.llm else "N/A"
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

        html = f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>PrivEscGen Build Report</title>
<style>
  body {{ font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
         margin: 2rem; background: #f8f9fa; color: #212529; }}
  h1 {{ color: #1a73e8; }}
  .summary {{ display: flex; gap: 1.5rem; margin: 1.5rem 0; flex-wrap: wrap; }}
  .card {{ background: #fff; border-radius: 8px; padding: 1.2rem 1.5rem;
           box-shadow: 0 1px 3px rgba(0,0,0,.12); min-width: 120px; }}
  .card .label {{ font-size: .85rem; color: #5f6368; }}
  .card .value {{ font-size: 1.8rem; font-weight: 700; }}
  .card .value.green {{ color: #1e8e3e; }}
  .card .value.red {{ color: #d93025; }}
  .card .value.amber {{ color: #e8710a; }}
  table {{ border-collapse: collapse; width: 100%; background: #fff;
           border-radius: 8px; overflow: hidden; box-shadow: 0 1px 3px rgba(0,0,0,.12);
           margin-bottom: 1.5rem; }}
  th {{ background: #1a73e8; color: #fff; padding: .7rem 1rem; text-align: left; font-weight: 500; }}
  td {{ padding: .6rem 1rem; border-bottom: 1px solid #e8eaed; }}
  tr:hover {{ background: #f1f3f4; }}
  .pass {{ color: #1e8e3e; font-weight: 600; }}
  .fail {{ color: #d93025; font-weight: 600; }}
  .review {{ color: #e8710a; font-weight: 600; }}
  .meta {{ color: #5f6368; font-size: .85rem; margin-top: 1.5rem; }}
</style>
</head>
<body>
<h1>PrivEscGen Build Report</h1>
<div class="summary">
  <div class="card"><div class="label">Total</div><div class="value">{total}</div></div>
  <div class="card"><div class="label">Passed</div><div class="value green">{passed}</div></div>
  <div class="card"><div class="label">Failed</div><div class="value red">{failed}</div></div>
  <div class="card"><div class="label">Review</div><div class="value amber">{review}</div></div>
  <div class="card"><div class="label">Pass Rate</div><div class="value">{rate}%</div></div>
</div>

<h2>By Category</h2>
<table>
<tr><th>Category</th><th>Total</th><th>Passed</th><th>Pass Rate</th></tr>
{cat_rows}</table>

<h2>By Difficulty</h2>
<table>
<tr><th>Difficulty</th><th>Total</th><th>Passed</th><th>Pass Rate</th></tr>
{diff_rows}</table>

<h2>Scenario Details</h2>
<table>
<tr><th>Scenario</th><th>Type</th><th>Difficulty</th><th>Category</th>
<th>Scaffolder</th><th>Exploiter</th><th>Feedback</th><th>Status</th><th>Time</th></tr>
{scenario_rows}</table>

<div class="meta">
  Generated: {timestamp} | LLM: {llm_info} | Duration: {duration:.1f}s
</div>
</body>
</html>"""
        output_path.write_text(html)
        logger.info(f"HTML report exported to {output_path}")
