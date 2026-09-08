#!/usr/bin/env python3
"""
PrivEscalate evaluation scheduler.

Runs any supported agent/model selection over the packaged environments.

Supports checkpoint/resume, parallel execution, cost tracking, and priority ordering.

Usage:
  python scripts/run_experiments.py --dry-run
  python scripts/run_experiments.py --priority --parallel 2
  python scripts/run_experiments.py --model gpt-4.1 --subset 5
  python scripts/run_experiments.py --resume
"""

import argparse
import json
import logging
import os
import signal
import subprocess
import sys
import time
from collections import defaultdict
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Optional
from urllib.parse import urlparse

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    datefmt="%H:%M:%S",
)
logger = logging.getLogger(__name__)

PROJECT_ROOT = Path(__file__).parent.parent
RESULTS_DIR = PROJECT_ROOT / "results"
PROGRESS_FILE = RESULTS_DIR / "progress.json"

# Ensure evaluation package is importable
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------

AGENTS = ["wintermute", "hacksynth", "privescagent"]

MODELS = [
    # Supported model aliases; arbitrary OpenAI-compatible model IDs may also
    # be supplied with the corresponding endpoint configuration.
    "claude-sonnet-4-6",          # Anthropic — Claude frontier
    "claude-haiku-4-5",           # Anthropic — Claude lightweight
    "gpt-4.1",                    # OpenAI API or compatible endpoint
    "deepseek-v3.2",              # OpenAI-compatible endpoint — DeepSeek
    "qwen-plus",                  # Dashscope API — Alibaba Qwen
    "gpt-5.4",                    # User-supplied OpenAI-compatible endpoint
]

# Map short model names -> (provider, actual model ID for API)
# Providers: "anthropic" (Anthropic API), "openai_compat" (OpenAI-compatible
# endpoint — set OPENAI_BASE_URL / OPENAI_API_KEY in .env), "dashscope" (Aliyun).
MODEL_PROVIDER_MAP = {
    "claude-sonnet-4-6":          ("anthropic",     "claude-sonnet-4-6"),
    "claude-haiku-4-5":           ("anthropic",     "claude-haiku-4-5-20251001"),
    "gpt-4.1":                    ("openai_compat", "gpt-4.1"),
    "deepseek-v3.2":              ("openai_compat", "deepseek-v3.2"),
    "qwen-plus":                  ("dashscope",     "qwen-plus"),
    "gpt-5.4":                    ("cpa",           "gpt-5.4"),
}

# Pricing: USD per 1M tokens (input, output)
MODEL_PRICING = {
    "claude-sonnet-4-6":          (3.00, 15.00),
    "claude-haiku-4-5":           (0.80, 4.00),
    "gpt-4.1":                    (2.00, 8.00),
    "deepseek-v3.2":              (0.27, 1.10),
    "qwen-plus":                  (0.80, 2.00),
    "gpt-5.4":                    (2.50, 15.00),
}

LEVELS = [0]
REPS = 1
MAX_STEPS = 20
TEMPERATURE = 0.0
BASE_PORT = 5001
API_KEY_ENV_OVERRIDE: Optional[str] = None
API_URL_ENV_OVERRIDE: Optional[str] = None

DIFFICULTY_ORDER = {"easy": 0, "medium": 1, "hard": 2}


def _load_env_file(path: Path, override: bool = False) -> None:
    """Load simple KEY=VALUE / export KEY=VALUE lines without printing secrets."""
    if not path.exists():
        return
    for raw_line in path.read_text(errors="ignore").splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        if line.startswith("export "):
            line = line[len("export "):].strip()
        key, value = line.split("=", 1)
        key = key.strip()
        value = value.strip().strip('"').strip("'")
        if key and (override or key not in os.environ):
            os.environ[key] = value


def _load_default_env() -> None:
    """Best-effort env loading from the artifact root."""
    _load_env_file(PROJECT_ROOT / ".env")


# ---------------------------------------------------------------------------
# Data structures
# ---------------------------------------------------------------------------

@dataclass
class ExperimentRun:
    """A single experiment run in the matrix."""
    model: str
    agent: str
    level: int
    scenario_id: str
    rep: int
    scenario_dir: str
    difficulty: str = "medium"
    category: str = ""
    scenario_type: str = "core"

    @property
    def run_key(self) -> str:
        return f"{self.model}|{self.agent}|{self.level}|{self.scenario_id}|{self.rep}"

    @property
    def experiment_id(self) -> str:
        return f"{self.agent}_{self.model}"


@dataclass
class RunResult:
    """Result of a single experiment run."""
    model: str
    agent: str
    level: int
    scenario_id: str
    rep: int
    success: bool = False
    steps: int = 0
    duration_seconds: float = 0.0
    difficulty: str = "medium"
    category: str = ""
    scenario_type: str = "core"
    input_tokens: int = 0
    output_tokens: int = 0
    cost_usd: float = 0.0
    error: str = ""
    timestamp: str = ""


# ---------------------------------------------------------------------------
# Scenario loading
# ---------------------------------------------------------------------------

def load_scenarios(scenarios_dir: Path, include_types: Optional[set[str]] = None) -> list[dict]:
    """Load all scenario metadata."""
    scenarios = []
    type_dirs = ["core", "variants", "variant"]
    if include_types and "expert" in include_types:
        type_dirs.append("expert")

    for type_dir in type_dirs:
        normalized_type = "variants" if type_dir == "variant" else type_dir
        if include_types and normalized_type not in include_types:
            continue
        sdir = scenarios_dir / type_dir
        if not sdir.exists():
            continue
        for scenario_dir in sorted(sdir.iterdir()):
            if not scenario_dir.is_dir():
                continue
            meta_file = scenario_dir / "metadata.json"
            if not meta_file.exists():
                continue
            meta = json.loads(meta_file.read_text())
            meta["_dir"] = str(scenario_dir)
            meta["_type"] = normalized_type
            scenarios.append(meta)
    return scenarios


# ---------------------------------------------------------------------------
# Experiment matrix
# ---------------------------------------------------------------------------

def build_experiment_matrix(
    scenarios: list[dict],
    agent_filter: Optional[str] = None,
    model_filter: Optional[str] = None,
    subset: Optional[int] = None,
) -> list[ExperimentRun]:
    """Build the full experiment matrix.

    By default, run wintermute with every configured model at level 0.
    Agent and model filters select a smaller evaluation matrix.
    """
    runs = []
    seen_keys = set()

    def _add_runs(agent: str, model: str, levels: list[int], scenario_list: list[dict]):
        for scenario in scenario_list:
            sid = scenario.get("scenario_id", scenario.get("name", "unknown"))
            for level in levels:
                for rep in range(REPS):
                    run = ExperimentRun(
                        model=model,
                        agent=agent,
                        level=level,
                        scenario_id=sid,
                        rep=rep,
                        scenario_dir=scenario["_dir"],
                        difficulty=scenario.get("difficulty", "medium"),
                        category=scenario.get("category", ""),
                        scenario_type=scenario.get("type", scenario.get("_type", "core")),
                    )
                    if run.run_key not in seen_keys:
                        seen_keys.add(run.run_key)
                        runs.append(run)

    effective_scenarios = scenarios[:subset] if subset else scenarios

    # Primary eval: wintermute x all models x levels
    if agent_filter is None or agent_filter == "wintermute":
        models = [model_filter] if model_filter else MODELS
        for model in models:
            _add_runs("wintermute", model, LEVELS, effective_scenarios)

    # Agent comparison: hacksynth and privescagent
    if agent_filter and agent_filter != "wintermute":
        models = [model_filter] if model_filter else ["claude-sonnet-4-6"]
        for model in models:
            _add_runs(agent_filter, model, LEVELS, effective_scenarios)

    return runs


def print_matrix_summary(runs: list[ExperimentRun]) -> None:
    """Print a summary of the experiment matrix."""
    # Group by (agent, model)
    groups = defaultdict(lambda: defaultdict(int))
    for r in runs:
        groups[(r.agent, r.model)][r.level] += 1

    total = len(runs)
    unique_scenarios = len({r.scenario_id for r in runs})
    unique_models = len({r.model for r in runs})
    unique_agents = len({r.agent for r in runs})

    print("\n" + "=" * 72)
    print("PRIVESCALATE EXPERIMENT MATRIX")
    print("=" * 72)
    print(f"  Total runs:       {total}")
    print(f"  Unique scenarios: {unique_scenarios}")
    print(f"  Models:           {unique_models} ({', '.join(sorted({r.model for r in runs}))})")
    print(f"  Agents:           {unique_agents} ({', '.join(sorted({r.agent for r in runs}))})")
    print(f"  Reps per tuple:   {REPS}")
    print(f"  Max steps:        {MAX_STEPS}")
    print(f"  Temperature:      {TEMPERATURE}")
    print()

    print(f"  {'Agent':<15} {'Model':<20} {'L0':>5} {'L1':>5} {'L2':>5} {'Total':>7}")
    print(f"  {'-'*15} {'-'*20} {'-'*5} {'-'*5} {'-'*5} {'-'*7}")
    for (agent, model), levels in sorted(groups.items()):
        l0 = levels.get(0, 0)
        l1 = levels.get(1, 0)
        l2 = levels.get(2, 0)
        row_total = l0 + l1 + l2
        print(f"  {agent:<15} {model:<20} {l0:>5} {l1:>5} {l2:>5} {row_total:>7}")

    # Estimated cost
    est_cost = _estimate_total_cost(runs)
    print(f"\n  Estimated max cost: ${est_cost:,.2f}")
    print("=" * 72 + "\n")


def _estimate_total_cost(runs: list[ExperimentRun]) -> float:
    """Rough cost estimate assuming ~20k input + 5k output tokens per run."""
    est_input = 20_000
    est_output = 5_000
    total = 0.0
    for r in runs:
        pricing = MODEL_PRICING.get(r.model, (0, 0))
        total += est_input * pricing[0] / 1_000_000
        total += est_output * pricing[1] / 1_000_000
    return round(total, 2)


# ---------------------------------------------------------------------------
# Checkpoint / resume
# ---------------------------------------------------------------------------

def load_completed_keys(experiment_id: str) -> set[str]:
    """Load already-completed run keys from JSONL results file."""
    completed = set()
    results_file = RESULTS_DIR / f"{experiment_id}.jsonl"
    if results_file.exists():
        for line in results_file.read_text().strip().split("\n"):
            if not line.strip():
                continue
            try:
                rec = json.loads(line)
                if rec.get("error"):
                    continue
                key = f"{rec['model']}|{rec['agent']}|{rec['level']}|{rec['scenario_id']}|{rec['rep']}"
                completed.add(key)
            except (json.JSONDecodeError, KeyError):
                continue
    return completed


def load_all_completed_keys() -> set[str]:
    """Load completed keys across all experiment JSONL files."""
    completed = set()
    if not RESULTS_DIR.exists():
        return completed
    for f in RESULTS_DIR.glob("*.jsonl"):
        for line in f.read_text().strip().split("\n"):
            if not line.strip():
                continue
            try:
                rec = json.loads(line)
                if rec.get("error"):
                    continue
                key = f"{rec['model']}|{rec['agent']}|{rec['level']}|{rec['scenario_id']}|{rec['rep']}"
                completed.add(key)
            except (json.JSONDecodeError, KeyError):
                continue
    return completed


def save_result(result: RunResult) -> None:
    """Append a result to the appropriate JSONL file."""
    RESULTS_DIR.mkdir(parents=True, exist_ok=True)
    experiment_id = f"{result.agent}_{result.model}"
    results_file = RESULTS_DIR / f"{experiment_id}.jsonl"
    result_key = f"{result.model}|{result.agent}|{result.level}|{result.scenario_id}|{result.rep}"
    existing = []
    if results_file.exists():
        for line in results_file.read_text().splitlines():
            if not line.strip():
                continue
            try:
                rec = json.loads(line)
                key = f"{rec['model']}|{rec['agent']}|{rec['level']}|{rec['scenario_id']}|{rec['rep']}"
            except (json.JSONDecodeError, KeyError):
                existing.append(line)
                continue
            if key != result_key:
                existing.append(line)

    existing.append(json.dumps(asdict(result), ensure_ascii=False))
    results_file.write_text("\n".join(existing) + "\n")


def update_progress(completed: int, total: int, current_cost: float) -> None:
    """Update the progress tracking file."""
    RESULTS_DIR.mkdir(parents=True, exist_ok=True)
    progress = {
        "completed": completed,
        "total": total,
        "percent": round(completed / total * 100, 1) if total > 0 else 0,
        "running_cost_usd": round(current_cost, 4),
        "last_updated": time.strftime("%Y-%m-%d %H:%M:%S"),
    }
    PROGRESS_FILE.write_text(json.dumps(progress, indent=2))


# ---------------------------------------------------------------------------
# Cost tracking
# ---------------------------------------------------------------------------

def compute_cost(model: str, input_tokens: int, output_tokens: int) -> float:
    """Compute USD cost for a model run."""
    pricing = MODEL_PRICING.get(model, (0, 0))
    cost = input_tokens * pricing[0] / 1_000_000 + output_tokens * pricing[1] / 1_000_000
    return round(cost, 6)


# ---------------------------------------------------------------------------
# Single run execution
# ---------------------------------------------------------------------------

def _setup_adapter_env(run: ExperimentRun) -> None:
    """Set environment variables for the adapter based on model/provider."""
    provider, model_id = MODEL_PROVIDER_MAP.get(run.model, ("cpa", run.model))

    os.environ["PRIVESC_AGENT_MODEL"] = model_id
    os.environ["PRIVESC_MODEL_NAME"] = run.model
    os.environ["PRIVESC_TEMPERATURE"] = str(TEMPERATURE)

    # Reset api_path (glm uses non-standard path)
    os.environ.pop("CPA_API_PATH", None)

    if provider == "openai_compat":
        api_url = os.getenv("OPENAI_BASE_URL", "")
        api_key = os.getenv("OPENAI_API_KEY", "")
    elif provider == "anthropic":
        api_url = os.getenv("ANTHROPIC_BASE_URL", "https://api.anthropic.com")
        api_key = os.getenv("ANTHROPIC_API_KEY", "")
    elif provider == "dashscope":
        api_url = os.getenv("DASHSCOPE_API_URL", "https://dashscope-intl.aliyuncs.com/compatible-mode")
        api_key = os.getenv("DASHSCOPE_API_KEY", "")
    else:  # cpa (generic OpenAI-compatible proxy)
        api_url = os.getenv("CPA_API_URL", "")
        api_key = os.getenv("CPA_API_KEY", "")

    if API_URL_ENV_OVERRIDE:
        api_url = os.getenv(API_URL_ENV_OVERRIDE, "")
    if API_KEY_ENV_OVERRIDE:
        api_key = os.getenv(API_KEY_ENV_OVERRIDE, "")

    # hackingBuddyGPT concatenates CPA_API_URL + CPA_API_PATH. DashScope's
    # OpenAI-compatible base URL commonly already ends in /v1, so keep the
    # final request at .../v1/chat/completions instead of .../v1/v1/...
    parsed_path = urlparse(api_url).path.rstrip("/")
    if parsed_path.endswith("/v1"):
        os.environ["CPA_API_PATH"] = "/chat/completions"

    os.environ["CPA_API_URL"] = api_url
    os.environ["CPA_API_KEY"] = api_key
    os.environ["PRIVESC_API_URL"] = api_url
    os.environ["PRIVESC_API_KEY"] = api_key


def _validate_model_env(model: str) -> None:
    """Fail fast on missing provider credentials before launching Docker runs."""
    provider, _ = MODEL_PROVIDER_MAP.get(model, ("cpa", model))
    if provider == "dashscope":
        api_key = os.getenv(API_KEY_ENV_OVERRIDE or "DASHSCOPE_API_KEY", "")
        if not api_key:
            raise SystemExit(
                "qwen-plus requires DASHSCOPE_API_KEY. Source the .env file or pass "
                "--api-key-env with a populated variable."
            )
    elif provider == "openai_compat":
        api_key = os.getenv(API_KEY_ENV_OVERRIDE or "OPENAI_API_KEY", "")
        api_url = os.getenv(API_URL_ENV_OVERRIDE or "OPENAI_BASE_URL", "")
        if not api_key or not api_url:
            raise SystemExit(
                f"{model} requires OPENAI_API_KEY and OPENAI_BASE_URL, or explicit "
                "--api-key-env/--api-url-env overrides."
            )
    elif provider == "anthropic":
        api_key = os.getenv(API_KEY_ENV_OVERRIDE or "ANTHROPIC_API_KEY", "")
        if not api_key:
            raise SystemExit(
                f"{model} requires ANTHROPIC_API_KEY, or an explicit --api-key-env override."
            )


def _create_adapter(agent_name: str):
    """Create the appropriate adapter based on agent name."""
    if agent_name == "wintermute":
        from evaluation.adapters.wintermute import WintermuteAdapter
        return WintermuteAdapter()
    elif agent_name == "hacksynth":
        from evaluation.adapters.hacksynth_adapter import HackSynthAdapter
        return HackSynthAdapter()
    elif agent_name == "privescagent":
        from evaluation.adapters.privescagent_adapter import PrivEscAgentAdapter
        return PrivEscAgentAdapter()
    else:
        raise ValueError(f"Unknown agent: {agent_name}")


def execute_run(run: ExperimentRun, port: int) -> RunResult:
    """Execute a single experiment run: Docker container + adapter directly."""
    from evaluation.runner import ScenarioRunner, build_agent_info, load_hints

    result = RunResult(
        model=run.model,
        agent=run.agent,
        level=run.level,
        scenario_id=run.scenario_id,
        rep=run.rep,
        difficulty=run.difficulty,
        category=run.category,
        scenario_type=run.scenario_type,
        timestamp=time.strftime("%Y-%m-%dT%H:%M:%S"),
    )

    # Configure adapter environment
    _setup_adapter_env(run)

    # Create adapter based on agent type
    adapter = _create_adapter(run.agent)

    # Check if already completed (checkpoint/resume)
    # Not all adapters support is_completed; skip check if unavailable
    if hasattr(adapter, 'is_completed') and adapter.is_completed(run.scenario_id, run.level):
        logger.info(f"  Already completed, skipping: {run.scenario_id} L{run.level}")
        # Load existing result
        try:
            result_file = adapter._run_dir(run.scenario_id) / f"L{run.level}_result.json"
            data = json.loads(result_file.read_text())
            result.success = data.get("success", False)
            result.steps = data.get("steps", 0)
            result.duration_seconds = data.get("duration", 0)
            result.input_tokens = data.get("input_tokens", 0)
            result.output_tokens = data.get("output_tokens", 0)
            result.cost_usd = data.get("cost_usd", 0)
        except (OSError, json.JSONDecodeError):
            pass
        return result

    # Load scenario metadata
    scenario_dir = Path(run.scenario_dir)
    meta = {}
    meta_file = scenario_dir / "metadata.json"
    if meta_file.exists():
        meta = json.loads(meta_file.read_text())

    # Load hints
    hints = load_hints(PROJECT_ROOT)

    # Build agent_info
    agent_info = build_agent_info(meta, port, run.level, hints)

    # Start Docker container
    runner = ScenarioRunner(scenario_dir, port)
    if not runner.start():
        result.error = "Docker container failed to start"
        return result

    try:
        # Run the adapter
        t0 = time.time()
        adapter_result = adapter.run(agent_info, MAX_STEPS, timeout=MAX_STEPS * 30)
        duration = time.time() - t0

        result.success = adapter_result.get("success", False)
        result.steps = adapter_result.get("steps", 0)
        result.duration_seconds = duration
        result.input_tokens = adapter_result.get("input_tokens", 0)
        result.output_tokens = adapter_result.get("output_tokens", 0)
        result.cost_usd = adapter_result.get("cost_usd", 0.0)

        # Save interaction log for non-wintermute adapters
        # (WintermuteAdapter saves its own logs internally)
        raw_output = adapter_result.get("raw_output", "") or adapter_result.get("output_log", "")
        if raw_output and run.agent != "wintermute":
            output_base = Path(os.getenv("PRIVESC_OUTPUT_DIR", "output"))
            log_dir = output_base / run.agent / run.model / run.scenario_id
            log_dir.mkdir(parents=True, exist_ok=True)
            log_file = log_dir / f"L{run.level}_interaction.log"
            header = (
                f"# {run.agent} Run Log\n"
                f"# Model: {run.model}\n"
                f"# Scenario: {run.scenario_id}\n"
                f"# Result: {'SUCCESS' if result.success else 'FAIL'}\n"
                f"# Steps: {result.steps}\n"
                f"# Duration: {result.duration_seconds:.1f}s\n"
                f"# Timestamp: {time.strftime('%Y-%m-%d %H:%M:%S')}\n"
                f"{'=' * 72}\n\n"
            )
            log_file.write_text(header + raw_output, encoding="utf-8")

    except Exception as e:
        result.error = str(e)[:500]
        result.duration_seconds = time.time() - t0 if 't0' in dir() else 0

    finally:
        runner.stop()

    return result


# ---------------------------------------------------------------------------
# Rate limit / backoff
# ---------------------------------------------------------------------------

def backoff_sleep(attempt: int, base: float = 2.0, max_wait: float = 120.0) -> None:
    """Exponential backoff with jitter."""
    import random
    wait = min(base * (2 ** attempt) + random.uniform(0, 1), max_wait)
    logger.warning(f"Rate limited. Backing off {wait:.1f}s (attempt {attempt + 1})")
    time.sleep(wait)


# ---------------------------------------------------------------------------
# Priority ordering
# ---------------------------------------------------------------------------

def sort_by_priority(runs: list[ExperimentRun]) -> list[ExperimentRun]:
    """Sort runs: Easy first, then Medium, then Hard for faster initial results."""
    return sorted(runs, key=lambda r: (
        DIFFICULTY_ORDER.get(r.difficulty, 1),
        r.level,
        r.scenario_id,
        r.rep,
    ))


# ---------------------------------------------------------------------------
# Progress display
# ---------------------------------------------------------------------------

class ProgressTracker:
    """Track and display experiment progress."""

    def __init__(self, total: int):
        self.total = total
        self.completed = 0
        self.successes = 0
        self.failures = 0
        self.errors = 0
        self.total_cost = 0.0
        self.total_tokens = 0
        self.start_time = time.time()
        self._model_results: dict[str, dict] = defaultdict(
            lambda: {"pass": 0, "fail": 0, "error": 0, "cost": 0.0}
        )

    def record(self, result: RunResult) -> None:
        self.completed += 1
        self.total_cost += result.cost_usd
        self.total_tokens += result.input_tokens + result.output_tokens

        if result.error:
            self.errors += 1
            self._model_results[result.model]["error"] += 1
        elif result.success:
            self.successes += 1
            self._model_results[result.model]["pass"] += 1
        else:
            self.failures += 1
            self._model_results[result.model]["fail"] += 1

        self._model_results[result.model]["cost"] += result.cost_usd

    def display(self) -> None:
        elapsed = time.time() - self.start_time
        rate = self.completed / elapsed if elapsed > 0 else 0
        remaining = (self.total - self.completed) / rate if rate > 0 else 0

        pct = self.completed / self.total * 100 if self.total > 0 else 0
        bar_len = 40
        filled = int(bar_len * self.completed / self.total) if self.total > 0 else 0
        bar = "#" * filled + "-" * (bar_len - filled)

        eta_min = remaining / 60
        elapsed_min = elapsed / 60

        print(
            f"\r  [{bar}] {pct:5.1f}% "
            f"({self.completed}/{self.total}) "
            f"P:{self.successes} F:{self.failures} E:{self.errors} "
            f"${self.total_cost:.2f} "
            f"ETA:{eta_min:.0f}m "
            f"({elapsed_min:.0f}m elapsed)",
            end="", flush=True,
        )

    def print_model_summary(self, model: str) -> None:
        """Print summary after all runs for a model complete."""
        m = self._model_results.get(model, {})
        total = m.get("pass", 0) + m.get("fail", 0) + m.get("error", 0)
        sr = m["pass"] / total * 100 if total > 0 else 0
        print(f"\n\n  --- Model complete: {model} ---")
        print(f"      Runs: {total}  Pass: {m['pass']}  Fail: {m['fail']}  Error: {m.get('error', 0)}")
        print(f"      SR: {sr:.1f}%  Cost: ${m['cost']:.2f}")
        print()


# ---------------------------------------------------------------------------
# Container cleanup handler
# ---------------------------------------------------------------------------

_containers_to_clean: list[str] = []


def _cleanup_handler(signum, frame):
    """Clean up Docker containers on Ctrl+C."""
    print("\n\nInterrupted. Cleaning up containers...")
    for cname in _containers_to_clean:
        try:
            subprocess.run(
                ["docker", "rm", "-f", cname],
                capture_output=True, timeout=10,
            )
        except Exception:
            pass
    sys.exit(1)


# ---------------------------------------------------------------------------
# Main execution
# ---------------------------------------------------------------------------

def run_experiments(
    runs: list[ExperimentRun],
    parallel: int = 1,
    priority: bool = False,
) -> None:
    """Execute the experiment matrix with checkpoint/resume."""
    # Load completed runs
    completed_keys = load_all_completed_keys()
    pending = [r for r in runs if r.run_key not in completed_keys]

    if not pending:
        print("All runs already completed. Nothing to do.")
        return

    skipped = len(runs) - len(pending)
    if skipped > 0:
        logger.info(f"Resuming: {skipped} runs already completed, {len(pending)} remaining")

    if priority:
        pending = sort_by_priority(pending)

    # Setup
    signal.signal(signal.SIGINT, _cleanup_handler)
    (RESULTS_DIR / "tmp").mkdir(parents=True, exist_ok=True)

    tracker = ProgressTracker(len(pending))
    port_base = BASE_PORT
    active_models = set()

    if parallel <= 1:
        # Sequential execution
        for i, run in enumerate(pending):
            port = port_base + (i % 100)
            logger.info(
                f"[{i+1}/{len(pending)}] {run.agent}/{run.model} "
                f"L{run.level} {run.scenario_id} rep{run.rep}"
            )

            max_retries = 3
            for attempt in range(max_retries):
                result = execute_run(run, port)

                if result.error and "rate" in result.error.lower():
                    backoff_sleep(attempt)
                    continue
                break

            save_result(result)
            tracker.record(result)
            tracker.display()
            update_progress(tracker.completed, tracker.total, tracker.total_cost)

            # Print model summary when model transitions
            prev_model = run.model
            active_models.add(run.model)
            if i + 1 < len(pending) and pending[i + 1].model != prev_model:
                tracker.print_model_summary(prev_model)

    else:
        # Parallel execution with thread pool
        def _run_with_port(args):
            run, port = args
            max_retries = 3
            for attempt in range(max_retries):
                result = execute_run(run, port)
                if result.error and "rate" in result.error.lower():
                    backoff_sleep(attempt)
                    continue
                break
            return result

        work_items = [
            (run, port_base + (i % (parallel * 50)))
            for i, run in enumerate(pending)
        ]

        with ThreadPoolExecutor(max_workers=parallel) as executor:
            futures = {
                executor.submit(_run_with_port, item): item[0]
                for item in work_items
            }

            for future in as_completed(futures):
                run = futures[future]
                try:
                    result = future.result()
                except Exception as e:
                    result = RunResult(
                        model=run.model, agent=run.agent, level=run.level,
                        scenario_id=run.scenario_id, rep=run.rep,
                        error=str(e)[:500],
                        timestamp=time.strftime("%Y-%m-%dT%H:%M:%S"),
                    )

                save_result(result)
                tracker.record(result)
                tracker.display()
                update_progress(tracker.completed, tracker.total, tracker.total_cost)

    # Final summary
    print("\n\n" + "=" * 72)
    print("EXPERIMENT COMPLETE")
    print("=" * 72)
    print(f"  Total runs:  {tracker.completed}")
    print(f"  Passed:      {tracker.successes}")
    print(f"  Failed:      {tracker.failures}")
    print(f"  Errors:      {tracker.errors}")
    print(f"  Total cost:  ${tracker.total_cost:.2f}")
    print(f"  Total tokens: {tracker.total_tokens:,}")
    elapsed = time.time() - tracker.start_time
    print(f"  Wall time:   {elapsed/3600:.1f}h")
    print("=" * 72)

    # Write final aggregated results
    _write_aggregated_results()


def _write_aggregated_results() -> None:
    """Aggregate all JSONL files into a single results JSON."""
    all_results = []
    if not RESULTS_DIR.exists():
        return
    for f in sorted(RESULTS_DIR.glob("*.jsonl")):
        for line in f.read_text().strip().split("\n"):
            if not line.strip():
                continue
            try:
                all_results.append(json.loads(line))
            except json.JSONDecodeError:
                continue

    if not all_results:
        return

    output = {
        "metadata": {
            "total_runs": len(all_results),
            "models": sorted({r["model"] for r in all_results}),
            "agents": sorted({r["agent"] for r in all_results}),
            "generated": time.strftime("%Y-%m-%dT%H:%M:%S"),
            "max_steps": MAX_STEPS,
            "temperature": TEMPERATURE,
            "reps": REPS,
        },
        "results": all_results,
    }

    out_file = RESULTS_DIR / "all_results.json"
    out_file.write_text(json.dumps(output, indent=2, ensure_ascii=False))
    logger.info(f"Aggregated results written to {out_file}")


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def main():
    _load_default_env()

    parser = argparse.ArgumentParser(
        description="PrivEscalate Experiment Scheduler",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Dry run: show the experiment matrix
  python scripts/run_experiments.py --dry-run

  # Run only gpt-4.1, easy scenarios first
  python scripts/run_experiments.py --model gpt-4.1 --priority

  # Run 5 scenarios for testing
  python scripts/run_experiments.py --subset 5

  # Resume interrupted run with 2 parallel workers
  python scripts/run_experiments.py --parallel 2

  # Single agent comparison
  python scripts/run_experiments.py --agent hacksynth --model claude-sonnet-4-6

  # Use non-default environment variable names for the API endpoint/key
  python scripts/run_experiments.py --model deepseek-v3.2 \\
      --api-key-env DEEPSEEK_API_KEY --api-url-env DEEPSEEK_BASE_URL
        """,
    )

    parser.add_argument("--dry-run", action="store_true",
                        help="Print experiment matrix without running")
    parser.add_argument("--priority", action="store_true",
                        help="Run Easy scenarios first, then Medium, then Hard")
    parser.add_argument("--subset", type=int, default=None,
                        help="Only use N scenarios (for testing)")
    parser.add_argument("--agent", type=str, default=None,
                        choices=AGENTS,
                        help="Only run one agent")
    parser.add_argument("--model", type=str, default=None,
                        choices=MODELS,
                        help="Only run one model")
    parser.add_argument("--parallel", type=int, default=1,
                        help="Number of parallel workers (different Docker ports)")
    parser.add_argument("--scenarios-dir", type=str, default="dataset/scenarios",
                        help="Scenarios directory (default: dataset/scenarios)")
    parser.add_argument("--base-port", type=int, default=None,
                        help="Starting Docker port (default: 5001). Use different ports for parallel experiments.")
    parser.add_argument("--resume", action="store_true",
                        help="Explicitly resume from checkpoint (default behavior)")
    parser.add_argument("--results-dir", type=str, default=None,
                        help="Output directory for generated evaluation records (default: results/).")
    parser.add_argument("--scenario-type", type=str, default=None,
                        help="Comma-separated scenario types to run: core, variants, expert")
    parser.add_argument("--api-key-env", type=str, default=None,
                        help="Environment variable name containing the API key. Overrides provider defaults.")
    parser.add_argument("--api-url-env", type=str, default=None,
                        help="Environment variable name containing the API base URL. Overrides provider defaults.")
    parser.add_argument("-v", "--verbose", action="store_true")

    args = parser.parse_args()
    if args.verbose:
        logging.getLogger().setLevel(logging.DEBUG)

    for option, env_name in (
        ("--api-key-env", args.api_key_env),
        ("--api-url-env", args.api_url_env),
    ):
        if env_name and not os.getenv(env_name):
            parser.error(f"{option} points to unset or empty environment variable: {env_name}")

    global API_KEY_ENV_OVERRIDE, API_URL_ENV_OVERRIDE
    API_KEY_ENV_OVERRIDE = args.api_key_env
    API_URL_ENV_OVERRIDE = args.api_url_env

    # A dry run only inspects the matrix and must not require provider secrets.
    if args.model and not args.dry_run:
        _validate_model_env(args.model)

    include_types = None
    if args.scenario_type:
        include_types = {t.strip() for t in args.scenario_type.split(",") if t.strip()}
        invalid_types = include_types - {"core", "variants", "expert"}
        if invalid_types:
            parser.error(f"invalid --scenario-type value(s): {', '.join(sorted(invalid_types))}")

    # Override results directory if specified
    global RESULTS_DIR, PROGRESS_FILE
    if args.results_dir:
        RESULTS_DIR = PROJECT_ROOT / args.results_dir
        PROGRESS_FILE = RESULTS_DIR / "progress.json"

    # Load scenarios
    scenarios_dir = PROJECT_ROOT / args.scenarios_dir
    scenarios = load_scenarios(scenarios_dir, include_types=include_types)
    if include_types:
        logger.info(f"Filtered to {len(scenarios)} scenario(s) of type: {', '.join(sorted(include_types))}")

    if not scenarios:
        logger.error(f"No scenarios found in {scenarios_dir}")
        sys.exit(1)

    logger.info(f"Loaded {len(scenarios)} scenarios from {scenarios_dir}")

    # Build matrix
    runs = build_experiment_matrix(
        scenarios,
        agent_filter=args.agent,
        model_filter=args.model,
        subset=args.subset,
    )

    if not runs:
        logger.error("No experiment runs generated. Check filters.")
        sys.exit(1)

    # Always show matrix summary
    print_matrix_summary(runs)

    if args.dry_run:
        # In dry-run, also show first few runs
        print("First 20 runs:")
        if args.priority:
            runs = sort_by_priority(runs)
        for r in runs[:20]:
            print(f"  {r.agent:15s} {r.model:20s} L{r.level} {r.difficulty:8s} {r.scenario_id} rep{r.rep}")
        if len(runs) > 20:
            print(f"  ... and {len(runs) - 20} more")
        return

    # Override base port if specified
    global BASE_PORT
    if args.base_port is not None:
        BASE_PORT = args.base_port

    # Execute
    run_experiments(runs, parallel=args.parallel, priority=args.priority)


if __name__ == "__main__":
    main()
