"""
PrivEscAgent Adapter for PrivEscalate Evaluation.

Calls hackingBuddyGPT CLI with "PrivEscAgent" UseCase via subprocess.
Structurally identical to WintermuteAdapter, differing only in:
  - UseCase name: "PrivEscAgent" instead of "LinuxPrivesc"
  - Output directory: "privescagent" instead of "wintermute"
  - Ablation support via extra CLI args
"""

import json
import logging
import os
import re
import sqlite3
import subprocess
import sys
import time
from pathlib import Path
from typing import Optional
from urllib.parse import urlparse

logger = logging.getLogger(__name__)

PROJECT_ROOT = Path(__file__).parent.parent.parent

# Pricing: USD per 1M tokens (input, output)
MODEL_PRICING = {
    # Anthropic: https://platform.claude.com/docs/en/about-claude/pricing
    "claude-opus-4-6":            (15.00, 75.00),
    "claude-sonnet-4-6":          (3.00, 15.00),
    "claude-haiku-4-5":           (1.00, 5.00),
    # OpenAI: https://developers.openai.com/api/docs/pricing
    "gpt-4.1":                    (2.00, 8.00),
    # DeepSeek: https://api-docs.deepseek.com/quick_start/pricing (cache miss)
    "deepseek-v3.2":              (0.56, 1.68),
    # Alibaba Qwen: https://www.alibabacloud.com/help/en/model-studio/model-pricing
    "qwen-plus":                  (0.26, 0.78),
}


class PrivEscAgentAdapter:
    """
    Adapter for PrivEscAgent via hackingBuddyGPT CLI.

    Configuration via environment variables:
      CPA_API_URL          — API base URL
      CPA_API_KEY          — API key
      PRIVESC_AGENT_MODEL  — model name (default: claude-sonnet-4-6)

    Ablation configuration:
      PRIVESCAGENT_DISABLE_PRIVENUM          — disable PrivEnum module
      PRIVESCAGENT_DISABLE_CATEGORY_MATCHER  — disable CategoryMatcher
      PRIVESCAGENT_DISABLE_STEP_PLANNER      — disable StepPlanner
      PRIVESCAGENT_DISABLE_STRATEGY_SELECTOR — disable StrategySelector
    """

    _RE_TURN = re.compile(r"Starting turn (\d+)")
    _RE_SUCCESS = re.compile(
        r"(Run was a success|Run finished successfully)", re.IGNORECASE
    )
    _RE_FAILURE = re.compile(
        r"(maximum turn number reached|Run failed)", re.IGNORECASE
    )

    # Provider defaults. PRIVESC_API_URL/PRIVESC_API_KEY always take priority.
    # PrivEscAgent runs through hackingBuddyGPT's OpenAI-compatible connector,
    # so Claude models require a compatible gateway supplied by the evaluator.
    PROVIDER_CONFIGS = {
        "claude-sonnet-4-6": {
            "api_url": os.getenv("CPA_API_URL", ""),
            "api_key_env": "CPA_API_KEY",
            "api_key_default": "",
            "context_size": 200000,
        },
        "claude-haiku-4-5": {
            "api_url": os.getenv("CPA_API_URL", ""),
            "api_key_env": "CPA_API_KEY",
            "api_key_default": "",
            "context_size": 200000,
        },
        "gpt-4.1": {
            "api_url": os.getenv("OPENAI_BASE_URL", "https://api.openai.com"),
            "api_key_env": "OPENAI_API_KEY",
            "api_key_default": "",
            "context_size": 1047576,
        },
        "deepseek-v3.2": {
            "api_url": os.getenv("DEEPSEEK_BASE_URL", "https://api.deepseek.com"),
            "api_key_env": "DEEPSEEK_API_KEY",
            "api_key_default": "",
            "context_size": 128000,
        },
        "qwen-plus": {
            "api_url": "https://dashscope-intl.aliyuncs.com/compatible-mode",
            "api_key_env": "DASHSCOPE_API_KEY",
            "api_key_default": "",
            "context_size": 128000,
        },
    }

    def __init__(self, **kwargs):
        self.model = os.getenv("PRIVESC_AGENT_MODEL", "claude-sonnet-4-6")
        self.model_name = os.getenv("PRIVESC_MODEL_NAME", self.model)

        # Auto-select API config based on model.
        provider = self.PROVIDER_CONFIGS.get(self.model, {
            "api_url": os.getenv("CPA_API_URL", ""),
            "api_key_env": "CPA_API_KEY",
            "api_key_default": "",
            "context_size": 200000,
        })
        self.api_url = os.getenv("PRIVESC_API_URL", provider["api_url"])
        self.api_key = os.getenv("PRIVESC_API_KEY", os.getenv(provider["api_key_env"], provider["api_key_default"]))
        self.api_path = self._default_api_path(self.api_url)
        self.context_size = provider["context_size"]

        # Ablation flags
        self.disable_privenum = os.getenv("PRIVESCAGENT_DISABLE_PRIVENUM", "").lower() in ("1", "true")
        self.disable_category_matcher = os.getenv("PRIVESCAGENT_DISABLE_CATEGORY_MATCHER", "").lower() in ("1", "true")
        self.disable_step_planner = os.getenv("PRIVESCAGENT_DISABLE_STEP_PLANNER", "").lower() in ("1", "true")
        self.disable_strategy_selector = os.getenv("PRIVESCAGENT_DISABLE_STRATEGY_SELECTOR", "").lower() in ("1", "true")

    @staticmethod
    def _default_api_path(api_url: str) -> str:
        """Avoid appending /v1 twice when a proxy base URL already includes it."""
        path = urlparse(api_url).path.rstrip("/")
        return "/chat/completions" if path.endswith("/v1") else "/v1/chat/completions"

    @property
    def available(self) -> bool:
        return True

    def _run_dir(self, scenario_id: str) -> Path:
        output_base = Path(os.getenv("PRIVESC_OUTPUT_DIR", "output"))
        if not output_base.is_absolute():
            output_base = PROJECT_ROOT / output_base
        return output_base / "privescagent" / self.model_name / scenario_id

    def is_completed(self, scenario_id: str, level: int) -> bool:
        result_file = self._run_dir(scenario_id) / f"L{level}_result.json"
        return result_file.exists()

    def run(
        self,
        agent_info: dict,
        max_steps: int = 30,
        timeout: int = 300,
    ) -> dict:
        """Run PrivEscAgent against a scenario."""
        t0 = time.time()
        effective_timeout = max(timeout, max_steps * 30)
        scenario_id = agent_info.get("_scenario_id", "unknown")
        level = agent_info.get("level", 0)

        try:
            cmd = self._build_cmd(agent_info, max_steps)
            logger.info(
                f"  Running PrivEscAgent: {scenario_id} L{level} "
                f"({self.model_name}, max={max_steps})"
            )

            prev_max_run_id = self._get_max_run_id()

            child_env = os.environ.copy()
            hb_src = Path(os.getenv(
                "HACKINGBUDDY_SRC",
                str(PROJECT_ROOT / "baselines" / "hackingBuddyGPT" / "src"),
            ))
            python_paths = [str(PROJECT_ROOT)]
            if hb_src.exists():
                python_paths.append(str(hb_src))
            if child_env.get("PYTHONPATH"):
                python_paths.append(child_env["PYTHONPATH"])
            child_env["PYTHONPATH"] = os.pathsep.join(python_paths)

            proc = subprocess.run(
                cmd, capture_output=True, text=True,
                timeout=effective_timeout,
                env=child_env,
            )

            duration = time.time() - t0
            combined = (proc.stdout or "") + "\n" + (proc.stderr or "")

            steps = self._parse_steps(combined)

            # Token counts from SQLite
            db_data = self._read_sqlite_data(after_run_id=prev_max_run_id)
            if db_data:
                input_tokens = db_data["input_tokens"]
                output_tokens = db_data["output_tokens"]
                commands = db_data["commands"]
            else:
                input_tokens = steps * 500
                output_tokens = steps * 100
                commands = self._extract_commands(combined)

            success = self._parse_success(combined, commands)

            cost_usd = self._compute_cost(input_tokens, output_tokens)

            result = {
                "success": success,
                "steps": steps,
                "duration": round(duration, 1),
                "milestones": {},
                "input_tokens": input_tokens,
                "output_tokens": output_tokens,
                "cost_usd": cost_usd,
                "commands": commands,
                "model": self.model_name,
                "model_id": self.model,
                "agent": "privescagent",
                "scenario_id": scenario_id,
                "level": level,
                "difficulty": agent_info.get("difficulty", ""),
                "category": agent_info.get("category", ""),
                "attack_technique": agent_info.get("attack_technique", ""),
                "ablation": self._ablation_config(),
                "timestamp": time.strftime("%Y-%m-%dT%H:%M:%S"),
            }

            self._save_output(result, combined, agent_info)
            return result

        except subprocess.TimeoutExpired:
            duration = time.time() - t0
            logger.error(f"  PrivEscAgent timeout ({effective_timeout}s)")
            result = self._error_result(
                scenario_id, level, duration,
                f"TIMEOUT: {effective_timeout}s", agent_info,
            )
            self._save_output(result, f"TIMEOUT after {effective_timeout}s", agent_info)
            return result

        except Exception as e:
            duration = time.time() - t0
            logger.error(f"  PrivEscAgent error: {e}")
            result = self._error_result(
                scenario_id, level, duration, f"ERROR: {e}", agent_info,
            )
            self._save_output(result, f"ERROR: {e}", agent_info)
            return result

    def _ablation_config(self) -> dict:
        return {
            "privenum": not self.disable_privenum,
            "category_matcher": not self.disable_category_matcher,
            "step_planner": not self.disable_step_planner,
            "strategy_selector": not self.disable_strategy_selector,
        }

    def _build_cmd(self, agent_info: dict, max_steps: int) -> list[str]:
        host = agent_info.get("host", "localhost")
        port = str(agent_info.get("port", 22))
        username = agent_info.get("username", "lowpriv")
        password = agent_info.get("password", "password123")
        hint = agent_info.get("hint", "")

        db_file = f"privescagent_{self.model_name.replace('/', '_')}.sqlite3"
        self._db_file = db_file

        cmd = [
            sys.executable, "-m",
            "hackingBuddyGPT.cli.wintermute", "PrivEscAgent",
            "--llm.api_key", self.api_key,
            "--llm.model", self.model,
            "--llm.api_url", self.api_url,
            "--llm.api_path", self.api_path,
            "--llm.context_size", str(self.context_size),
            "--conn.host", host,
            "--conn.hostname", host,
            "--conn.port", port,
            "--conn.username", username,
            "--conn.password", password,
            "--conn.keyfilename", "",
            "--max_turns", str(max_steps),
            "--log_db.connection_string", db_file,
            "--llm.temperature", "1" if self.model == "claude-sonnet-4-6" else "0",
        ]
        if hint:
            cmd.extend(["--hint", hint])

        # Ablation flags
        if self.disable_privenum:
            cmd.extend(["--disable_privenum", "True"])
        if self.disable_category_matcher:
            cmd.extend(["--disable_category_matcher", "True"])
        if self.disable_step_planner:
            cmd.extend(["--disable_step_planner", "True"])
        if self.disable_strategy_selector:
            cmd.extend(["--disable_strategy_selector", "True"])

        # GTFOBins knowledge base path
        gtfobins_path = str(PROJECT_ROOT / "privescagent" / "knowledge" / "gtfobins_db.json")
        cmd.extend(["--gtfobins_path", gtfobins_path])

        return cmd

    def _compute_cost(self, input_tokens: int, output_tokens: int) -> float:
        pricing = MODEL_PRICING.get(self.model_name, (0, 0))
        cost = input_tokens * pricing[0] / 1_000_000 + output_tokens * pricing[1] / 1_000_000
        return round(cost, 6)

    def _error_result(self, scenario_id, level, duration, error_msg, agent_info):
        return {
            "success": False,
            "steps": 0,
            "duration": round(duration, 1),
            "milestones": {},
            "input_tokens": 0,
            "output_tokens": 0,
            "cost_usd": 0.0,
            "commands": [],
            "error": error_msg,
            "model": self.model_name,
            "model_id": self.model,
            "agent": "privescagent",
            "scenario_id": scenario_id,
            "level": level,
            "difficulty": agent_info.get("difficulty", ""),
            "category": agent_info.get("category", ""),
            "attack_technique": agent_info.get("attack_technique", ""),
            "ablation": self._ablation_config(),
            "timestamp": time.strftime("%Y-%m-%dT%H:%M:%S"),
        }

    def _save_output(self, result: dict, raw_output: str, agent_info: dict):
        scenario_id = result.get("scenario_id", "unknown")
        level = result.get("level", 0)
        run_dir = self._run_dir(scenario_id)
        try:
            run_dir.mkdir(parents=True, exist_ok=True)
            result_file = run_dir / f"L{level}_result.json"
            result_file.write_text(
                json.dumps(result, indent=2, ensure_ascii=False, default=str),
                encoding="utf-8",
            )
            log_file = run_dir / f"L{level}_interaction.log"
            header = (
                f"# PrivEscAgent Run Log\n"
                f"# Model: {self.model_name} ({self.model})\n"
                f"# Scenario: {scenario_id}\n"
                f"# Level: {level}\n"
                f"# Ablation: {json.dumps(self._ablation_config())}\n"
                f"# Target: {agent_info.get('username')}@"
                f"{agent_info.get('host')}:{agent_info.get('port')}\n"
                f"# Result: {'SUCCESS' if result.get('success') else 'FAIL'}\n"
                f"# Steps: {result.get('steps', 0)}\n"
                f"# Duration: {result.get('duration', 0)}s\n"
                f"# Timestamp: {time.strftime('%Y-%m-%d %H:%M:%S')}\n"
                f"{'=' * 72}\n\n"
            )
            log_file.write_text(header + raw_output, encoding="utf-8")
        except OSError as e:
            logger.warning(f"  Failed to save output: {e}")

    def _parse_steps(self, output: str) -> int:
        matches = self._RE_TURN.findall(output)
        return max(int(m) for m in matches) if matches else 0

    def _parse_success(self, output: str, commands: Optional[list[dict]] = None) -> bool:
        if self._RE_SUCCESS.search(output):
            return True
        return self._detect_root_success(commands or [])

    @staticmethod
    def _detect_root_success(commands: list[dict]) -> bool:
        """Detect root from executed command output, not prompts or LLM text."""
        root_patterns = [
            re.compile(r"(?:^|\s)uid=0\(root\)"),
            re.compile(r"(?:^|\s)euid=0(?:\(|\b)"),
            re.compile(r"(?:^|\s)gid=0\(root\)"),
            re.compile(r"(?:^|\s)(?:\x1b\[\?2004h)?root@[A-Za-z0-9_.-]+:[^\r\n#]*#"),
        ]
        for command in commands:
            result = str(command.get("result", ""))
            if any(p.search(result) for p in root_patterns):
                return True
        return False

    def _extract_commands(self, output: str) -> list[dict]:
        """Fallback parser for hackingBuddyGPT rich CLI logs."""
        commands = []
        turn_splits = re.split(r"Starting turn (\d+)", output)
        for i in range(1, len(turn_splits) - 1, 2):
            turn_num = int(turn_splits[i])
            turn_content = turn_splits[i + 1] if i + 1 < len(turn_splits) else ""
            boxes = self._extract_rich_boxes(turn_content)
            if not boxes:
                continue
            cmd_text = boxes[0]
            result_text = boxes[1] if len(boxes) > 1 else ""
            action = "test_credential" if "Authentication " in result_text else "exec_command"
            commands.append({
                "turn": turn_num,
                "action": action,
                "command": cmd_text,
                "result": result_text[:500],
            })
        return commands

    @staticmethod
    def _extract_rich_boxes(text: str) -> list[str]:
        boxes = []
        in_box = False
        current = []
        for line in text.splitlines():
            stripped = line.strip()
            if stripped.startswith("╭"):
                in_box = True
                current = []
                continue
            if stripped.startswith("╰") and in_box:
                content = []
                for raw in current:
                    item = raw.strip()
                    if item.startswith("│"):
                        item = item[1:]
                    if item.endswith("│"):
                        item = item[:-1]
                    item = item.strip()
                    if item:
                        content.append(item)
                if content:
                    boxes.append(" ".join(content))
                in_box = False
                current = []
                continue
            if in_box and stripped.startswith("│"):
                current.append(line)
        return boxes

    def _get_max_run_id(self) -> int:
        db_path = PROJECT_ROOT / getattr(self, '_db_file', 'privescagent.sqlite3')
        if not db_path.exists():
            return 0
        try:
            conn = sqlite3.connect(str(db_path))
            row = conn.execute("SELECT MAX(id) FROM runs").fetchone()
            conn.close()
            return row[0] if row and row[0] else 0
        except (sqlite3.Error, OSError):
            return 0

    def _read_sqlite_data(self, after_run_id: int = 0) -> Optional[dict]:
        db_path = PROJECT_ROOT / getattr(self, '_db_file', 'privescagent.sqlite3')
        if not db_path.exists():
            return None
        try:
            conn = sqlite3.connect(str(db_path))
            row = conn.execute(
                "SELECT id FROM runs WHERE id > ? ORDER BY id DESC LIMIT 1",
                (after_run_id,),
            ).fetchone()
            if not row:
                conn.close()
                return None
            run_id = row[0]
            token_row = conn.execute(
                "SELECT COALESCE(SUM(tokens_query), 0), "
                "       COALESCE(SUM(tokens_response), 0) "
                "FROM messages WHERE run_id = ? AND role = 'assistant'",
                (run_id,),
            ).fetchone()
            input_tokens = token_row[0] if token_row else 0
            output_tokens = token_row[1] if token_row else 0
            commands = []
            tool_rows = conn.execute(
                "SELECT m.id, tc.function_name, tc.arguments, "
                "       tc.result_text, tc.duration "
                "FROM tool_calls tc "
                "JOIN messages m ON tc.run_id = m.run_id "
                "  AND tc.message_id = m.id "
                "WHERE tc.run_id = ? ORDER BY m.id",
                (run_id,),
            ).fetchall()
            for i, tr in enumerate(tool_rows):
                commands.append({
                    "turn": i + 1,
                    "action": tr[1] or "unknown",
                    "command": tr[2] or "",
                    "result": (tr[3] or "")[:500],
                    "duration": round(tr[4], 2) if tr[4] else 0,
                })
            conn.close()
            if input_tokens == 0 and output_tokens == 0:
                return None
            return {
                "input_tokens": input_tokens,
                "output_tokens": output_tokens,
                "commands": commands,
            }
        except (sqlite3.Error, OSError) as e:
            logger.warning(f"  Failed to read SQLite: {e}")
            return None
