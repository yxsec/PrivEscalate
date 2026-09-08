"""
LLM Client for PrivEscGen agents.

Provides a unified interface for calling LLMs (OpenAI, Anthropic, local models).
Used by Scaffolder (variant generation, error fixing) and Exploiter (Mode 3 generation).
"""

import logging
import os
from pathlib import Path
from typing import Optional

logger = logging.getLogger(__name__)
logger.setLevel(logging.DEBUG)

# Runtime log directory.
_LOG_DIR = Path(__file__).parent.parent / "logs"


def _create_task_logger(task_name: str) -> logging.FileHandler:
    """Create a per-task log file: logs/{timestamp}_{task_name}.log"""
    from datetime import datetime
    _LOG_DIR.mkdir(parents=True, exist_ok=True)
    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    safe_name = task_name.replace("/", "_").replace(" ", "_")[:60]
    log_file = _LOG_DIR / f"{ts}_{safe_name}.log"
    handler = logging.FileHandler(log_file, encoding="utf-8")
    handler.setLevel(logging.DEBUG)
    handler.setFormatter(logging.Formatter("%(asctime)s [%(levelname)s] %(message)s"))
    return handler

# Try importing OpenAI
try:
    from openai import OpenAI
    HAS_OPENAI = True
except ImportError:
    HAS_OPENAI = False

# Try importing Anthropic
try:
    import anthropic
    HAS_ANTHROPIC = True
except ImportError:
    HAS_ANTHROPIC = False


class LLMClient:
    """
    Unified LLM client supporting OpenAI and Anthropic APIs.

    Usage:
        client = LLMClient(provider="openai", model="gpt-4o")
        response = client.chat(system_prompt, user_prompt)
    """

    def __init__(
        self,
        provider: str = "openai",
        model: str = "gpt-4o",
        api_key: Optional[str] = None,
        base_url: Optional[str] = None,
        temperature: float = 0.2,
        max_tokens: int = 8192,
        task_name: str = "default",
    ):
        self.provider = provider
        self.model = model
        self.temperature = temperature
        self.max_tokens = max_tokens

        # Per-task log file: logs/{timestamp}_{task_name}.log
        # Remove any previous file handlers to avoid cross-task log pollution
        for h in logger.handlers[:]:
            if isinstance(h, logging.FileHandler):
                logger.removeHandler(h)
                h.close()
        self._log_handler = _create_task_logger(f"{provider}_{model}_{task_name}")
        logger.addHandler(self._log_handler)
        logger.info(f"=== New LLM session: {provider}/{model} task={task_name} ===")

        if provider == "openai":
            if not HAS_OPENAI:
                raise ImportError("pip install openai")
            kwargs = {"api_key": api_key or os.getenv("OPENAI_API_KEY")}
            url = base_url or os.getenv("OPENAI_BASE_URL")
            if url:
                kwargs["base_url"] = url
            self.client = OpenAI(**kwargs)
        elif provider == "anthropic":
            if not HAS_ANTHROPIC:
                raise ImportError("pip install anthropic")
            kwargs = {"api_key": api_key or os.getenv("ANTHROPIC_API_KEY")}
            url = base_url or os.getenv("ANTHROPIC_BASE_URL")
            if url:
                kwargs["base_url"] = url
            self.client = anthropic.Anthropic(**kwargs)
        else:
            raise ValueError(f"Unsupported provider: {provider}")

    # Cumulative token usage tracking
    total_input_tokens: int = 0
    total_output_tokens: int = 0
    total_calls: int = 0

    def chat(self, system_prompt: str, user_prompt: str) -> str:
        """Send a chat request and return the response text.

        Token usage and request/response are logged via logger.
        Cumulative stats available via self.total_input_tokens etc.
        """
        logger.info(
            f"LLM call #{self.total_calls + 1}: {self.provider}/{self.model} "
            f"(system={len(system_prompt)} chars, user={len(user_prompt)} chars)"
        )
        logger.debug(f"LLM REQUEST system: {system_prompt[:200]}...")
        logger.debug(f"LLM REQUEST user: {user_prompt[:500]}...")

        if self.provider == "openai":
            response = self.client.chat.completions.create(
                model=self.model,
                temperature=self.temperature,
                max_tokens=self.max_tokens,
                messages=[
                    {"role": "system", "content": system_prompt},
                    {"role": "user", "content": user_prompt},
                ],
            )
            text = response.choices[0].message.content
            # Token tracking
            usage = getattr(response, "usage", None)
            if usage:
                inp = getattr(usage, "prompt_tokens", 0)
                out = getattr(usage, "completion_tokens", 0)
                self.total_input_tokens += inp
                self.total_output_tokens += out
                logger.info(f"LLM TOKENS: input={inp}, output={out}, total_cumul=({self.total_input_tokens},{self.total_output_tokens})")

        elif self.provider == "anthropic":
            response = self.client.messages.create(
                model=self.model,
                max_tokens=self.max_tokens,
                temperature=self.temperature,
                system=system_prompt,
                messages=[{"role": "user", "content": user_prompt}],
            )
            text = response.content[0].text
            # Token tracking
            usage = getattr(response, "usage", None)
            if usage:
                inp = getattr(usage, "input_tokens", 0)
                out = getattr(usage, "output_tokens", 0)
                self.total_input_tokens += inp
                self.total_output_tokens += out
                logger.info(f"LLM TOKENS: input={inp}, output={out}, total_cumul=({self.total_input_tokens},{self.total_output_tokens})")
        else:
            raise ValueError(f"Unsupported provider: {self.provider}")

        self.total_calls += 1
        logger.debug(f"LLM RESPONSE ({len(text)} chars): {text[:500]}...")

        # Full conversation log (for debug/reproducibility)
        self._log_conversation(system_prompt, user_prompt, text)

        return text

    def chat_json(self, system_prompt: str, user_prompt: str) -> dict:
        """Send a chat request and parse the response as JSON.

        Uses provider-specific mechanisms to enforce JSON output:
        - Anthropic: assistant prefill with '{'
        - OpenAI: response_format=json_object
        Falls back to regex extraction if parsing fails.
        """
        import json as _json

        logger.info(
            f"LLM JSON call #{self.total_calls + 1}: {self.provider}/{self.model}"
        )
        logger.debug(f"LLM JSON REQUEST system: {system_prompt[:200]}...")
        logger.debug(f"LLM JSON REQUEST user: {user_prompt[:500]}...")

        text = ""
        if self.provider == "anthropic":
            # Opus models don't support prefill; others do
            use_prefill = "opus" not in self.model.lower()

            if use_prefill:
                response = self.client.messages.create(
                    model=self.model,
                    max_tokens=self.max_tokens,
                    temperature=self.temperature,
                    system=system_prompt,
                    messages=[
                        {"role": "user", "content": user_prompt},
                        {"role": "assistant", "content": "{"},
                    ],
                )
                text = "{" + response.content[0].text
            else:
                response = self.client.messages.create(
                    model=self.model,
                    max_tokens=self.max_tokens,
                    temperature=self.temperature,
                    system=system_prompt + "\n\nCRITICAL: Respond with ONLY a JSON object. No text before or after.",
                    messages=[{"role": "user", "content": user_prompt}],
                )
                text = response.content[0].text
            usage = getattr(response, "usage", None)
            if usage:
                inp = getattr(usage, "input_tokens", 0)
                out = getattr(usage, "output_tokens", 0)
                self.total_input_tokens += inp
                self.total_output_tokens += out
                logger.info(f"LLM TOKENS: input={inp}, output={out}")

        elif self.provider == "openai":
            response = self.client.chat.completions.create(
                model=self.model,
                temperature=self.temperature,
                max_tokens=self.max_tokens,
                response_format={"type": "json_object"},
                messages=[
                    {"role": "system", "content": system_prompt},
                    {"role": "user", "content": user_prompt},
                ],
            )
            text = response.choices[0].message.content
            usage = getattr(response, "usage", None)
            if usage:
                inp = getattr(usage, "prompt_tokens", 0)
                out = getattr(usage, "completion_tokens", 0)
                self.total_input_tokens += inp
                self.total_output_tokens += out
                logger.info(f"LLM TOKENS: input={inp}, output={out}")

        self.total_calls += 1
        logger.debug(f"LLM JSON RESPONSE ({len(text)} chars): {text[:500]}...")
        self._log_conversation(system_prompt, user_prompt, text)

        # Parse JSON
        import re
        text = re.sub(r"```json\s*", "", text)
        text = re.sub(r"```\s*", "", text).strip()
        try:
            return _json.loads(text)
        except _json.JSONDecodeError:
            # Balanced brace extraction fallback
            for match in re.finditer(r'\{', text):
                start = match.start()
                depth = 0
                for i in range(start, len(text)):
                    if text[i] == '{':
                        depth += 1
                    elif text[i] == '}':
                        depth -= 1
                        if depth == 0:
                            try:
                                return _json.loads(text[start:i+1])
                            except _json.JSONDecodeError:
                                break
            logger.error("chat_json: could not parse JSON from response")
            return {}

    def _log_conversation(self, system: str, user: str, response: str):
        """Append full conversation to a JSONL log file for debugging."""
        import json as _json
        from datetime import datetime
        _LOG_DIR.mkdir(parents=True, exist_ok=True)
        conv_log = _LOG_DIR / "conversations.jsonl"
        entry = {
            "timestamp": datetime.now().isoformat(),
            "provider": self.provider,
            "model": self.model,
            "call_number": self.total_calls,
            "system_prompt": system,
            "user_prompt": user,
            "response": response,
            "tokens": {
                "input": self.total_input_tokens,
                "output": self.total_output_tokens,
            },
        }
        try:
            import fcntl
            with open(conv_log, "a", encoding="utf-8") as f:
                fcntl.flock(f, fcntl.LOCK_EX)
                f.write(_json.dumps(entry, ensure_ascii=False) + "\n")
                f.flush()
                fcntl.flock(f, fcntl.LOCK_UN)
        except OSError:
            pass

    def summary(self) -> dict:
        """Return usage summary with cost estimate."""
        # Pricing (USD per 1M tokens, approximate)
        PRICING = {
            "gpt-4o": {"input": 2.50, "output": 10.00},
            "gpt-4o-mini": {"input": 0.15, "output": 0.60},
            "claude-opus-4-6": {"input": 15.00, "output": 75.00},
            "claude-sonnet-4-5-20250929": {"input": 3.00, "output": 15.00},
            "claude-sonnet-4-6": {"input": 3.00, "output": 15.00},
        }
        pricing = PRICING.get(self.model, {"input": 5.0, "output": 15.0})
        input_cost = self.total_input_tokens / 1_000_000 * pricing["input"]
        output_cost = self.total_output_tokens / 1_000_000 * pricing["output"]
        return {
            "provider": self.provider,
            "model": self.model,
            "total_calls": self.total_calls,
            "total_input_tokens": self.total_input_tokens,
            "total_output_tokens": self.total_output_tokens,
            "estimated_cost_usd": round(input_cost + output_cost, 4),
            "conversation_log": str(_LOG_DIR / "conversations.jsonl"),
        }


# ============================================================
# PROMPT TEMPLATES — packaged with PrivEscGen
# Re-exported through the PrivEscGen package.
# ============================================================
from .prompts.manager import MANAGER_PARSE_PROMPT as _MMP  # noqa: E402
from .prompts.scaffolder import SCAFFOLDER_ENV_PROMPT as _SEP, SCAFFOLDER_FIX_PROMPT as _SFP, SCAFFOLDER_VARIANT_PROMPT as _SVP  # noqa: E402
from .prompts.exploiter import EXPLOITER_GENERATE_PROMPT as _EGP, EXPLOITER_ADAPT_PROMPT as _EAP  # noqa: E402
from .prompts.verifier import VERIFIER_DIAGNOSE_PROMPT as _VDP  # noqa: E402

MANAGER_PARSE_PROMPT = _MMP
SCAFFOLDER_ENV_PROMPT = _SEP
SCAFFOLDER_FIX_PROMPT = _SFP
SCAFFOLDER_VARIANT_PROMPT = _SVP
EXPLOITER_GENERATE_PROMPT = _EGP
EXPLOITER_ADAPT_PROMPT = _EAP
VERIFIER_DIAGNOSE_PROMPT = _VDP

# Prompt definitions live in privescgen/prompts/*.py.
_PROMPTS_MIGRATED = True
