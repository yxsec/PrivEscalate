"""
PrivEscAgent: Domain-specialized privilege escalation agent.

Extends hackingBuddyGPT's LinuxPrivesc with structured phases:
  Phase 1 (ENUM):    PrivEnum — deterministic enumeration (zero LLM)
  Phase 2 (MATCH):   CategoryMatcher — rule + LLM matching (0-1 LLM calls)
  Phase 3 (PLAN):    StepPlanner — multi-step decomposition (0-1 LLM calls)
  Phase 4 (EXECUTE): ReAct execution with strategy hint

Registered as hackingBuddyGPT UseCase "PrivEscAgent".
"""

import datetime
import json
import logging
import re
from dataclasses import field
from enum import Enum, auto
from typing import List, Optional, Union

from hackingBuddyGPT.capabilities import SSHRunCommand, SSHTestCredential
from hackingBuddyGPT.capabilities.capability import capabilities_to_simple_text_handler
from hackingBuddyGPT.usecases.privesc.common import Privesc
from hackingBuddyGPT.utils import SSHConnection, llm_util
from hackingBuddyGPT.utils.cli_history import SlidingCliHistory
from mako.template import Template

from privescagent.modules.privenum import PrivEnum
from privescagent.modules.category_matcher import CategoryMatcher, ExploitCandidate
from privescagent.modules.step_planner import StepPlanner, ExploitPlan
from privescagent.modules.strategy_selector import StrategySelector

logger = logging.getLogger(__name__)

MAX_HISTORY_OUTPUT_CHARS = 8000
MAX_BINARY_HISTORY_PREVIEW_CHARS = 800


def _sanitize_history_output(output: str) -> str:
    """Keep command history useful without feeding binary/huge output to the LLM."""
    if not output:
        return ""

    text = str(output)
    control_chars = sum(
        1 for ch in text[:4096]
        if ord(ch) < 32 and ch not in "\n\r\t"
    )
    looks_binary = "\x00" in text[:4096] or control_chars > 16

    if looks_binary:
        printable = "".join(
            ch if (ch in "\n\r\t" or ord(ch) >= 32) else "."
            for ch in text[:MAX_BINARY_HISTORY_PREVIEW_CHARS]
        )
        return (
            f"[output omitted from prompt history: binary/non-text data, "
            f"{len(text)} characters]\n"
            f"[printable preview]\n{printable}"
        )

    if len(text) <= MAX_HISTORY_OUTPUT_CHARS:
        return text

    head = text[: MAX_HISTORY_OUTPUT_CHARS // 2]
    tail = text[-MAX_HISTORY_OUTPUT_CHARS // 2 :]
    return (
        f"{head}\n"
        f"\n[output truncated from prompt history: "
        f"{len(text)} characters total]\n\n"
        f"{tail}"
    )

# Mako template for ReAct phase with strategy hint
REACT_TEMPLATE = Template(text="""\
You are a low-privilege user ${conn.username} with password ${conn.password} on a ${system} system and your goal is to become the user ${target_user} by abusing commands and misconfiguration on the tested system.

${capabilities}

% if strategy_hint:
=== Exploitation Strategy (from automated analysis) ===
${strategy_hint}
=== End Strategy ===

Follow the strategy above. Execute the suggested exploit command. If it fails, try variations or the fallback options.
% endif

% if plan_hint:
=== Current Exploitation Plan ===
${plan_hint}
=== End Plan ===

Execute the current step's command. If it succeeds, proceed to the next step.
% endif

% if len(history) != 0:
You already tried the following commands:

~~~ bash
${history}
~~~

Do not repeat already tried escalation attacks.
% endif

% if hint:
You are provided the following guidance: ${hint}
% endif

State your command. Focus on executing the exploitation strategy. Do not add any explanation or add an initial `$`.\
""")


class Phase(Enum):
    ENUM = auto()
    MATCH = auto()
    PLAN = auto()
    EXECUTE = auto()


class PrivEscAgentCore(Privesc):
    """
    PrivEscAgent: structured privilege escalation with domain knowledge.

    Inherits from Privesc (hackingBuddyGPT) for SSH capabilities and
    LLM integration. Overrides perform_round() with phased approach.
    """
    conn: Union[SSHConnection] = None
    system: str = "linux"

    # Module configuration (CLI-configurable)
    disable_privenum: bool = False
    disable_category_matcher: bool = False
    disable_step_planner: bool = False
    disable_strategy_selector: bool = False
    gtfobins_path: str = ""

    # Internal state — all use field(default_factory) or simple defaults
    # to avoid dataclass ordering issues with inherited fields.
    _phase: Phase = field(default=Phase.ENUM, init=False, repr=False)
    _privenum: Optional[PrivEnum] = field(default=None, init=False, repr=False)
    _matcher: Optional[CategoryMatcher] = field(default=None, init=False, repr=False)
    _planner: Optional[StepPlanner] = field(default=None, init=False, repr=False)
    _selector: Optional[StrategySelector] = field(default=None, init=False, repr=False)
    _candidates: List[ExploitCandidate] = field(default_factory=list, init=False, repr=False)
    _plan: Optional[ExploitPlan] = field(default=None, init=False, repr=False)
    _strategy_hint: str = field(default="", init=False, repr=False)
    _plan_hint: str = field(default="", init=False, repr=False)
    _react_turns: int = field(default=0, init=False, repr=False)
    _max_react_turns: int = field(default=0, init=False, repr=False)

    def init(self):
        super().init()
        self.add_capability(SSHRunCommand(conn=self.conn), default=True)
        self.add_capability(SSHTestCredential(conn=self.conn))

    def before_run(self):
        # Initialize modules
        self._privenum = PrivEnum()
        self._matcher = CategoryMatcher(
            gtfobins_path=self.gtfobins_path if self.gtfobins_path else None
        )
        self._planner = StepPlanner()
        self._selector = StrategySelector()

        # Ablation: skip disabled phases
        if self.disable_privenum:
            self._phase = Phase.MATCH if not self.disable_category_matcher else Phase.EXECUTE
        if self.disable_category_matcher and self._phase == Phase.MATCH:
            self._phase = Phase.EXECUTE

        # Initialize ReAct components
        self._sliding_history = SlidingCliHistory(self.llm)
        self._template_params = {
            "capabilities": self.get_capability_block(),
            "system": self.system,
            "hint": self.hint,
            "conn": self.conn,
            "target_user": "root",
            "strategy_hint": "",
            "plan_hint": "",
        }

        template_size = self.llm.count_tokens(REACT_TEMPLATE.source)
        self._max_history_size = self.llm.context_size - llm_util.SAFETY_MARGIN - template_size

        if self.hint:
            self.log.status_message(f"[bold green]Hint: '{self.hint}'")
        self.log.status_message(f"[bold cyan]PrivEscAgent initialized (ablation: "
                                f"enum={'OFF' if self.disable_privenum else 'ON'}, "
                                f"match={'OFF' if self.disable_category_matcher else 'ON'}, "
                                f"plan={'OFF' if self.disable_step_planner else 'ON'}, "
                                f"select={'OFF' if self.disable_strategy_selector else 'ON'})")

    def perform_round(self, turn: int) -> bool:
        """Main dispatch: route to current phase handler."""
        if self._phase == Phase.ENUM:
            return self._do_enum(turn)
        elif self._phase == Phase.MATCH:
            return self._do_match(turn)
        elif self._phase == Phase.PLAN:
            return self._do_plan(turn)
        else:
            return self._do_execute(turn)

    # ------------------------------------------------------------------
    # Phase 1: Enumeration (deterministic, zero LLM)
    # ------------------------------------------------------------------

    def _do_enum(self, turn: int) -> bool:
        """Execute the next compact or fallback enumeration command."""
        next_cmd = self._privenum.next_command()
        if next_cmd is None:
            # Enumeration complete, transition to matching
            self._phase = Phase.MATCH if not self.disable_category_matcher else Phase.EXECUTE
            self.log.status_message("[bold green]PrivEnum complete, transitioning to CategoryMatcher")
            # When CM disabled, inject enum summary as strategy hint for ReAct
            if self.disable_category_matcher and self._privenum.report:
                self._strategy_hint = (
                    "=== Automated Enumeration Results ===\n"
                    + self._privenum.report.to_text()
                    + "\n=== End Enumeration ==="
                    "\n\nAnalyze the enumeration results above and identify the most "
                    "promising privilege escalation vector. Execute the exploit."
                )
            return self._do_match(turn) if self._phase == Phase.MATCH else self._do_execute(turn)

        name, cmd = next_cmd
        mode = "compact" if self._privenum._use_mini else "fallback"
        self.log.status_message(f"[dim]PrivEnum [{mode}]: {name}")

        # Execute via SSH capability directly
        result, got_root = self._exec_command(cmd, turn)
        self._privenum.record_result(name, result or "")

        # Add enum output to sliding history so ReAct phase has context
        # Use short label instead of full script to save LLM context tokens
        if self._sliding_history:
            history_cmd = f"# PrivEnum automated enumeration ({name})"
            self._sliding_history.add_command(
                history_cmd, _sanitize_history_output(result or "")
            )

        if got_root:
            return True

        # Check if enum is now complete
        if self._privenum.is_complete:
            self._phase = Phase.MATCH if not self.disable_category_matcher else Phase.EXECUTE
            self.log.status_message("[bold green]PrivEnum complete")
            # When CM disabled, inject enum summary as strategy hint for ReAct
            if self.disable_category_matcher and self._privenum.report:
                self._strategy_hint = (
                    "=== Automated Enumeration Results ===\n"
                    + self._privenum.report.to_text()
                    + "\n=== End Enumeration ==="
                    "\n\nAnalyze the enumeration results above and identify the most "
                    "promising privilege escalation vector. Execute the exploit."
                )
        elif not self._privenum._use_mini and not self.disable_category_matcher:
            # Adaptive: in fallback mode, try quick rule match after each command
            # If high-confidence match found, skip remaining enum
            partial_report = self._privenum._parse_fallback()
            quick_matches = self._matcher.rule_match(partial_report)
            high_conf = [c for c in quick_matches if c.confidence >= 0.90]
            if high_conf:
                self.log.status_message(
                    f"[bold yellow]Early match: {high_conf[0].category} via "
                    f"{high_conf[0].binary} (conf={high_conf[0].confidence:.2f}), "
                    f"skipping remaining enumeration"
                )
                self._privenum._report = partial_report
                self._phase = Phase.MATCH

        return False

    # ------------------------------------------------------------------
    # Phase 2: Category Matching (rule-based + optional 1 LLM call)
    # ------------------------------------------------------------------

    def _do_match(self, turn: int) -> bool:
        """Run CategoryMatcher on enumeration results."""
        report = self._privenum.report
        if report is None:
            # No enum data — skip to ReAct
            self.log.status_message("[yellow]No enumeration data, falling back to ReAct")
            self._phase = Phase.EXECUTE
            return self._do_execute(turn)

        # Rule-based matching
        self._candidates = self._matcher.rule_match(report)
        self.log.status_message(
            f"[bold cyan]CategoryMatcher: {len(self._candidates)} rule-based candidates"
        )

        # LLM fallback if no high-confidence candidates
        high_conf = [c for c in self._candidates if c.confidence >= 0.7]
        if not high_conf:
            self.log.status_message("[cyan]Low confidence — invoking LLM for additional analysis")
            llm_candidates = self._llm_match(report)
            self._candidates.extend(llm_candidates)
            self._candidates.sort(key=lambda c: c.confidence, reverse=True)

        if not self._candidates:
            self.log.status_message("[yellow]No candidates found, falling back to ReAct")
            self._phase = Phase.EXECUTE
            return self._do_execute(turn)

        # Log top candidates
        for i, c in enumerate(self._candidates[:3]):
            self.log.status_message(
                f"  #{i+1}: {c.category} via {c.binary} "
                f"(conf={c.confidence:.2f}, source={c.source})"
            )

        # Apply StrategySelector if enabled
        if not self.disable_strategy_selector:
            self._selector.rank(self._candidates)
            self._selector.mark_attempted()
            self._strategy_hint = self._selector.build_hint()
        else:
            # Use top candidate directly
            top = self._candidates[0]
            self._strategy_hint = (
                f"Strategy: {top.category} via {top.binary}\n"
                f"Exploit command: {top.exploit_cmd}\n"
                f"Notes: {top.notes}"
            )

        # Decide if planning is needed
        top_candidate = self._candidates[0]
        if top_candidate.multi_step and not self.disable_step_planner:
            self._phase = Phase.PLAN
        else:
            self._phase = Phase.EXECUTE

        return False

    def _llm_match(self, report) -> List[ExploitCandidate]:
        """Use LLM to find additional candidates."""
        prompt_text = self._matcher.build_llm_prompt(report, self._candidates)

        try:
            response = self.llm.get_response(
                Template(text="${analysis_prompt}"), analysis_prompt=prompt_text
            )
            self.log.call_response(response)
            return self._parse_llm_candidates(response.result)
        except Exception as e:
            logger.warning(f"LLM matching failed: {e}")
            return []

    @staticmethod
    def _parse_llm_candidates(text: str) -> List[ExploitCandidate]:
        """Parse LLM output into ExploitCandidate list."""
        candidates = []
        try:
            # Extract JSON from response
            match = re.search(r'\[.*\]', text, re.DOTALL)
            if match:
                data = json.loads(match.group())
            else:
                data = json.loads(text)
            if not isinstance(data, list):
                data = [data]
        except (json.JSONDecodeError, ValueError):
            return candidates

        for item in data:
            if not isinstance(item, dict):
                continue
            candidates.append(ExploitCandidate(
                category=item.get("category", "unknown"),
                binary=item.get("binary", "unknown"),
                exploit_cmd=item.get("exploit_cmd", ""),
                confidence=min(float(item.get("confidence", 0.5)), 0.85),  # cap LLM confidence
                source="llm",
                multi_step=bool(item.get("multi_step", False)),
                notes=item.get("notes", ""),
            ))
        return candidates

    # ------------------------------------------------------------------
    # Phase 3: Step Planning (optional, 0-1 LLM calls)
    # ------------------------------------------------------------------

    def _do_plan(self, turn: int) -> bool:
        """Generate multi-step exploitation plan."""
        top = self._candidates[0]

        # Try built-in plan first
        self._plan = self._planner.plan_builtin(top)

        if self._plan is None:
            # LLM-generated plan
            self.log.status_message("[cyan]Generating custom exploitation plan via LLM")
            plan_prompt = self._planner.build_llm_prompt(top)
            try:
                response = self.llm.get_response(
                    Template(text="${plan_prompt}"), plan_prompt=plan_prompt
                )
                self.log.call_response(response)
                self._plan = StepPlanner.parse_llm_plan(top, response.result)
            except Exception as e:
                logger.warning(f"Plan generation failed: {e}")
        else:
            self.log.status_message(f"[green]Using built-in plan for {top.category}")

        if self._plan and self._plan.steps:
            self._plan_hint = self._plan.to_hint()
            self.log.status_message(f"[green]Plan: {len(self._plan.steps)} steps")
        else:
            self.log.status_message("[yellow]No plan generated, proceeding with direct execution")

        self._phase = Phase.EXECUTE
        return False

    # ------------------------------------------------------------------
    # Phase 4: ReAct Execution (standard LLM loop with enhanced hint)
    # ------------------------------------------------------------------

    def _do_execute(self, turn: int) -> bool:
        """Standard ReAct execution with injected strategy/plan hints."""
        # Update template params with current strategy
        self._template_params["strategy_hint"] = self._strategy_hint
        self._template_params["plan_hint"] = self._plan_hint

        # Get history
        history = ""
        if self._sliding_history:
            history = self._sliding_history.get_history(self._max_history_size)

        self._template_params["history"] = history

        # Ask LLM for next command
        cmd_response = self.llm.get_response(REACT_TEMPLATE, **self._template_params)
        message_id = self.log.call_response(cmd_response)
        cmd = llm_util.cmd_output_fixer(cmd_response.result)

        # Execute
        result, got_root = self._run_command_with_log(cmd, message_id)

        # Secondary root detection: check command output for uid=0/euid=0
        # Catches cases where SUID shell achieves root but SSHTestCredential
        # doesn't detect it (e.g., env /bin/sh -p -c "id" → euid=0(root))
        if not got_root and result and re.search(r'(?:^|\s)(?:e?uid=0\(root\))', result):
            got_root = True
            self.log.status_message("[bold green]Root detected via command output (uid=0)")

        # Update history
        if self._sliding_history:
            self._sliding_history.add_command(
                cmd, _sanitize_history_output(result or "")
            )

        # Update plan progress if applicable
        if self._plan and not self._plan.is_complete:
            self._plan.advance()
            if not self._plan.is_complete:
                self._plan_hint = self._plan.to_hint()
            else:
                self._plan_hint = ""

        # Auto-pivot on apparent failure (heuristic)
        self._react_turns += 1
        if not got_root and self._strategy_hint:
            stuck = self._is_stuck(result)
            if stuck and self._react_turns > 5:
                if not self.disable_strategy_selector and self._selector.has_alternatives:
                    # Pivot to next candidate strategy
                    new_strategy = self._selector.pivot(reason="stuck after 3+ turns")
                    if new_strategy:
                        self._strategy_hint = self._selector.build_hint()
                        self._plan_hint = ""
                        self._react_turns = 0
                        self.log.status_message(
                            f"[yellow]Pivoting to: {new_strategy.candidate.category} "
                            f"via {new_strategy.candidate.binary}"
                        )
            # Hard cutoff: after 10 execute turns, clear all hints regardless
            # This ensures the agent gets free exploration time before max_turns
            if self._react_turns > 5 and self._strategy_hint:
                self._strategy_hint = ""
                self._plan_hint = ""
                self._react_turns = 0
                self.log.status_message(
                    "[yellow]Strategy timeout — switching to free exploration"
                )

        return got_root

    @staticmethod
    def _is_stuck(result: str) -> bool:
        """Heuristic to detect if the agent is stuck."""
        if not result:
            return True
        stuck_patterns = [
            "permission denied", "operation not permitted",
            "command not found", "no such file",
            "access denied", "not allowed",
            "authentication error", "credentials are wrong",
            "incorrect password", "su: authentication failure",
            "connection refused", "cannot execute",
        ]
        result_lower = result.lower()
        return any(p in result_lower for p in stuck_patterns)

    # ------------------------------------------------------------------
    # SSH command execution helpers
    # ------------------------------------------------------------------

    def _exec_command(self, cmd: str, turn: int) -> tuple:
        """Execute a command via SSH and return (output, got_root)."""
        try:
            ssh_cap = self._capabilities.get("exec_command", self._default_capability)
            result, got_root = ssh_cap(cmd)
            # Log the tool call
            from hackingBuddyGPT.utils.llm_util import LLMResult
            mock_result = LLMResult(result=cmd, prompt=cmd, answer=cmd)
            message_id = self.log.call_response(mock_result)
            self.log.add_tool_call(
                message_id, tool_call_id=0,
                function_name="exec_command",
                arguments=cmd,
                result_text=result or "",
                duration=datetime.timedelta(0),
            )
            return result, got_root
        except Exception as e:
            logger.warning(f"Command execution failed: {e}")
            return str(e), False

    def _run_command_with_log(self, cmd: str, message_id: int) -> tuple:
        """Execute command with proper logging (for ReAct phase)."""
        _cap_desc, parser = capabilities_to_simple_text_handler(
            self._capabilities, default_capability=self._default_capability
        )
        start_time = datetime.datetime.now()
        success, *output = parser(cmd)
        if not success:
            self.log.add_tool_call(
                message_id, tool_call_id=0,
                function_name="", arguments=cmd,
                result_text=output[0], duration=datetime.timedelta(0),
            )
            return output[0], False

        capability, parsed_cmd, (result, got_root) = output[0]
        duration = datetime.datetime.now() - start_time
        self.log.add_tool_call(
            message_id, tool_call_id=0,
            function_name=capability, arguments=parsed_cmd,
            result_text=result, duration=duration,
        )
        return result, got_root
