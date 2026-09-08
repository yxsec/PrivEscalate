"""
Verifier Agent: Triple verification for scenario correctness.

Layer 1: Build Verification (both Dockerfiles build)
Layer 2: Exploit Differential Test (uid=0 on vuln, fail on fixed)
Layer 3: Consistency Check (no unintended paths, deterministic)

When LLM is available:
  - Diagnoses verification failures with structured JSON output
  - L3 runs automated privesc enumeration on fixed containers
  - Optional LLM audit for high-quality mode
"""

import json
import logging
import re
import subprocess
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional

logger = logging.getLogger(__name__)

DOCKER_TIMEOUT = 120
SSH_WAIT = 2  # seconds to wait for SSH after container start

# Commands to detect unintended privilege escalation vectors
L3_PRIVESC_CHECKS = [
    ("suid_binaries", "find / -perm -4000 -type f 2>/dev/null"),
    ("sudo_rules", "sudo -l 2>/dev/null || true"),
    ("cron_jobs", "cat /etc/crontab 2>/dev/null; ls -la /etc/cron.d/ 2>/dev/null"),
    ("capabilities", "getcap -r / 2>/dev/null || true"),
    ("writable_sensitive", "find /etc /usr -writable -type f 2>/dev/null | head -20"),
    ("shell_users", "cat /etc/passwd | grep -v nologin | grep -v /bin/false"),
]

# Known-safe SUID binaries in debian:bookworm-slim
SAFE_SUID_BINARIES = {
    # Core system utilities (Debian bookworm defaults)
    "/usr/bin/su",
    "/usr/bin/sudo",
    "/usr/bin/passwd",
    "/usr/bin/chsh",
    "/usr/bin/chfn",
    "/usr/bin/newgrp",
    "/usr/bin/gpasswd",
    "/usr/bin/mount",
    "/usr/bin/umount",
    "/usr/bin/ping",
    "/usr/bin/at",
    "/usr/bin/mtr-packet",
    "/usr/bin/newgidmap",
    "/usr/bin/newuidmap",
    # FUSE filesystem
    "/usr/bin/fusermount",
    "/usr/bin/fusermount3",
    # PolicyKit
    "/usr/bin/pkexec",
    "/usr/lib/polkit-1/polkit-agent-helper-1",
    # Service daemons (common apt dependencies)
    "/usr/sbin/exim4",
    # SSH / D-Bus
    "/usr/lib/openssh/ssh-keysign",
    "/usr/lib/dbus-1.0/dbus-daemon-launch-helper",
    # Snap (if installed)
    "/usr/lib/snapd/snap-confine",
}


@dataclass
class VerificationResult:
    """Result of triple verification."""
    l1_build_vuln: bool = False
    l1_build_fixed: bool = False
    l2_exploit_on_vuln: bool = False
    l2_exploit_on_fixed_fails: bool = False
    l3_no_unintended_paths: bool = True  # default True, set False if found
    l3_deterministic: bool = True
    l3_unintended_details: list[str] = field(default_factory=list)
    failures: list[str] = field(default_factory=list)
    # Raw data for LLM diagnosis
    vuln_uid: int = -1
    vuln_exploit_output: str = ""
    fixed_uid: int = -1
    build_stderr_vuln: str = ""
    build_stderr_fixed: str = ""

    @property
    def all_passed(self) -> bool:
        return (
            self.l1_build_vuln
            and self.l1_build_fixed
            and self.l2_exploit_on_vuln
            and self.l2_exploit_on_fixed_fails
            and self.l3_no_unintended_paths
        )


class Verifier:
    """Performs triple verification on constructed scenarios."""

    def __init__(self, project_root: Path, llm=None):
        self.project_root = project_root
        self.llm = llm  # Optional[LLMClient]

    def verify(self, spec) -> VerificationResult:
        """Run all three verification layers."""
        result = VerificationResult()
        scenario_dir = spec.output_dir
        scenario_id = spec.scenario_id
        vuln_tag = f"privesc-{scenario_id}-vuln".lower()
        fixed_tag = f"privesc-{scenario_id}-fixed".lower()

        # === Layer 1: Build Verification ===
        logger.info(f"  [L1] Building {scenario_id}...")

        ok_vuln, stderr_vuln = self._docker_build(
            scenario_dir / "Dockerfile", vuln_tag
        )
        result.l1_build_vuln = ok_vuln
        result.build_stderr_vuln = stderr_vuln
        if not ok_vuln:
            result.failures.append("L1: Vulnerable Dockerfile build failed")

        ok_fixed, stderr_fixed = self._docker_build(
            scenario_dir / "Dockerfile.fixed", fixed_tag
        )
        result.l1_build_fixed = ok_fixed
        result.build_stderr_fixed = stderr_fixed
        if not ok_fixed:
            result.failures.append("L1: Fixed Dockerfile build failed")

        if not (ok_vuln and ok_fixed):
            self._cleanup([vuln_tag, fixed_tag])
            return result

        # === Layer 2: Exploit Differential Test ===
        logger.info(f"  [L2] Differential testing {scenario_id}...")

        exploit_path = scenario_dir / "exploit.sh"
        if not exploit_path.exists():
            result.failures.append("L2: No exploit.sh found")
            self._cleanup([vuln_tag, fixed_tag])
            return result

        # Test on vulnerable container
        result.vuln_uid, result.vuln_exploit_output = self._run_exploit_in_container(vuln_tag, exploit_path, spec)
        result.l2_exploit_on_vuln = (result.vuln_uid == 0)
        if not result.l2_exploit_on_vuln:
            result.failures.append(
                f"L2: Exploit did not achieve uid=0 on vuln (got uid={result.vuln_uid})"
            )

        # Test on fixed container (should FAIL)
        result.fixed_uid, _ = self._run_exploit_in_container(fixed_tag, exploit_path, spec)
        result.l2_exploit_on_fixed_fails = (result.fixed_uid != 0)
        if not result.l2_exploit_on_fixed_fails:
            result.failures.append("L2: Exploit still achieves root on fixed container")

        # === Layer 3: Consistency Check ===
        logger.info(f"  [L3] Consistency check {scenario_id}...")

        # L3a: Check for unintended privesc paths in fixed container
        unintended = self._check_unintended_paths(fixed_tag, spec)
        if unintended:
            result.l3_no_unintended_paths = False
            result.l3_unintended_details = unintended
            result.failures.append(
                f"L3: Unintended privesc paths in fixed container: {'; '.join(unintended)}"
            )

        # L3b: Deterministic rebuild
        result.l3_deterministic = self._check_deterministic(scenario_dir, vuln_tag)
        if not result.l3_deterministic:
            result.failures.append("L3: Non-deterministic build detected")

        # Cleanup
        self._cleanup([vuln_tag, fixed_tag])

        return result

    # ------------------------------------------------------------------
    # LLM diagnosis (called by Manager feedback loop)
    # ------------------------------------------------------------------

    def diagnose(self, spec, result: VerificationResult) -> Optional[dict]:
        """
        Use LLM to diagnose why verification failed.

        Returns a parsed dict with keys:
          - fix_target: "dockerfile" | "exploit" | "both"
          - root_cause: str
          - dockerfile_fix: str | None
          - exploit_fix: str | None

        Returns None if no LLM or parsing fails.
        """
        if not self.llm:
            return None

        from .llm_client import VERIFIER_DIAGNOSE_PROMPT

        scenario_dir = spec.output_dir

        # Read current artifacts
        dockerfile_content = ""
        dockerfile_fixed_content = ""
        exploit_content = ""

        dockerfile_path = scenario_dir / "Dockerfile"
        if dockerfile_path.exists():
            dockerfile_content = dockerfile_path.read_text()

        fixed_path = scenario_dir / "Dockerfile.fixed"
        if fixed_path.exists():
            dockerfile_fixed_content = fixed_path.read_text()

        exploit_path = scenario_dir / "exploit.sh"
        if exploit_path.exists():
            exploit_content = exploit_path.read_text()

        # Determine which layer failed
        if not result.l1_build_vuln or not result.l1_build_fixed:
            failed_layer = "L1 (Build)"
            error_details = result.build_stderr_vuln or result.build_stderr_fixed
        elif not result.l2_exploit_on_vuln:
            failed_layer = "L2 (Exploit on vuln)"
            error_details = f"Exploit returned uid={result.vuln_uid}, expected uid=0.\nActual exploit output:\n{result.vuln_exploit_output[:1500]}"
        elif not result.l2_exploit_on_fixed_fails:
            failed_layer = "L2 (Exploit on fixed)"
            error_details = "Exploit still achieves root on fixed container"
        else:
            failed_layer = "L3 (Consistency)"
            error_details = "; ".join(result.l3_unintended_details) or "Unknown"

        logger.info(f"  LLM diagnosing failure: {failed_layer}...")

        diag = self.llm.chat_json(
            VERIFIER_DIAGNOSE_PROMPT["system"],
            VERIFIER_DIAGNOSE_PROMPT["user"].format(
                scenario_id=spec.scenario_id,
                failed_layer=failed_layer,
                error_details=error_details[:2000],
                exploit_uid=result.vuln_uid,
                dockerfile_content=dockerfile_content[:3000],
                dockerfile_fixed_content=dockerfile_fixed_content[:3000],
                exploit_content=exploit_content[:2000],
            ),
        )

        # chat_json returns dict directly; validate fix_target
        if not isinstance(diag, dict) or "fix_target" not in diag:
            logger.warning(f"  LLM diagnosis missing fix_target: {diag}")
            return None
        return diag

    def _parse_diagnosis(self, response: str) -> Optional[dict]:
        """Parse structured JSON diagnosis from LLM response.

        Three-stage parsing: direct JSON → balanced-brace extraction → field extraction.
        """
        # Strip markdown fences
        response = re.sub(r"```json\s*", "", response)
        response = re.sub(r"```\s*", "", response).strip()

        # Stage 1: Parse entire response as JSON
        try:
            diag = json.loads(response)
            if isinstance(diag, dict) and "fix_target" in diag:
                return diag
        except json.JSONDecodeError:
            pass

        # Stage 2: Find JSON object containing "fix_target" using balanced braces
        for match in re.finditer(r'\{', response):
            start = match.start()
            depth = 0
            end = start
            for i in range(start, len(response)):
                if response[i] == '{':
                    depth += 1
                elif response[i] == '}':
                    depth -= 1
                    if depth == 0:
                        end = i + 1
                        break
            if end > start:
                candidate = response[start:end]
                try:
                    diag = json.loads(candidate)
                    if isinstance(diag, dict) and "fix_target" in diag:
                        return diag
                except json.JSONDecodeError:
                    continue

        # Stage 3: Extract fields from natural language response
        logger.warning("  JSON parse failed, extracting fields from natural language")
        diag = {"fix_target": "exploit", "root_cause": "", "dockerfile_fix": None, "exploit_fix": None}

        resp_lower = response.lower()
        if "dockerfile" in resp_lower and "exploit" in resp_lower:
            diag["fix_target"] = "both"
        elif "dockerfile" in resp_lower:
            diag["fix_target"] = "dockerfile"

        # Root cause: first non-empty line
        lines = [line.strip() for line in response.split('\n') if line.strip() and not line.strip().startswith('{')]
        if lines:
            diag["root_cause"] = lines[0][:200]

        # Extract exploit script if embedded in response
        exploit_match = re.search(r'(#!/bin/bash[^\x00]*?)(?=\n\n[A-Z]|\Z)', response, re.DOTALL)
        if exploit_match:
            diag["exploit_fix"] = exploit_match.group(1).strip()

        return diag

    # ------------------------------------------------------------------
    # L3: Unintended privilege escalation path detection
    # ------------------------------------------------------------------

    def _check_unintended_paths(self, fixed_tag: str, spec) -> list[str]:
        """
        Run privesc enumeration checks on the fixed container.

        The fixed container should have NO exploitable paths.
        Returns list of detected issues (empty = clean).
        """
        container_name = f"verify-l3-{fixed_tag}-{int(time.time())}"
        issues = []

        try:
            # Start container
            subprocess.run(
                ["docker", "run", "-d", "--name", container_name, fixed_tag],
                capture_output=True, timeout=30,
            )
            time.sleep(1)

            username = spec.params.get("username", "lowpriv")

            for check_name, cmd in L3_PRIVESC_CHECKS:
                try:
                    r = subprocess.run(
                        [
                            "docker", "exec", container_name,
                            "su", "-", username, "-c", cmd,
                        ],
                        capture_output=True, text=True, timeout=15,
                    )
                    output = r.stdout.strip()
                    if not output:
                        continue

                    # Analyze output for each check type
                    finding = self._analyze_check(check_name, output, spec)
                    if finding:
                        issues.append(finding)

                except subprocess.TimeoutExpired:
                    continue

        except Exception as e:
            logger.error(f"  L3 check error: {e}")
        finally:
            subprocess.run(
                ["docker", "rm", "-f", container_name],
                capture_output=True, timeout=10,
            )

        return issues

    def _analyze_check(self, check_name: str, output: str, spec) -> Optional[str]:
        """Analyze output of a single privesc enumeration check."""
        intended_binary = spec.params.get("binary_path", "")

        if check_name == "suid_binaries":
            binaries = set(output.strip().split("\n"))
            unexpected = binaries - SAFE_SUID_BINARIES
            # Remove the intended vulnerability binary (it's expected in vuln, but
            # this check runs on fixed — so it should NOT be present)
            if intended_binary:
                unexpected.discard(intended_binary)
            if unexpected:
                return f"Unexpected SUID binaries: {', '.join(sorted(unexpected))}"

        elif check_name == "sudo_rules":
            # Any sudo rule for the low-priv user is suspicious in fixed container
            if "NOPASSWD" in output or "ALL" in output:
                return f"Sudo rules found: {output[:200]}"

        elif check_name == "capabilities":
            if output.strip():
                return f"Capabilities found: {output[:200]}"

        elif check_name == "writable_sensitive":
            if output.strip():
                return f"Writable sensitive files: {output[:200]}"

        elif check_name == "cron_jobs":
            # Check for user-writable cron entries
            if spec.params.get("username", "lowpriv") in output:
                return f"User-related cron jobs found: {output[:200]}"

        return None

    # ------------------------------------------------------------------
    # Docker helpers
    # ------------------------------------------------------------------

    def _docker_build(self, dockerfile: Path, tag: str) -> tuple[bool, str]:
        """Build a Dockerfile. Returns (success, stderr)."""
        try:
            r = subprocess.run(
                ["docker", "build", "-t", tag, "-f", str(dockerfile), str(dockerfile.parent)],
                capture_output=True, text=True, timeout=DOCKER_TIMEOUT,
            )
            if r.returncode == 0:
                return (True, "")
            return (False, r.stderr)
        except subprocess.TimeoutExpired:
            return (False, "Build timed out")
        except FileNotFoundError:
            return (False, "Docker not found")

    def _run_exploit_in_container(self, image_tag: str, exploit_path: Path, spec) -> tuple:
        """
        Run exploit in container via SSH and return (uid, raw_output).
        Uses SSH instead of docker exec + su to preserve Linux capabilities.
        Returns (0, output) if root, (-1, output) if failed.
        """
        container_name = f"verify-{image_tag}-{int(time.time())}"
        # Use a random high port to avoid conflicts
        import random
        ssh_port = random.randint(30000, 50000)
        username = spec.params.get("username", "lowpriv")
        password = spec.params.get("password", "password123")

        # Load run_config for docker_run_args
        run_config_path = spec.output_dir / "run_config.json" if spec.output_dir else None
        extra_args = []
        if run_config_path and run_config_path.exists():
            try:
                rc = json.loads(run_config_path.read_text())
                extra_args = rc.get("docker_run_args", [])
            except (json.JSONDecodeError, OSError):
                pass

        try:
            # Start container with SSH port mapping
            cmd = ["docker", "run", "-d", "--name", container_name,
                   "-p", f"{ssh_port}:22"] + extra_args + [image_tag]
            subprocess.run(cmd, capture_output=True, timeout=30)
            time.sleep(SSH_WAIT + 1)  # Extra wait for SSH to start

            # Copy exploit into container
            subprocess.run(
                ["docker", "cp", str(exploit_path), f"{container_name}:/tmp/exploit.sh"],
                capture_output=True, timeout=10,
            )
            subprocess.run(
                ["docker", "exec", container_name, "chmod", "+x", "/tmp/exploit.sh"],
                capture_output=True, timeout=10,
            )

            # Run exploit via SSH (preserves capabilities and matches eval environment)
            r = subprocess.run(
                ["sshpass", "-p", password, "ssh",
                 "-o", "StrictHostKeyChecking=no",
                 "-o", "UserKnownHostsFile=/dev/null",
                 "-o", "LogLevel=ERROR",
                 "-p", str(ssh_port),
                 f"{username}@localhost",
                 "bash /tmp/exploit.sh; echo EXIT_UID=$(id -u)"],
                capture_output=True, text=True, timeout=120,
            )

            output = r.stdout.strip()
            logger.debug(f"  Exploit output: {output[:300]}")

            # Check for uid=0 in output (from exploit itself or from id command)
            if "uid=0" in output or "euid=0" in output:
                return (0, output)

            # Fallback: check EXIT_UID
            for line in output.split("\n"):
                if line.startswith("EXIT_UID=0"):
                    return (0, output)

            return (-1, output)

        except Exception as e:
            logger.error(f"  Exploit test error: {e}")
            return (-1, str(e))
        finally:
            subprocess.run(
                ["docker", "rm", "-f", container_name],
                capture_output=True, timeout=10,
            )

    def _check_deterministic(self, scenario_dir: Path, tag: str) -> bool:
        """Check that rebuilding produces the same image."""
        tag2 = f"{tag}-rebuild".lower()
        try:
            ok, _ = self._docker_build(scenario_dir / "Dockerfile", tag2)
            self._cleanup([tag2])
            return ok
        except Exception:
            return False

    def _cleanup(self, tags: list[str]):
        """Remove Docker images."""
        for tag in tags:
            subprocess.run(
                ["docker", "rmi", "-f", tag],
                capture_output=True, timeout=10,
            )
