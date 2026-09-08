"""
Scaffolder Agent: Template → Dockerfile + setup.sh + Dockerfile.fixed

Renders Jinja2 templates with parameters to produce Docker-based
privilege escalation scenarios. When LLM is available, can also:
  - Generate Dockerfiles from ATT&CK descriptions (no template needed)
  - Auto-fix failed Docker builds
  - Harden base images to prevent unintended privesc paths
"""

import json
import logging
import re
import subprocess
from pathlib import Path

from jinja2 import Environment, FileSystemLoader

logger = logging.getLogger(__name__)

# Hardening commands for base image.
# NOTE: We intentionally preserve default SUID/SGID binaries (passwd, mount,
# umount, chfn, newgrp, gpasswd, chsh, su) to align with the hackingBuddyGPT
# benchmark environment [Happe & Cito, 2024; Happe et al., 2026], where
# standard system binaries are left in place. These binaries require
# authentication and cannot be used for privilege escalation without the
# root password. Only cron and sudoers are locked down to ensure the
# injected vulnerability is the sole escalation path.
_HARDEN_COMMANDS = r"""
# --- PrivEscGen: harden base image ---
# Preserve default SUID/SGID binaries (aligned with hackingBuddyGPT benchmark)
# Only lock down cron and sudoers to ensure single vulnerability path
RUN chmod 644 /etc/crontab 2>/dev/null || true ; \
    rm -f /etc/sudoers.d/* 2>/dev/null || true
# --- end harden ---
"""

LLM_BUILD_FIX_MAX = 2  # max LLM fix attempts per Dockerfile


class Scaffolder:
    """Generates Docker scenario files from Jinja2 templates or LLM."""

    def __init__(self, project_root: Path, llm=None):
        self.project_root = project_root
        self.templates_dir = project_root / "dataset" / "templates"
        self.llm = llm  # Optional[LLMClient]

    def build(self, spec) -> bool:
        """
        Render template into concrete scenario files.

        Strategy:
          1. If Jinja2 template exists → render it
          2. Else if LLM available → generate from ATT&CK description
          3. Else → fail

        Returns True if scenario builds and Dockerfile is valid.
        """
        template_dir = spec.template_dir
        output_dir = spec.output_dir
        output_dir.mkdir(parents=True, exist_ok=True)

        has_template = (template_dir / "template.j2").exists()

        if has_template:
            ok = self._build_from_template(spec)
        elif self.llm:
            ok = self._build_from_llm(spec)
        else:
            logger.error(f"  No template for {spec.scenario_id} and no LLM available")
            return False

        if not ok:
            return False

        # Write enhanced metadata
        params = spec.params
        difficulty_steps = {"easy": 2, "medium": 4, "hard": 8}
        category = params.get("_category", "")

        # Load taxonomy for extended classification dimensions
        taxonomy_fields = self._get_taxonomy_fields(category)

        metadata = {
            "scenario_id": spec.scenario_id,
            "type": spec.scenario_type,
            "category": category,
            "attack_technique": spec.attack_technique,
            "cwe": spec.cwe,
            "difficulty": spec.difficulty,
            "steps_expected": difficulty_steps.get(spec.difficulty, 4),
            "description": spec.description,
            "detailed_description": spec.description,
            "variant_of": spec.variant_of,
            "ground_truth_exploit": "exploit.sh",
            "detection_difficulty": taxonomy_fields.get("detection_difficulty", "medium"),
            "interaction_mode": taxonomy_fields.get("interaction_mode", "single_command"),
            "docker_feasibility": taxonomy_fields.get("docker_feasibility", "L1"),
            "ssh_user": params.get("username", "lowpriv"),
            "ssh_pass": params.get("password", "password123"),
            "ssh_port": 22,
        }

        # Override with template-level values if present (from ingester enrichment)
        template_params_file = spec.template_dir / "params.json"
        if template_params_file.exists():
            try:
                tparams = json.loads(template_params_file.read_text())
                for field in ("detection_difficulty",
                              "interaction_mode", "docker_feasibility"):
                    if field in tparams:
                        metadata[field] = tparams[field]
            except (json.JSONDecodeError, OSError):
                pass

        (output_dir / "metadata.json").write_text(
            json.dumps(metadata, indent=2, ensure_ascii=False)
        )

        # Generate run_config.json for evaluation runner
        self._generate_run_config(spec, output_dir)

        # Generate verify.sh for automated differential verification
        self._generate_verify_sh(spec, output_dir)

        # Verify Docker build (Layer 1 pre-check) with LLM auto-fix
        dockerfile_path = output_dir / "Dockerfile"
        success, stderr = self._docker_build(dockerfile_path, spec.scenario_id)
        if not success:
            if self.llm:
                success = self._llm_fix_build(dockerfile_path, stderr)
            if not success:
                return False

        return True

    # ------------------------------------------------------------------
    # Entry A: Template-based rendering (existing behavior)
    # ------------------------------------------------------------------

    def _build_from_template(self, spec) -> bool:
        """Render Jinja2 templates into Dockerfile + Dockerfile.fixed."""
        template_dir = spec.template_dir
        output_dir = spec.output_dir

        env = Environment(
            loader=FileSystemLoader(str(template_dir)),
            keep_trailing_newline=True,
        )

        # Merge default params with instance-specific params
        params_file = template_dir / "params.json"
        defaults = {}
        if params_file.exists():
            schema = json.loads(params_file.read_text())
            for key, val in schema.get("params", {}).items():
                if "default" in val:
                    defaults[key] = val["default"]

        params = {**defaults, **spec.params}

        # Render Dockerfile (vulnerable)
        try:
            tmpl = env.get_template("template.j2")
            dockerfile_content = tmpl.render(**params)
            # Inject hardening layer before vulnerability injection point
            dockerfile_content = self._inject_hardening(
                dockerfile_content, spec.params.get("binary_path", "")
            )
            (output_dir / "Dockerfile").write_text(dockerfile_content)
            logger.info(f"  Rendered Dockerfile for {spec.scenario_id}")
        except Exception as e:
            logger.error(f"  Failed to render Dockerfile: {e}")
            return False

        # Render Dockerfile.fixed
        try:
            tmpl_fixed = env.get_template("template.fixed.j2")
            fixed_content = tmpl_fixed.render(**params)
            (output_dir / "Dockerfile.fixed").write_text(fixed_content)
            logger.info(f"  Rendered Dockerfile.fixed for {spec.scenario_id}")
        except Exception as e:
            logger.error(f"  Failed to render Dockerfile.fixed: {e}")
            return False

        return True

    # ------------------------------------------------------------------
    # Entry B: LLM-based generation (new — core capability)
    # ------------------------------------------------------------------

    def _build_from_llm(self, spec) -> bool:
        """Generate Dockerfile + Dockerfile.fixed via LLM from ATT&CK description."""
        from .llm_client import SCAFFOLDER_ENV_PROMPT

        output_dir = spec.output_dir
        params = spec.params

        # Gather context for the prompt
        technique_id = spec.attack_technique or "unknown"
        technique_name = spec.description or params.get("_category", "")
        gtfobins_exploit = params.get("exploit_cmd", "N/A")
        username = params.get("username", "lowpriv")
        password = params.get("password", "password123")

        # Reference-guided generation: inject verified Dockerfile as one-shot example
        reference_example = ""
        ref_path = getattr(spec, "reference_dockerfile", None)
        if ref_path and ref_path.exists():
            try:
                ref_content = ref_path.read_text()
                reference_example = (
                    f"\n\nHere is a verified reference Dockerfile for a similar "
                    f"vulnerability category. Use it as a structural guide but adapt "
                    f"the vulnerability to match the description above:\n\n"
                    f"```dockerfile\n{ref_content}\n```"
                )
                logger.info(f"  Reference-guided: using {ref_path.parent.name} as example")
            except OSError:
                pass

        logger.info(f"  LLM generating Dockerfiles for {spec.scenario_id}...")

        response = self.llm.chat(
            SCAFFOLDER_ENV_PROMPT["system"],
            SCAFFOLDER_ENV_PROMPT["user"].format(
                technique_id=technique_id,
                technique_name=technique_name,
                description=spec.description,
                gtfobins_exploit=gtfobins_exploit,
                username=username,
                password=password,
                reference_example=reference_example,
            ),
        )

        # Parse the two Dockerfiles from response
        vuln_content, fixed_content = self._parse_dual_dockerfile(response)
        if not vuln_content:
            logger.error(f"  LLM failed to generate valid Dockerfiles for {spec.scenario_id}")
            return False

        (output_dir / "Dockerfile").write_text(vuln_content)
        (output_dir / "Dockerfile.fixed").write_text(fixed_content)
        logger.info(f"  LLM generated Dockerfile + Dockerfile.fixed for {spec.scenario_id}")
        return True

    def _parse_dual_dockerfile(self, response: str) -> tuple[str, str]:
        """
        Parse LLM response containing two Dockerfiles separated by ---FIXED---.
        Returns (vuln_content, fixed_content). Returns ("", "") on failure.
        """
        # Strip markdown code fences if present
        response = re.sub(r"```dockerfile\s*", "", response)
        response = re.sub(r"```\s*", "", response)

        marker = "---FIXED---"
        if marker not in response:
            # Try alternative markers
            for alt in ["---FIXED---", "# FIXED", "## Dockerfile.fixed", "---"]:
                if alt in response:
                    marker = alt
                    break
            else:
                logger.warning("  LLM response missing ---FIXED--- marker")
                return ("", "")

        parts = response.split(marker, 1)
        vuln = parts[0].strip()
        fixed = parts[1].strip() if len(parts) > 1 else ""

        if not vuln.startswith("FROM") or not fixed.startswith("FROM"):
            logger.warning("  LLM Dockerfiles don't start with FROM")
            return ("", "")

        return (vuln, fixed)

    # ------------------------------------------------------------------
    # LLM auto-fix for build failures
    # ------------------------------------------------------------------

    def _llm_fix_build(self, dockerfile: Path, stderr: str) -> bool:
        """Attempt to fix a failing Dockerfile using LLM."""
        from .llm_client import SCAFFOLDER_FIX_PROMPT

        content = dockerfile.read_text()
        for attempt in range(1, LLM_BUILD_FIX_MAX + 1):
            logger.info(f"  LLM fix attempt {attempt} for {dockerfile.name}...")

            fixed = self.llm.chat(
                SCAFFOLDER_FIX_PROMPT["system"],
                SCAFFOLDER_FIX_PROMPT["user"].format(
                    dockerfile_content=content,
                    error_output=stderr[-2000:],  # truncate long errors
                ),
            )

            # Strip markdown fences
            fixed = re.sub(r"```dockerfile\s*", "", fixed)
            fixed = re.sub(r"```\s*", "", fixed).strip()

            if not fixed.startswith("FROM"):
                logger.warning("  LLM fix doesn't start with FROM, skipping")
                continue

            dockerfile.write_text(fixed)
            success, stderr = self._docker_build(
                dockerfile, dockerfile.parent.name + "-fix"
            )
            if success:
                logger.info(f"  LLM fix succeeded on attempt {attempt}")
                return True
            content = fixed  # feed the fixed version back for next attempt

        logger.error(f"  LLM fix exhausted {LLM_BUILD_FIX_MAX} attempts")
        return False

    # ------------------------------------------------------------------
    # LLM-driven Dockerfile repair (called by Manager feedback loop)
    # ------------------------------------------------------------------

    def fix_dockerfile(self, spec, diagnosis: dict) -> bool:
        """
        Apply a diagnosed fix to the Dockerfile.

        Called by Manager when Verifier diagnosis points to a Dockerfile issue.
        `diagnosis` is a parsed JSON dict from VERIFIER_DIAGNOSE_PROMPT.
        """
        dockerfile_fix = diagnosis.get("dockerfile_fix")
        if not dockerfile_fix:
            logger.warning("  No dockerfile_fix in diagnosis")
            return False

        output_dir = spec.output_dir
        target = output_dir / "Dockerfile"
        target.write_text(dockerfile_fix)
        logger.info(f"  Applied LLM diagnosis fix to Dockerfile for {spec.scenario_id}")

        # Verify the fix builds
        success, _ = self._docker_build(target, spec.scenario_id + "-diag")
        return success

    # ------------------------------------------------------------------
    # Base hardening (Step 8)
    # ------------------------------------------------------------------

    def _inject_hardening(self, dockerfile_content: str, target_binary: str) -> str:
        """
        Inject hardening commands into a Dockerfile to remove
        unintended SUID/SGID binaries, keeping only the target.

        Inserted after the last RUN apt-get/apt install line,
        before the vulnerability injection.
        """
        lines = dockerfile_content.split("\n")
        insert_idx = None

        # Find the last apt install line
        for i, line in enumerate(lines):
            if re.search(r"(apt-get|apt)\s+install", line):
                # Walk past continuation lines
                j = i
                while j < len(lines) - 1 and lines[j].rstrip().endswith("\\"):
                    j += 1
                insert_idx = j + 1

        if insert_idx is None:
            return dockerfile_content

        # Customize hardening: preserve the target binary's SUID if needed
        harden = _HARDEN_COMMANDS
        if target_binary:
            binary_name = Path(target_binary).name
            harden = harden.replace(
                "grep -v -E '(su$|ping$)'",
                f"grep -v -E '(su$|ping$|{re.escape(binary_name)}$)'",
            )

        lines.insert(insert_idx, harden)
        return "\n".join(lines)

    def _generate_run_config(self, spec, output_dir: Path):
        """Generate run_config.json for the evaluation runner."""
        category = spec.params.get("_category", "")
        description = (spec.description or "").lower()
        # Detect cron-based scenarios from category or description
        is_cron = (
            "cron" in category.lower()
            or "cron" in description
            or "scheduled" in category.lower()
        )

        # Detect docker-in-docker scenarios
        is_docker = (
            "docker" in category.lower()
            or "docker" in description
            or "container_escape" in category.lower()
        )

        config = {
            "docker_run_args": [],
            "requires_privileged": False,
            "startup_delay": 5 if is_cron else 3,
            "note": "",
        }

        if is_cron:
            config["cron_wait"] = 65
            config["note"] = "Cron job triggers every minute"

        if is_docker:
            config["docker_run_args"] = [
                "--privileged",
                "-v", "/var/run/docker.sock:/var/run/docker.sock",
            ]
            config["requires_privileged"] = True
            config["note"] = "Docker-in-Docker requires host Docker socket"

        config_path = output_dir / "run_config.json"
        config_path.write_text(
            json.dumps(config, indent=2, ensure_ascii=False) + "\n"
        )
        logger.info(f"  Generated run_config.json for {spec.scenario_id}")

    def _generate_verify_sh(self, spec, output_dir: Path):
        """Generate a generic verify.sh for automated differential verification."""
        scenario_id = spec.scenario_id
        username = spec.params.get("username", "lowpriv")

        content = f"""#!/bin/bash
# Differential verification for {scenario_id}
# Auto-generated by PrivEscGen Scaffolder
# Returns 0 if scenario is correctly configured, 1 otherwise

set -e
SCENARIO_DIR="$(cd "$(dirname "$0")" && pwd)"
SCENARIO_NAME="$(basename "$SCENARIO_DIR")"
IMAGE_NAME="$(printf '%s' "${{SCENARIO_NAME}}" | tr '[:upper:]' '[:lower:]')"
VULN_IMAGE="privesc-${{IMAGE_NAME}}-vuln"
FIXED_IMAGE="privesc-${{IMAGE_NAME}}-fixed"

echo "=== Verifying scenario: ${{SCENARIO_NAME}} ==="

# Layer 1: Build verification
echo "[L1] Building vulnerable image..."
docker build -t "$VULN_IMAGE" -f "$SCENARIO_DIR/Dockerfile" "$SCENARIO_DIR" > /dev/null 2>&1
echo "[L1] Building fixed image..."
docker build -t "$FIXED_IMAGE" -f "$SCENARIO_DIR/Dockerfile.fixed" "$SCENARIO_DIR" > /dev/null 2>&1
echo "[L1] PASS: Both images build successfully"

# Layer 2: Exploit differential test
if [ ! -f "$SCENARIO_DIR/exploit.sh" ]; then
    echo "[L2] SKIP: No exploit.sh found"
    docker rmi "$VULN_IMAGE" "$FIXED_IMAGE" > /dev/null 2>&1 || true
    exit 0
fi

echo "[L2] Testing exploit on vulnerable image..."
VULN_CONTAINER=$(docker run -d "$VULN_IMAGE")
sleep 2

# Copy exploit into container and run as low-priv user
docker cp "$SCENARIO_DIR/exploit.sh" "$VULN_CONTAINER:/tmp/exploit.sh"
docker exec "$VULN_CONTAINER" chmod +x /tmp/exploit.sh
VULN_RESULT=$(docker exec "$VULN_CONTAINER" su - {username} -c "bash /tmp/exploit.sh; id" 2>&1 || true)
docker rm -f "$VULN_CONTAINER" > /dev/null 2>&1

if echo "$VULN_RESULT" | grep -q "uid=0"; then
    echo "[L2] PASS: Exploit achieves root on vulnerable image"
else
    echo "[L2] FAIL: Exploit does not achieve root on vulnerable image"
    echo "  Output: $VULN_RESULT"
    docker rmi "$VULN_IMAGE" "$FIXED_IMAGE" > /dev/null 2>&1 || true
    exit 1
fi

# Check exploit fails on fixed image
echo "[L2] Testing exploit on fixed image..."
FIXED_CONTAINER=$(docker run -d "$FIXED_IMAGE")
sleep 2

docker cp "$SCENARIO_DIR/exploit.sh" "$FIXED_CONTAINER:/tmp/exploit.sh"
docker exec "$FIXED_CONTAINER" chmod +x /tmp/exploit.sh
FIXED_RESULT=$(docker exec "$FIXED_CONTAINER" su - {username} -c "bash /tmp/exploit.sh; id" 2>&1 || true)
docker rm -f "$FIXED_CONTAINER" > /dev/null 2>&1

if echo "$FIXED_RESULT" | grep -q "uid=0"; then
    echo "[L2] FAIL: Exploit still achieves root on fixed image"
    docker rmi "$VULN_IMAGE" "$FIXED_IMAGE" > /dev/null 2>&1 || true
    exit 1
else
    echo "[L2] PASS: Exploit fails on fixed image"
fi

# Cleanup images
docker rmi "$VULN_IMAGE" "$FIXED_IMAGE" > /dev/null 2>&1 || true

echo "=== VERIFIED: ${{SCENARIO_NAME}} ==="
exit 0
"""
        verify_path = output_dir / "verify.sh"
        verify_path.write_text(content)
        verify_path.chmod(0o755)
        logger.info(f"  Generated verify.sh for {scenario_id}")

    def _get_taxonomy_fields(self, category: str) -> dict:
        """Look up taxonomy defaults for a given category.

        Loads taxonomy_knowledge.json and returns the extended classification
        dimensions (detection_difficulty, interaction_mode, and
        docker_feasibility) for the given category.

        Returns an empty dict if taxonomy is unavailable or category not found.
        """
        taxonomy_path = self.project_root / "dataset" / "sources" / "taxonomy_knowledge.json"
        if not taxonomy_path.exists() or not category:
            return {}
        try:
            data = json.loads(taxonomy_path.read_text(encoding="utf-8"))
            cat_info = data.get("categories", {}).get(category, {})
            if not cat_info:
                return {}
            # interaction_mode in taxonomy is a list; pick the first as default
            interaction_modes = cat_info.get("interaction_mode", [])
            default_mode = interaction_modes[0] if interaction_modes else "single_command"
            return {
                "detection_difficulty": cat_info.get("detection_difficulty", "medium"),
                "interaction_mode": default_mode,
                "docker_feasibility": cat_info.get("docker_feasibility", "L1"),
            }
        except (json.JSONDecodeError, OSError):
            return {}

    @staticmethod
    def _harden_base() -> str:
        """Return Dockerfile snippet for base hardening (usable by LLM prompts)."""
        return _HARDEN_COMMANDS

    # ------------------------------------------------------------------
    # Docker build helper
    # ------------------------------------------------------------------

    def _docker_build(self, dockerfile: Path, tag_suffix: str) -> tuple[bool, str]:
        """
        Attempt to build a Dockerfile.
        Returns (success: bool, stderr: str).
        """
        tag = f"privesc-{tag_suffix}-test".lower()
        try:
            result = subprocess.run(
                ["docker", "build", "-t", tag, "-f", str(dockerfile), str(dockerfile.parent)],
                capture_output=True,
                text=True,
                timeout=120,
            )
            if result.returncode == 0:
                # Cleanup test image
                subprocess.run(["docker", "rmi", tag], capture_output=True, timeout=30)
                return (True, "")
            else:
                logger.error(f"  Docker build failed:\n{result.stderr[-500:]}")
                return (False, result.stderr)
        except subprocess.TimeoutExpired:
            logger.error("  Docker build timed out")
            return (False, "Build timed out after 120 seconds")
        except FileNotFoundError:
            logger.error("  Docker not found. Is Docker installed?")
            return (False, "Docker not found")
