#!/usr/bin/env python3
"""
PrivEscalate Scenario Generator — CLI Entry Point

LLM is REQUIRED as the coordination backbone. Templates are used as
an optimization when available; LLM handles generation, repair, and
adaptation for everything else.

Usage:
  # Generate ALL scenarios
  python generate.py --all --provider openai --model gpt-4o

  # Generate from text description (no template needed)
  python generate.py --describe "SUID bit on find binary" --provider openai

  # Generate from a file of descriptions
  python generate.py --describe-file vulns.txt --provider openai

  # Generate with auto-generated variants
  python generate.py --all --variants 2 --provider openai

  # List all available templates
  python generate.py --list
"""

import argparse
import json
import logging
import os
import subprocess
import sys
import time
from pathlib import Path

# Add project root to path
PROJECT_ROOT = Path(__file__).parent
sys.path.insert(0, str(PROJECT_ROOT))

from privescgen.manager import Manager, ScenarioSpec  # noqa: E402
from privescgen.ingester import DataIngester  # noqa: E402

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    datefmt="%H:%M:%S",
)
logger = logging.getLogger(__name__)

# Rich imports (optional)
try:
    from rich.console import Console
    from rich.table import Table
    console = Console()
    HAS_RICH = True
except ImportError:
    HAS_RICH = False


def create_llm_client(args):
    """Create LLMClient from CLI arguments. LLM is required."""
    from privescgen.llm_client import LLMClient

    api_key = args.api_key
    if not api_key:
        env_key = {
            "openai": "OPENAI_API_KEY",
            "anthropic": "ANTHROPIC_API_KEY",
        }.get(args.provider)
        if env_key:
            api_key = os.getenv(env_key)

    if not api_key:
        logger.error(
            f"No API key for {args.provider}. "
            f"Set --api-key or environment variable."
        )
        sys.exit(1)

    try:
        client = LLMClient(
            provider=args.provider,
            model=args.model,
            api_key=api_key,
            temperature=args.temperature,
        )
        logger.info(f"LLM initialized: {args.provider}/{args.model}")
        return client
    except ImportError as e:
        logger.error(f"LLM SDK not installed: {e}")
        sys.exit(1)


# ------------------------------------------------------------------
# --list
# ------------------------------------------------------------------

def list_templates(templates_dir: Path):
    """List all available templates with instance counts."""
    if HAS_RICH:
        _list_templates_rich(templates_dir)
    else:
        _list_templates_plain(templates_dir)


def _list_templates_rich(templates_dir: Path):
    table = Table(title="Available Templates")
    table.add_column("Template", style="cyan bold")
    table.add_column("ATT&CK", style="yellow")
    table.add_column("CWE")
    table.add_column("Instances", justify="right")
    table.add_column("Core", justify="right", style="green")
    table.add_column("Variant", justify="right", style="blue")
    table.add_column("Mode")

    total_instances = 0
    for tdir in sorted(templates_dir.iterdir()):
        if not tdir.is_dir():
            continue
        params_file = tdir / "params.json"
        if not params_file.exists():
            continue

        params = json.loads(params_file.read_text())
        attack = params.get("attack_technique", "?")
        cwe = params.get("cwe", "?")
        instances = params.get("instances", [])
        core_count = sum(1 for i in instances if i.get("type", "core") == "core")
        var_count = sum(1 for i in instances if i.get("type") == "variant")
        has_template = "Template" if (tdir / "template.j2").exists() else "[dim]LLM-only[/]"
        total_instances += len(instances)

        table.add_row(
            tdir.name, attack, cwe,
            str(len(instances)), str(core_count), str(var_count),
            has_template,
        )

    table.caption = f"Total: {total_instances} scenario instances"
    console.print(table)


def _list_templates_plain(templates_dir: Path):
    print(f"\n{'Template':<25} {'ATT&CK':<12} {'Instances':<10} {'Mode'}")
    print("-" * 60)
    for tdir in sorted(templates_dir.iterdir()):
        if not tdir.is_dir():
            continue
        pf = tdir / "params.json"
        if not pf.exists():
            continue
        params = json.loads(pf.read_text())
        attack = params.get("attack_technique", "?")
        insts = params.get("instances", [])
        mode = "Template" if (tdir / "template.j2").exists() else "LLM-only"
        print(f"  {tdir.name:<23} {attack:<12} {len(insts):<10} {mode}")
    print()


# ------------------------------------------------------------------
# --describe / --describe-file
# ------------------------------------------------------------------

def generate_from_description(
    description: str,
    provider_args,
    templates_dir: Path,
    scenarios_dir: Path,
    manager: Manager,
):
    """Generate a scenario from a natural language description using LLM."""
    from privescgen.llm_client import MANAGER_PARSE_PROMPT

    logger.info(f"Parsing description: {description[:80]}...")

    # LLM extracts structured spec from description
    response = manager.llm.chat(
        MANAGER_PARSE_PROMPT["system"],
        MANAGER_PARSE_PROMPT["user"].format(description=description),
    )

    # Parse JSON response
    import re
    response = re.sub(r"```json\s*", "", response)
    response = re.sub(r"```\s*", "", response).strip()

    try:
        spec_data = json.loads(response)
    except json.JSONDecodeError:
        import re as _re
        match = _re.search(r"\{.*\}", response, _re.DOTALL)
        if match:
            spec_data = json.loads(match.group())
        else:
            logger.error("Failed to parse LLM response as JSON")
            return []

    scenario_id = spec_data.get("scenario_id", f"auto_{int(time.time())}")
    attack_technique = spec_data.get("attack_technique", "T0000")
    cwe = spec_data.get("cwe", "")
    difficulty = spec_data.get("difficulty", "medium")
    params = spec_data.get("params", {})
    params["_template_id"] = "llm_generated"
    params["_category"] = spec_data.get("category", "")

    # Create a temporary template dir (no template.j2 → LLM generates Dockerfile)
    temp_template_dir = templates_dir / f"_auto_{scenario_id}"
    temp_template_dir.mkdir(parents=True, exist_ok=True)

    # Write params.json for traceability
    params_json = {
        "template_id": f"auto_{scenario_id}",
        "category": spec_data.get("category", ""),
        "attack_technique": attack_technique,
        "cwe": cwe,
        "description": description,
        "params": {k: {"type": "string", "default": v} for k, v in params.items() if not k.startswith("_")},
        "instances": [{"scenario_id": scenario_id, "type": "core", "difficulty": difficulty}],
    }
    (temp_template_dir / "params.json").write_text(json.dumps(params_json, indent=2))

    output_dir = scenarios_dir / "core" / scenario_id
    spec = ScenarioSpec(
        scenario_id=scenario_id,
        template_dir=temp_template_dir,
        params=params,
        output_dir=output_dir,
        scenario_type="core",
        difficulty=difficulty,
        attack_technique=attack_technique,
        cwe=cwe,
        description=description,
    )

    logger.info(f"Generating: {scenario_id} (LLM-generated, {difficulty})")
    result = manager.build_scenario(spec)

    if result.success:
        logger.info(f"  [OK] {scenario_id}: Generated and verified")
    else:
        logger.warning(f"  [REVIEW] {scenario_id}: {result.error}")

    return [result]


def generate_from_description_file(
    filepath: str,
    provider_args,
    templates_dir: Path,
    scenarios_dir: Path,
    manager: Manager,
):
    """Generate scenarios from a file of descriptions (one per line)."""
    desc_file = Path(filepath)
    if not desc_file.exists():
        logger.error(f"Description file not found: {filepath}")
        return []

    descriptions = [
        line.strip() for line in desc_file.read_text().splitlines()
        if line.strip() and not line.startswith("#")
    ]

    logger.info(f"Found {len(descriptions)} descriptions in {filepath}")

    all_results = []
    for desc in descriptions:
        results = generate_from_description(
            desc, provider_args, templates_dir, scenarios_dir, manager
        )
        all_results.extend(results)

    return all_results


# ------------------------------------------------------------------
# --template / --all
# ------------------------------------------------------------------

def generate_from_template(
    template_name: str,
    instance_id: str | None,
    templates_dir: Path,
    scenarios_dir: Path,
    manager: Manager,
    num_variants: int = 0,
):
    """Generate scenario(s) from a template."""
    tdir = templates_dir / template_name
    if not tdir.exists():
        logger.error(f"Template not found: {template_name}")
        return []

    params_file = tdir / "params.json"
    if not params_file.exists():
        logger.error(f"No params.json in {template_name}")
        return []

    schema = json.loads(params_file.read_text())
    instances = schema.get("instances", [])

    # Filter to specific instance if requested
    if instance_id:
        instances = [i for i in instances if i.get("scenario_id") == instance_id]
        if not instances:
            logger.error(f"Instance not found: {instance_id}")
            return []

    # Get default params
    defaults = {}
    for key, val in schema.get("params", {}).items():
        if isinstance(val, dict) and "default" in val:
            defaults[key] = val["default"]

    has_template = (tdir / "template.j2").exists()

    # Generate LLM variants if requested
    if num_variants > 0 and manager.llm:
        new_variants = _generate_variants(schema, defaults, manager, num_variants)
        instances.extend(new_variants)

    results = []
    for inst in instances:
        scenario_id = inst["scenario_id"]
        scenario_type = inst.get("type", "core")
        output_dir = scenarios_dir / scenario_type / scenario_id

        # Merge defaults with instance-specific params
        inst_params = {**defaults}
        for k, v in inst.items():
            if k not in ("scenario_id", "type", "difficulty", "variant_of"):
                inst_params[k] = v
        inst_params["_template_id"] = schema.get("template_id", template_name)
        inst_params["_category"] = schema.get("category", "")
        # Propagate top-level fields needed by scaffolder/exploiter
        if "exploit_cmd" not in inst_params:
            inst_params["exploit_cmd"] = schema.get("exploit_cmd", schema.get("description", ""))
        if "binary_path" not in inst_params:
            inst_params["binary_path"] = schema.get("binary_path", "")

        spec = ScenarioSpec(
            scenario_id=scenario_id,
            template_dir=tdir,
            params=inst_params,
            output_dir=output_dir,
            scenario_type=scenario_type,
            difficulty=inst.get("difficulty", "medium"),
            attack_technique=schema.get("attack_technique", ""),
            cwe=schema.get("cwe", ""),
            description=schema.get("description", ""),
            variant_of=inst.get("variant_of"),
        )

        mode = "Template+LLM" if has_template else "LLM-generated"
        logger.info(f"Generating: {scenario_id} ({scenario_type}, {spec.difficulty}, {mode})")
        result = manager.build_scenario(spec, skip_failed=False)
        results.append(result)

        if result.success:
            logger.info(f"  [OK] {scenario_id}")
        elif result.needs_manual_review:
            logger.warning(f"  [REVIEW] {scenario_id}: {result.error}")
        else:
            logger.error(f"  [FAIL] {scenario_id}: {result.error}")

    return results


def _generate_variants(schema: dict, defaults: dict, manager, num_variants: int) -> list:
    """Use LLM to generate parameter variants for a template."""
    from privescgen.llm_client import SCAFFOLDER_VARIANT_PROMPT

    template_id = schema.get("template_id", "unknown")
    attack_technique = schema.get("attack_technique", "")
    description = schema.get("description", "")

    # Find a core instance as base
    core_instances = [i for i in schema.get("instances", []) if i.get("type", "core") == "core"]
    if not core_instances:
        return []

    base = core_instances[0]
    base_params = {**defaults}
    for k, v in base.items():
        if k not in ("scenario_id", "type", "difficulty", "variant_of"):
            base_params[k] = v

    logger.info(f"  Generating {num_variants} LLM variants for {template_id}...")

    response = manager.llm.chat(
        SCAFFOLDER_VARIANT_PROMPT["system"],
        SCAFFOLDER_VARIANT_PROMPT["user"].format(
            template_id=template_id,
            attack_technique=attack_technique,
            base_params=json.dumps(base_params, indent=2),
            description=description,
            num_variants=num_variants,
            base_scenario_id=base["scenario_id"],
            difficulty=base.get("difficulty", "medium"),
        ),
    )

    import re
    response = re.sub(r"```json\s*", "", response)
    response = re.sub(r"```\s*", "", response).strip()

    try:
        data = json.loads(response)
        variants = data.get("variants", [])
        logger.info(f"  LLM generated {len(variants)} variants")
        return variants
    except json.JSONDecodeError:
        logger.warning("  Failed to parse LLM variant response")
        return []


# ------------------------------------------------------------------
# --auto-discover
# ------------------------------------------------------------------

def generate_from_discovery(
    source: str,
    max_scenarios: int,
    filter_category: str | None,
    templates_dir: Path,
    scenarios_dir: Path,
    manager: Manager,
    use_llm_filter: bool = True,
):
    """Generate scenarios from auto-discovered vulnerabilities.

    Args:
        source: Data source — "gtfobins", "exploitdb", or "all".
        max_scenarios: Maximum number of scenarios to generate (0 = no limit).
        filter_category: Optional category filter (e.g., "A1_suid_sgid").
        templates_dir: Templates directory.
        scenarios_dir: Scenarios output directory.
        manager: Manager instance with LLM client.
        use_llm_filter: Whether to use LLM for Exploit-DB feasibility
            classification (default True).

    Returns:
        List of BuildResult objects.
    """
    ingester = DataIngester(manager.project_root, llm=manager.llm)
    categories = [filter_category] if filter_category else None
    # 0 or negative means no limit
    limit = max_scenarios if max_scenarios and max_scenarios > 0 else None

    # Phase 1: Discover and write templates (no Docker build)
    all_specs = []

    if source in ("gtfobins", "all"):
        specs = ingester.discover_gtfobins(
            max_scenarios=limit, categories=categories
        )
        if specs:
            logger.info(f"Auto-discover (GTFOBins): {len(specs)} templates written")
            all_specs.extend(specs)
        else:
            logger.info("Auto-discover (GTFOBins): no new scenarios to generate")

    if source in ("exploitdb", "all"):
        edb_specs = ingester.discover_exploitdb(use_llm_filter=use_llm_filter)
        if limit and len(edb_specs) > limit:
            logger.info(
                f"Auto-discover (Exploit-DB): truncating {len(edb_specs)} "
                f"feasible scenarios to limit={limit}"
            )
            edb_specs = edb_specs[:limit]
        if edb_specs:
            logger.info(f"Auto-discover (Exploit-DB): {len(edb_specs)} templates written")
            all_specs.extend(edb_specs)
        else:
            logger.info("Auto-discover (Exploit-DB): no new descriptions to generate")

    logger.info(
        f"Auto-discover complete: {len(all_specs)} templates ready. "
        f"Use --all to build scenarios from templates."
    )
    # Return specs but do NOT build — building is done by --all
    return all_specs


def generate_all(
    templates_dir: Path,
    scenarios_dir: Path,
    manager: Manager,
    num_variants: int = 0,
    shard: tuple[int, int] | None = None,
    retry_failed: bool = False,
):
    """Generate all scenarios from all templates.

    Args:
        shard: Optional (index, total) tuple for parallel sharding.
               When set, only templates where sorted_index % total == index
               are processed. This allows multiple processes to run in
               parallel without overlap.
        retry_failed: If True, retry previously-failed templates.
               Default False — failed templates are skipped.
    """
    all_results = []

    tdirs = sorted(
        tdir for tdir in templates_dir.iterdir()
        if tdir.is_dir() and (tdir / "params.json").exists()
    )

    if shard is not None:
        shard_idx, shard_total = shard
        total_before = len(tdirs)
        tdirs = [t for i, t in enumerate(tdirs) if i % shard_total == shard_idx]
        logger.info(
            f"Shard {shard_idx}/{shard_total}: processing {len(tdirs)}/{total_before} templates"
        )

    skipped_failed = 0
    for tdir in tdirs:
        if not tdir.is_dir() or not (tdir / "params.json").exists():
            continue

        # Skip previously failed templates unless --retry-failed
        if not retry_failed:
            try:
                status = json.loads((tdir / "params.json").read_text()).get("status", "pending")
                if status == "failed":
                    skipped_failed += 1
                    continue
            except (json.JSONDecodeError, OSError):
                pass

        try:
            # Auto-generated templates (_auto_*) go through manager.build_batch
            if tdir.name.startswith("_auto_"):
                from privescgen.manager import ScenarioSpec
                import json as _json
                params = _json.loads((tdir / "params.json").read_text())
                scenario_id = params.get("instances", [{}])[0].get("scenario_id", tdir.name.replace("_auto_", ""))
                output_dir = scenarios_dir / "core" / scenario_id
                ref_dockerfile = None
                # Find reference from same category
                category = params.get("category", "")
                for existing in sorted((scenarios_dir / "core").iterdir()) if (scenarios_dir / "core").exists() else []:
                    meta_f = existing / "metadata.json"
                    if meta_f.exists():
                        try:
                            emeta = _json.loads(meta_f.read_text())
                            if emeta.get("category") == category:
                                ref_dockerfile = existing / "Dockerfile"
                                break
                        except Exception:
                            pass
                spec = ScenarioSpec(
                    scenario_id=scenario_id,
                    template_dir=tdir,
                    params={
                        "username": "lowpriv",
                        "password": "password123",
                        "root_password": "r00tSecure!",
                        "exploit_cmd": params.get("exploit_cmd", params.get("description", "")),
                        "binary_path": params.get("binary_path", ""),
                        "_template_id": params.get("template_id", ""),
                        "_category": category,
                    },
                    output_dir=output_dir,
                    scenario_type="core",
                    difficulty=params.get("instances", [{}])[0].get("difficulty", "medium"),
                    attack_technique=params.get("attack_technique", ""),
                    cwe=params.get("cwe", ""),
                    description=params.get("description", ""),
                    reference_dockerfile=ref_dockerfile,
                )
                batch_results = manager.build_batch([spec])
                all_results.extend(batch_results)
                continue

            results = generate_from_template(
                tdir.name, None, templates_dir, scenarios_dir, manager,
                num_variants=num_variants,
            )
            all_results.extend(results)
        except KeyboardInterrupt:
            logger.warning(f"Interrupted at template {tdir.name}")
            raise
        except Exception as e:
            logger.error(f"[CRASH] Template {tdir.name} failed with: {e}")
            # Append to crash list for later retry via --from-list
            crash_list = PROJECT_ROOT / ".cache" / "logs" / "crashed_templates.txt"
            crash_list.parent.mkdir(parents=True, exist_ok=True)
            try:
                import fcntl
                with open(crash_list, "a") as f:
                    fcntl.flock(f, fcntl.LOCK_EX)
                    f.write(f"{tdir.name}\n")
                    f.flush()
                    fcntl.flock(f, fcntl.LOCK_UN)
            except OSError:
                pass
            continue

    if skipped_failed > 0:
        logger.info(f"Skipped {skipped_failed} previously-failed templates (use --retry-failed to retry)")

    return all_results


# ------------------------------------------------------------------
# --verify
# ------------------------------------------------------------------

def verify_all(scenarios_dir: Path):
    """Run verify.sh for all scenarios that have it."""
    if HAS_RICH:
        console.print("\n[bold]Verifying All Scenarios[/]\n")
    else:
        print("\n=== Verifying All Scenarios ===\n")

    total = passed = failed = skipped = 0

    for type_dir in ["core", "variants"]:
        sdir = scenarios_dir / type_dir
        if not sdir.exists():
            continue
        for scenario_dir in sorted(sdir.iterdir()):
            if not scenario_dir.is_dir():
                continue
            total += 1
            verify_script = scenario_dir / "verify.sh"

            if not verify_script.exists():
                print(f"  SKIP {scenario_dir.name}")
                skipped += 1
                continue

            try:
                result = subprocess.run(
                    ["bash", str(verify_script)],
                    capture_output=True, text=True, timeout=180,
                )
                if result.returncode == 0:
                    print(f"  PASS {scenario_dir.name}")
                    passed += 1
                else:
                    print(f"  FAIL {scenario_dir.name}")
                    failed += 1
            except subprocess.TimeoutExpired:
                print(f"  TIMEOUT {scenario_dir.name}")
                failed += 1
            except Exception as e:
                print(f"  ERROR {scenario_dir.name}: {e}")
                failed += 1

    print(f"\nTotal: {total} | Passed: {passed} | Failed: {failed} | Skipped: {skipped}")


# ------------------------------------------------------------------
# main
# ------------------------------------------------------------------

def main():
    parser = argparse.ArgumentParser(
        description="PrivEscalate Scenario Generator (LLM-Driven Pipeline)",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python generate.py --list
  python generate.py --all --provider openai
  python generate.py --all --variants 2 --provider openai
  python generate.py --describe "SUID on find" --provider openai
  python generate.py --describe-file vulns.txt --provider openai
  python generate.py --template suid_gtfobins --provider openai
  python generate.py --all --verify --provider openai --report report.json
  python generate.py --auto-discover gtfobins --max-scenarios 50 --provider openai
  python generate.py --auto-discover all --filter-category A1_suid_sgid --provider openai
  python generate.py --from-list .cache/logs/crashed_templates.txt --provider openai
        """,
    )

    # Mode arguments
    parser.add_argument("--list", action="store_true", help="List available templates")
    parser.add_argument("--template", type=str, help="Generate from a specific template")
    parser.add_argument("--instance", type=str, help="Generate a specific instance")
    parser.add_argument("--all", action="store_true", help="Generate all scenarios")
    parser.add_argument("--describe", type=str, help="Generate from a text description (LLM parses it)")
    parser.add_argument("--describe-file", type=str, help="Generate from a file of descriptions (one per line)")
    parser.add_argument("--auto-discover", type=str, choices=["gtfobins", "exploitdb", "all"],
                        help="Auto-discover vulnerabilities from data sources")
    parser.add_argument("--max-scenarios", type=int, default=0,
                        help="Max scenarios for --auto-discover (default: 0 = no limit)")
    parser.add_argument("--filter-category", type=str, default=None,
                        help="Filter by category for --auto-discover (e.g., A1_suid_sgid)")
    parser.add_argument("--no-llm-filter", action="store_true",
                        help="Disable LLM feasibility classification for Exploit-DB")
    parser.add_argument("--variants", type=int, default=0, help="Auto-generate N variants per template via LLM")
    parser.add_argument("--verify", action="store_true", help="Run verification on scenarios")
    parser.add_argument("--shard", type=str, default=None,
                        help="Process only shard I of N templates (format: I/N, e.g. 0/3). "
                             "Allows multiple processes to run in parallel.")
    parser.add_argument("--from-list", type=str, default=None,
                        help="Generate only templates listed in a file (one name per line). "
                             "Use with .cache/logs/crashed_templates.txt to retry crashed ones.")
    parser.add_argument("--retry-failed", action="store_true",
                        help="Retry templates previously marked as failed (default: skip)")
    parser.add_argument("--show-progress", action="store_true",
                        help="Show generation progress summary and exit")
    parser.add_argument("--output", type=str, default=None, help="Custom output directory")
    parser.add_argument("--report", type=str, default=None, help="Export JSON build report")
    parser.add_argument("--report-html", type=str, default=None, help="Export HTML build report")
    parser.add_argument("-v", "--verbose", action="store_true", help="Verbose output")

    # LLM arguments
    llm_group = parser.add_argument_group("LLM configuration (required for generation)")
    llm_group.add_argument("--provider", type=str, choices=["openai", "anthropic"],
                           default=os.environ.get("PRIVESC_LLM_PROVIDER"))
    llm_group.add_argument("--model", type=str,
                           default=os.environ.get("PRIVESC_LLM_MODEL", "gpt-4o"))
    llm_group.add_argument("--api-key", type=str, default=None)
    llm_group.add_argument("--temperature", type=float, default=0.2)

    args = parser.parse_args()

    if args.verbose:
        logging.getLogger().setLevel(logging.DEBUG)

    templates_dir = PROJECT_ROOT / "dataset" / "templates"
    if args.output:
        scenarios_dir = Path(args.output)
    elif args.all or args.verify:
        # Production mode: output to dataset/scenarios/
        scenarios_dir = PROJECT_ROOT / "dataset" / "scenarios"
    else:
        # Development mode: choose a timestamped output dir.  Read-only modes
        # must not leave an empty output directory behind.
        from datetime import datetime
        ts = datetime.now().strftime("%Y%m%d_%H%M%S")
        task_hint = (args.describe or args.template or args.auto_discover or "run")[:40]
        task_hint = task_hint.replace(" ", "_").replace("/", "_")
        scenarios_dir = PROJECT_ROOT / "output" / f"{ts}_{task_hint}"
        if not (args.list or args.show_progress):
            scenarios_dir.mkdir(parents=True, exist_ok=True)
            logger.info(f"Output dir: {scenarios_dir}")

    if args.show_progress:
        # Show generation progress summary from templates
        import json as _json
        pending = verified = failed = scaffolded = exploited = 0
        for tdir in sorted(templates_dir.iterdir()) if templates_dir.exists() else []:
            pf = tdir / "params.json"
            if pf.exists():
                try:
                    status = _json.loads(pf.read_text()).get("status", "pending")
                except Exception:
                    status = "pending"
                if status == "verified":
                    verified += 1
                elif status == "failed":
                    failed += 1
                elif status == "scaffolded":
                    scaffolded += 1
                elif status == "exploited":
                    exploited += 1
                else:
                    pending += 1
        total = pending + verified + failed + scaffolded + exploited
        print("Generation Progress:")
        print(f"  Verified:   {verified}")
        print(f"  Failed:     {failed}")
        print(f"  Scaffolded: {scaffolded}")
        print(f"  Exploited:  {exploited}")
        print(f"  Pending:    {pending}")
        print(f"  Total:      {total}")
        # Also show core scenarios
        core_dir = scenarios_dir if args.output else PROJECT_ROOT / "dataset" / "scenarios" / "core"
        core_count = len(list(core_dir.iterdir())) if core_dir.exists() else 0
        print(f"\n  Core scenarios: {core_count}")
        return

    if args.list:
        list_templates(templates_dir)
        return

    # Determine if we need LLM
    needs_llm = args.template or args.all or args.describe or args.describe_file or args.auto_discover or args.from_list
    if needs_llm and not args.provider:
        parser.error("--provider is required for generation. Use: --provider openai or --provider anthropic")

    llm_client = create_llm_client(args) if needs_llm else None
    manager = Manager(PROJECT_ROOT, llm_client=llm_client) if llm_client else None

    all_results = []

    if args.auto_discover:
        results = generate_from_discovery(
            args.auto_discover, args.max_scenarios, args.filter_category,
            templates_dir, scenarios_dir, manager,
            use_llm_filter=not args.no_llm_filter,
        )
        all_results.extend(results)

    elif args.describe:
        results = generate_from_description(
            args.describe, args, templates_dir, scenarios_dir, manager
        )
        all_results.extend(results)

    elif args.describe_file:
        results = generate_from_description_file(
            args.describe_file, args, templates_dir, scenarios_dir, manager
        )
        all_results.extend(results)

    elif args.template:
        results = generate_from_template(
            args.template, args.instance, templates_dir, scenarios_dir, manager,
            num_variants=args.variants,
        )
        all_results.extend(results)

    elif args.from_list:
        # Generate only templates listed in a file
        list_path = Path(args.from_list)
        if not list_path.exists():
            parser.error(f"List file not found: {args.from_list}")
        template_names = sorted(set(
            line.strip() for line in list_path.read_text().splitlines()
            if line.strip() and not line.startswith("#")
        ))
        logger.info(f"From list: {len(template_names)} templates to process from {args.from_list}")
        for tname in template_names:
            if not (templates_dir / tname).exists():
                logger.warning(f"  Template not found, skipping: {tname}")
                continue
            results = generate_from_template(
                tname, None, templates_dir, scenarios_dir, manager,
                num_variants=args.variants,
            )
            all_results.extend(results)

    elif args.all:
        # Parse --shard I/N
        shard = None
        if args.shard:
            try:
                parts = args.shard.split("/")
                shard = (int(parts[0]), int(parts[1]))
                if shard[0] < 0 or shard[0] >= shard[1] or shard[1] < 1:
                    parser.error(f"Invalid --shard: index must be 0 <= I < N, got {args.shard}")
            except (ValueError, IndexError):
                parser.error(f"Invalid --shard format: '{args.shard}'. Expected I/N (e.g. 0/3)")
        results = generate_all(
            templates_dir, scenarios_dir, manager,
            num_variants=args.variants, shard=shard,
            retry_failed=args.retry_failed,
        )
        all_results.extend(results)

    if all_results and args.report:
        manager.results = all_results
        manager.export_report(Path(args.report))

    if all_results and args.report_html:
        manager.results = all_results
        manager.export_html_report(Path(args.report_html))

    if args.verify:
        verify_all(scenarios_dir)

    if not any([args.list, args.template, args.all, args.verify, args.describe, args.describe_file, args.auto_discover, args.from_list]):
        parser.print_help()


if __name__ == "__main__":
    main()
