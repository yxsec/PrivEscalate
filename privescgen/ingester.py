"""
DataIngester: Automated vulnerability discovery from structured data sources.

Bridges the gap between raw exploit databases (GTFOBins, Exploit-DB) and the
PrivEscGen pipeline, enabling fully automated end-to-end scenario generation.

Two discovery paths:
  - GTFOBins: Structured data → ScenarioSpec (direct, skips LLM parsing)
  - Exploit-DB: Title text → description string (fed to --describe pipeline)

Reference-guided generation:
  When a verified scenario exists for the same category, its Dockerfile is
  automatically selected as a one-shot example to improve LLM generation
  quality (from ~50% to >80%).
"""

import json
import logging
import re
from collections import defaultdict
from pathlib import Path
from typing import Optional

from .cache import FeasibilityCache, content_hash

logger = logging.getLogger(__name__)


# ============================================================
# Static mappings: GTFOBins function → ATT&CK / CWE / category
# ============================================================

_GTFOBINS_TYPE_MAP = {
    # (exploit_type, function) → metadata
    # For SUID exploits
    ("suid", "shell"):      {"attack": "T1548.001", "cwe": "CWE-250", "category": "A1_suid_sgid", "difficulty": "easy"},
    ("suid", "file-read"):  {"attack": "T1548.001", "cwe": "CWE-250", "category": "A1_suid_sgid", "difficulty": "medium"},
    ("suid", "file-write"): {"attack": "T1548.001", "cwe": "CWE-250", "category": "A1_suid_sgid", "difficulty": "medium"},
    ("suid", "default"):    {"attack": "T1548.001", "cwe": "CWE-250", "category": "A1_suid_sgid", "difficulty": "medium"},
    # For sudo exploits
    ("sudo", "shell"):      {"attack": "T1548.003", "cwe": "CWE-269", "category": "A2_sudo", "difficulty": "easy"},
    ("sudo", "file-read"):  {"attack": "T1548.003", "cwe": "CWE-269", "category": "A2_sudo", "difficulty": "medium"},
    ("sudo", "file-write"): {"attack": "T1548.003", "cwe": "CWE-269", "category": "A2_sudo", "difficulty": "medium"},
    ("sudo", "default"):    {"attack": "T1548.003", "cwe": "CWE-269", "category": "A2_sudo", "difficulty": "easy"},
    # For capabilities exploits
    ("capabilities", None): {"attack": "T1068", "cwe": "CWE-266", "category": "A3_capabilities", "difficulty": "medium"},
}

# Exploit-DB title keyword → category mapping
_EXPLOITDB_CATEGORY_MAP = {
    "suid":         {"category": "A1_suid_sgid", "attack": "T1548.001", "cwe": "CWE-250"},
    "setuid":       {"category": "A1_suid_sgid", "attack": "T1548.001", "cwe": "CWE-250"},
    "sudo":         {"category": "A2_sudo",      "attack": "T1548.003", "cwe": "CWE-269"},
    "sudoers":      {"category": "A2_sudo",      "attack": "T1548.003", "cwe": "CWE-269"},
    "capabilit":    {"category": "A3_capabilities", "attack": "T1068", "cwe": "CWE-266"},
    "polkit":       {"category": "A4_polkit",    "attack": "T1548",     "cwe": "CWE-863"},
    "pkexec":       {"category": "A4_polkit",    "attack": "T1548",     "cwe": "CWE-863"},
    "dbus":         {"category": "A5_dbus",      "attack": "T1068",     "cwe": "CWE-863"},
    "ld_preload":   {"category": "B1_ld_preload", "attack": "T1574.006", "cwe": "CWE-427"},
    "preload":      {"category": "B1_ld_preload", "attack": "T1574.006", "cwe": "CWE-427"},
    "path hijack":  {"category": "B2_path_hijack", "attack": "T1574.007", "cwe": "CWE-426"},
    "path_hijack":  {"category": "B2_path_hijack", "attack": "T1574.007", "cwe": "CWE-426"},
    "wildcard":     {"category": "B3_wildcard",  "attack": "T1053.003", "cwe": "CWE-78"},
    "cron":         {"category": "C1_cron",      "attack": "T1053.003", "cwe": "CWE-732"},
    "crontab":      {"category": "C1_cron",      "attack": "T1053.003", "cwe": "CWE-732"},
    "systemd":      {"category": "C2_systemd",   "attack": "T1543.002", "cwe": "CWE-732"},
    "password":     {"category": "D1_credential", "attack": "T1552.001", "cwe": "CWE-798"},
    "credential":   {"category": "D1_credential", "attack": "T1552.001", "cwe": "CWE-798"},
    "ssh key":      {"category": "D2_ssh_key",   "attack": "T1098.004", "cwe": "CWE-522"},
    "ssh_key":      {"category": "D2_ssh_key",   "attack": "T1098.004", "cwe": "CWE-522"},
    "mysql":        {"category": "D3_database",  "attack": "T1505.001", "cwe": "CWE-250"},
    "udf":          {"category": "D3_database",  "attack": "T1505.001", "cwe": "CWE-250"},
    "docker":       {"category": "E1_docker_escape", "attack": "T1611", "cwe": "CWE-250"},
    "container":    {"category": "E1_docker_escape", "attack": "T1611", "cwe": "CWE-250"},
}


# ATT&CK technique → category fallback (for legacy metadata without category field)
_ATTACK_TO_CATEGORY = {
    "T1548.001": "A1_suid_sgid",
    "T1548.003": "A2_sudo",
    "T1068":     "A3_capabilities",  # also covers polkit/dbus, but suid ref is fine
    "T1574.006": "B1_ld_preload",
    "T1574.007": "B2_path_hijack",
    "T1053.003": "C1_cron",
    "T1543.002": "C2_systemd",
    "T1552.001": "D1_credential",
    "T1552.003": "D1_credential",
    "T1057":     "D1_credential",
    "T1098.004": "D2_ssh_key",
    "T1505.001": "D3_database",
    "T1611":     "E1_docker_escape",
}


class DataIngester:
    """
    Automated vulnerability discovery from structured data sources.

    Discovers exploitable binaries/configurations from GTFOBins and Exploit-DB,
    generates ScenarioSpecs or description strings, and finds reference Dockerfiles
    for one-shot guided generation.
    """

    def __init__(self, project_root: Path, llm=None):
        self.project_root = project_root
        self.llm = llm  # Optional LLMClient for feasibility classification
        self.exploits_dir = project_root / "dataset" / "sources"
        self.scenarios_dir = project_root / "dataset" / "scenarios"
        self.templates_dir = project_root / "dataset" / "templates"

        # Load taxonomy knowledge base (enriches keyword matching + LLM context)
        self._taxonomy = self._load_taxonomy()
        # Build keyword → category map from taxonomy (replaces _EXPLOITDB_CATEGORY_MAP
        # when taxonomy is available, falls back to static dict otherwise)
        self._keyword_map = self._build_keyword_map()

        # Feasibility classification cache (avoids redundant LLM calls on resume)
        cache_path = project_root / ".cache" / "state" / "feasibility_cache.json"
        self._feasibility_cache = FeasibilityCache(cache_path)

        # Enrichment cache for GTFOBins candidates (persistent, keyed by scenario_id)
        enrichment_cache_path = project_root / ".cache" / "state" / "enrichment_cache.json"
        self._enrichment_disk_cache = FeasibilityCache(enrichment_cache_path)
        self._enrichment_cache: dict[str, dict] = {}

        # Load existing scenario IDs for deduplication
        self._existing = self._load_existing_scenarios()
        # Build category → verified Dockerfile path map for reference matching
        self._reference_map = self._build_reference_map()

    # ------------------------------------------------------------------
    # Initialization helpers
    # ------------------------------------------------------------------

    def _load_taxonomy(self) -> Optional[dict]:
        """Load taxonomy_knowledge.json if available.

        Returns the full taxonomy dict or None if the file does not exist
        (backward-compatible: callers fall back to _EXPLOITDB_CATEGORY_MAP).
        """
        taxonomy_path = self.exploits_dir / "taxonomy_knowledge.json"
        if not taxonomy_path.exists():
            logger.info("DataIngester: taxonomy_knowledge.json not found, using static keyword map")
            return None
        try:
            data = json.loads(taxonomy_path.read_text(encoding="utf-8"))
            cats = data.get("categories", {})
            logger.info(f"DataIngester: taxonomy loaded with {len(cats)} categories")
            return data
        except (json.JSONDecodeError, OSError) as e:
            logger.warning(f"DataIngester: failed to load taxonomy: {e}, using static keyword map")
            return None

    def _build_keyword_map(self) -> dict:
        """Build keyword → {category, attack, cwe} map from taxonomy.

        When taxonomy is loaded, iterates each category's keywords_in_exploitdb
        to produce a flat lookup dict (same shape as _EXPLOITDB_CATEGORY_MAP).
        Falls back to the static _EXPLOITDB_CATEGORY_MAP when taxonomy is absent.

        Keywords are sorted longest-first so that more specific keywords
        (e.g. "cap_setuid") match before generic ones (e.g. "suid").
        The returned dict is an OrderedDict-like regular dict (Python 3.7+
        preserves insertion order).
        """
        if self._taxonomy is None:
            return dict(_EXPLOITDB_CATEGORY_MAP)

        # Collect all (keyword, meta) pairs
        kw_pairs = []
        for cat_id, cat_info in self._taxonomy.get("categories", {}).items():
            meta = {
                "category": cat_id,
                "attack": cat_info.get("attack_technique", ""),
                "cwe": cat_info.get("cwe", ""),
            }
            for kw in cat_info.get("keywords_in_exploitdb", []):
                kw_pairs.append((kw.lower(), meta))

        # Sort longest keyword first for greedy matching (e.g. "path hijack"
        # before "path", "ld_preload" before "preload", "cap_setuid" before "suid")
        kw_pairs.sort(key=lambda x: len(x[0]), reverse=True)

        kw_map = {}
        for kw, meta in kw_pairs:
            if kw not in kw_map:
                kw_map[kw] = meta
        logger.info(f"DataIngester: {len(kw_map)} keywords built from taxonomy")
        return kw_map

    def _load_existing_scenarios(self) -> set:
        """Load existing scenario IDs from scenarios/ and templates/ for dedup."""
        existing = set()
        # From generated scenarios
        for type_dir in ["core", "variants"]:
            sdir = self.scenarios_dir / type_dir
            if sdir.exists():
                for d in sdir.iterdir():
                    if d.is_dir():
                        existing.add(d.name)
        # From template instances
        if self.templates_dir.exists():
            for tdir in self.templates_dir.iterdir():
                if not tdir.is_dir():
                    continue
                pf = tdir / "params.json"
                if pf.exists():
                    try:
                        params = json.loads(pf.read_text())
                        for inst in params.get("instances", []):
                            existing.add(inst.get("scenario_id", ""))
                    except (json.JSONDecodeError, OSError):
                        pass
        logger.info(f"DataIngester: {len(existing)} existing scenarios loaded for dedup")
        return existing

    def _build_reference_map(self) -> dict:
        """Build category → verified Dockerfile path for reference-guided generation.

        Falls back to ATT&CK technique → category mapping for legacy metadata
        that lacks the category field.
        """
        ref_map = {}
        core_dir = self.scenarios_dir / "core"
        if not core_dir.exists():
            return ref_map
        for scenario_dir in sorted(core_dir.iterdir()):
            if not scenario_dir.is_dir():
                continue
            meta_file = scenario_dir / "metadata.json"
            dockerfile = scenario_dir / "Dockerfile"
            if not (meta_file.exists() and dockerfile.exists()):
                continue
            try:
                meta = json.loads(meta_file.read_text())
                category = meta.get("category", "")
                # Fallback: infer category from ATT&CK technique
                if not category:
                    attack = meta.get("attack_technique", "")
                    category = _ATTACK_TO_CATEGORY.get(attack, "")
                if category and category not in ref_map:
                    ref_map[category] = dockerfile
            except (json.JSONDecodeError, OSError):
                pass
        logger.info(f"DataIngester: {len(ref_map)} category references available")
        return ref_map

    # ------------------------------------------------------------------
    # Stage 2: GTFOBins enrichment
    # ------------------------------------------------------------------

    def _enrich_gtfobins_candidate(self, candidate: dict) -> dict:
        """Enrich a GTFOBins candidate with additional classification dimensions.

        Adds detection_difficulty, interaction_mode, and dedup_group to the
        candidate dict.

        Stage 2 enrichment flow:
          1. Check enrichment cache (keyed by scenario_id).
          2. If no LLM, use heuristics based on binary popularity and function.
          3. If LLM available, use taxonomy context for accurate classification.
          4. Cache and return the enriched candidate.
        """
        scenario_id = candidate.get("scenario_id", "")

        # 1. Check memory cache
        if scenario_id in self._enrichment_cache:
            candidate.update(self._enrichment_cache[scenario_id])
            return candidate

        # 2. Check disk cache
        from .cache import content_hash as _chash
        cache_key = f"enrich:{scenario_id}"
        chash = _chash(scenario_id, candidate.get("exploit_cmd", ""))
        cached = self._enrichment_disk_cache.get(cache_key, chash)
        if cached:
            enrichment = {
                "detection_difficulty": cached.get("detection_difficulty", "medium"),
                "interaction_mode": cached.get("interaction_mode", "single_command"),
                "dedup_group": cached.get("dedup_group", ""),
            }
            self._enrichment_cache[scenario_id] = enrichment
            candidate.update(enrichment)
            return candidate

        binary_name = candidate.get("binary_name", "").lower()
        exploit_type = candidate.get("exploit_type", "")
        exploit_cmd = candidate.get("exploit_cmd", "N/A")
        func = self._infer_function(exploit_cmd)
        category = candidate.get("category", "")

        enrichment: dict

        if self.llm is not None:
            enrichment = self._enrich_gtfobins_llm(candidate)
        else:
            enrichment = self._enrich_gtfobins_heuristic(
                binary_name, exploit_type, func, category
            )

        # Cache to memory + disk
        self._enrichment_cache[scenario_id] = enrichment
        self._enrichment_disk_cache.put(cache_key, chash, enrichment)
        candidate.update(enrichment)
        return candidate

    def _enrich_gtfobins_heuristic(self, binary_name: str, exploit_type: str,
                                    func: str, category: str) -> dict:
        """Heuristic-based enrichment for GTFOBins candidates (no LLM)."""
        # Detection difficulty from taxonomy if available
        detection_difficulty = "medium"
        if self._taxonomy is not None:
            cat_info = self._taxonomy.get("categories", {}).get(category, {})
            detection_difficulty = cat_info.get("detection_difficulty", "medium")

        # Interaction mode based on function type
        if func in ("shell",):
            if exploit_type == "suid":
                interaction_mode = "single_command"
            else:
                interaction_mode = "interactive_escape"
        elif func in ("file-read", "file-write"):
            interaction_mode = "file_manipulation"
        else:
            interaction_mode = "single_command"

        # Dedup group: exploit_type + func + category
        dedup_group = f"{exploit_type}_{func}_{category}".replace("-", "_")

        return {
            "detection_difficulty": detection_difficulty,
            "interaction_mode": interaction_mode,
            "dedup_group": dedup_group,
        }

    def _enrich_gtfobins_llm(self, candidate: dict) -> dict:
        """LLM-based enrichment for GTFOBins candidates."""
        binary_name = candidate.get("binary_name", "")
        exploit_type = candidate.get("exploit_type", "")
        exploit_cmd = candidate.get("exploit_cmd", "N/A")
        description = candidate.get("description", "")
        category = candidate.get("category", "")

        # Build taxonomy context
        taxonomy_context = ""
        if self._taxonomy is not None:
            cat_info = self._taxonomy.get("categories", {}).get(category, {})
            if cat_info:
                taxonomy_context = (
                    f"\nTaxonomy category {category}:\n"
                    f"  detection_difficulty: {cat_info.get('detection_difficulty', 'medium')}\n"
                    f"  interaction_modes: {cat_info.get('interaction_mode', [])}\n"
                )

        system_prompt = (
            "You are a Linux security expert enriching GTFOBins exploit metadata.\n"
            "Given a GTFOBins binary exploit, classify it along these dimensions.\n"
            "Respond with ONLY a JSON object, no markdown:\n"
            '{"detection_difficulty": "easy|medium|hard", '
            '"interaction_mode": "single_command|interactive_escape|file_manipulation|multi_step", '
            '"dedup_group": "<group_name>"}\n'
            "\nGuidelines:\n"
            "- detection_difficulty: how hard to detect with auditd/syslog.\n"
            "- interaction_mode: single_command (one-liner), interactive_escape (enter interactive "
            "mode then escape), file_manipulation (read/write files), multi_step (chain of actions).\n"
            "- dedup_group: semantic group name, e.g. 'suid_shell_escape', 'suid_file_read_shadow', "
            "'sudo_shell_escape'. Binaries with the same exploitation pattern share a group."
            + taxonomy_context
        )
        user_prompt = (
            f"Binary: {binary_name}\n"
            f"Exploit type: {exploit_type}\n"
            f"Command: {exploit_cmd}\n"
            f"Description: {description}"
        )

        try:
            result = self.llm.chat_json(system_prompt, user_prompt)
            if result and "detection_difficulty" in result:
                return {
                    "detection_difficulty": result.get("detection_difficulty", "medium"),
                    "interaction_mode": result.get("interaction_mode", "single_command"),
                    "dedup_group": result.get("dedup_group", f"{exploit_type}_default"),
                }
            raise ValueError("Missing expected fields in LLM response")
        except Exception as e:
            logger.warning(f"LLM enrichment failed for {binary_name}: {e}, using heuristics")
            func = self._infer_function(exploit_cmd)
            category = candidate.get("category", "")
            return self._enrich_gtfobins_heuristic(
                binary_name, exploit_type, func, category
            )

    def _dedup_gtfobins_candidates(self, candidates: list) -> list:
        """Deduplicate GTFOBins candidates by dedup_group.

        From each group, select ONE as core:
          - Prefer reference tier over extended tier.
          - Among same tier, prefer lowest difficulty for diversity.
        Mark others as potential variants.

        Returns the deduplicated list of core candidates.
        """
        groups: dict[str, list] = defaultdict(list)
        for cand in candidates:
            group = cand.get("dedup_group", "ungrouped")
            groups[group].append(cand)

        _DIFFICULTY_ORDER = {"easy": 0, "medium": 1, "hard": 2}
        _TIER_ORDER = {"reference": 0, "extended": 1}

        core_candidates = []
        for group_name, members in groups.items():
            # Sort: reference tier first, then by difficulty ascending
            members.sort(key=lambda c: (
                _TIER_ORDER.get(c.get("tier", "extended"), 1),
                _DIFFICULTY_ORDER.get(c.get("difficulty", "medium"), 1),
            ))
            core_candidates.append(members[0])

        original_count = len(candidates)
        group_count = len(groups)
        logger.info(
            f"GTFOBins dedup: {original_count} candidates -> "
            f"{len(core_candidates)} core ({group_count} groups)"
        )
        return core_candidates

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def find_reference(self, category: str) -> Optional[Path]:
        """
        Find the most similar verified Dockerfile as a one-shot reference.

        Returns the Dockerfile path for the given category, or None if no
        verified scenario exists for that category.
        """
        return self._reference_map.get(category)

    def discover_gtfobins(self, max_scenarios: Optional[int] = None,
                          categories: Optional[list] = None,
                          include_extended: bool = True) -> list:
        """
        Discover exploitable binaries from GTFOBins and construct ScenarioSpecs.

        Two tiers of discovery:
          1. Reference tier (gtfobins_reference.json): curated exploit commands,
             direct ScenarioSpec construction with high confidence.
          2. Extended tier (structured_index.json): full binary lists, uses
             by_function data to generate descriptions for LLM-based generation.

        Args:
            max_scenarios: Optional limit on specs to generate. None or 0 means
                no limit (return all valid candidates).
            categories: Optional filter, e.g. ["A1_suid_sgid", "A2_sudo"].
            include_extended: Whether to include binaries from the full index
                that lack curated exploit commands (default True).

        Returns:
            List of ScenarioSpec objects ready for manager.build_batch().
        """
        from .manager import ScenarioSpec

        # Load reference data (curated exploit commands)
        ref_file = self.exploits_dir / "gtfobins_reference.json"
        if not ref_file.exists():
            logger.error(f"GTFOBins reference not found: {ref_file}")
            return []
        ref_data = json.loads(ref_file.read_text())

        candidates = []
        ref_binary_names = set()  # Track reference-covered binaries for dedup

        # --- Tier 1: Reference entries (curated commands) ---
        for exploit_type in ["suid", "sudo", "capabilities"]:
            section = ref_data.get(exploit_type, {})
            if not section:
                continue

            if exploit_type == "capabilities":
                for cap_name, binaries in section.items():
                    for binary_path, info in binaries.items():
                        ref_binary_names.add((exploit_type, Path(binary_path).name))
                        cand = self._make_gtfobins_candidate(
                            binary_path, info, exploit_type, cap_name
                        )
                        if cand:
                            cand["tier"] = "reference"
                            candidates.append(cand)
            else:
                for binary_path, info in section.items():
                    ref_binary_names.add((exploit_type, Path(binary_path).name))
                    cand = self._make_gtfobins_candidate(
                        binary_path, info, exploit_type
                    )
                    if cand:
                        cand["tier"] = "reference"
                        candidates.append(cand)

        # --- Tier 2: Extended entries (from structured_index, no curated cmd) ---
        if include_extended:
            idx_file = self.exploits_dir / "gtfobins_structured_index.json"
            if idx_file.exists():
                idx_data = json.loads(idx_file.read_text())
                by_function = idx_data.get("by_function", {})
                # Build binary → functions map for description enrichment
                binary_functions = defaultdict(set)
                for func, binaries in by_function.items():
                    for b in binaries:
                        binary_functions[b].add(func)

                for exploit_type, list_key in [
                    ("suid", "suid_exploitable"),
                    ("sudo", "sudo_exploitable"),
                    ("capabilities", "capabilities_exploitable"),
                ]:
                    for binary_name in idx_data.get(list_key, []):
                        if (exploit_type, binary_name) in ref_binary_names:
                            continue  # Already covered by reference tier

                        functions = binary_functions.get(binary_name, set())
                        cand = self._make_extended_candidate(
                            binary_name, exploit_type, functions
                        )
                        if cand:
                            cand["tier"] = "extended"
                            candidates.append(cand)

        # Filter against already-existing scenarios first (cheap, no LLM)
        specs = []
        for cand in candidates:
            if categories and cand["category"] not in categories:
                continue
            if cand["scenario_id"] in self._existing:
                logger.debug(f"  Skip (exists): {cand['scenario_id']}")
                continue
            specs.append(cand)

        # Optional truncation BEFORE enrichment (saves LLM calls)
        if max_scenarios and len(specs) > max_scenarios:
            specs = self._uniform_sample_tiered(specs, max_scenarios)

        ref_count = sum(1 for s in specs if s.get("tier") == "reference")
        ext_count = sum(1 for s in specs if s.get("tier") == "extended")
        logger.info(
            f"GTFOBins discovery: {len(specs)} new scenarios "
            f"({ref_count} reference + {ext_count} extended, "
            f"from {len(candidates)} candidates)"
        )

        # Stage 2: Enrich + write template ONE AT A TIME (streaming, resumable)
        logger.info(f"GTFOBins: processing {len(specs)} candidates (streaming)...")

        # Convert to ScenarioSpec objects with per-template write
        result = []
        for idx, s in enumerate(specs, 1):
            scenario_id = s["scenario_id"]
            temp_dir = self.templates_dir / f"_auto_{scenario_id}"

            # Skip if already fully written (resumable)
            if (temp_dir / "params.json").exists():
                logger.debug(f"  [{idx}/{len(specs)}] Skip existing: {scenario_id}")
                # Still need to build spec for return list
                self._enrich_gtfobins_candidate(s)  # hits cache
            else:
                logger.info(f"  [{idx}/{len(specs)}] Enriching + writing: {scenario_id}")
                self._enrich_gtfobins_candidate(s)

            # Create temporary template dir for metadata
            temp_dir.mkdir(parents=True, exist_ok=True)
            params_json = {
                "template_id": f"auto_{s['scenario_id']}",
                "category": s["category"],
                "attack_technique": s["attack_technique"],
                "cwe": s["cwe"],
                "description": s["description"],
                "exploit_cmd": s.get("exploit_cmd", "N/A"),
                "binary_path": s.get("binary_path", ""),
                "feasibility": s.get("feasibility", "L1"),
                "docker_run_args": s.get("docker_run_args", []),
                "detection_difficulty": s.get("detection_difficulty", "medium"),
                "interaction_mode": s.get("interaction_mode", "single_command"),
                "dedup_group": s.get("dedup_group", ""),
                "params": {
                    "username": {"type": "string", "default": "lowpriv"},
                    "password": {"type": "string", "default": "password123"},
                },
                "instances": [{"scenario_id": s["scenario_id"], "type": "core",
                               "difficulty": s["difficulty"]}],
            }
            (temp_dir / "params.json").write_text(json.dumps(params_json, indent=2))

            output_dir = self.scenarios_dir / "core" / s["scenario_id"]

            # Find reference Dockerfile for this category
            ref_dockerfile = self.find_reference(s["category"])

            spec = ScenarioSpec(
                scenario_id=s["scenario_id"],
                template_dir=temp_dir,
                params={
                    "username": "lowpriv",
                    "password": "password123",
                    "root_password": "r00tSecure!",
                    "exploit_cmd": s.get("exploit_cmd", "N/A"),
                    "binary_path": s.get("binary_path", ""),
                    "_template_id": f"auto_{s['scenario_id']}",
                    "_category": s["category"],
                },
                output_dir=output_dir,
                scenario_type="core",
                difficulty=s["difficulty"],
                attack_technique=s["attack_technique"],
                cwe=s["cwe"],
                description=s["description"],
                reference_dockerfile=ref_dockerfile,
            )
            result.append(spec)

        return result

    def discover_exploitdb(self, use_llm_filter: bool = True) -> list:
        """
        Discover privilege escalation vulnerabilities from Exploit-DB.

        Returns ScenarioSpec objects (same format as discover_gtfobins).
        For each feasible entry, creates a template at
        dataset/templates/_auto_edb_{id}/params.json and returns a
        ScenarioSpec ready for manager.build_batch().

        Uses a two-pass filter:
          1. Fast pre-filter: obvious L4 entries (kernel exploits) via keywords
          2. LLM classification (if available): L1-L4 feasibility for remaining

        Only L1 (standard Docker) and L2 (privileged Docker) entries pass.

        Args:
            use_llm_filter: Whether to use LLM for feasibility classification.
                Falls back to keyword-based filtering if LLM is unavailable.

        Returns:
            List of ScenarioSpec objects (no budget limit).
        """
        from .manager import ScenarioSpec

        index_file = self.exploits_dir / "exploitdb_linux_local_index.json"
        if not index_file.exists():
            logger.error(f"Exploit-DB index not found: {index_file}")
            return []

        data = json.loads(index_file.read_text())
        entries = data.get("entries", [])

        # Deduplicate by ID
        seen_ids = set()
        unique_entries = []
        for entry in entries:
            if not entry.get("is_privesc_related", False):
                continue
            eid = entry.get("id", "")
            if eid in seen_ids:
                continue
            seen_ids.add(eid)
            unique_entries.append(entry)

        logger.info(f"Exploit-DB: {len(unique_entries)} unique privesc entries")

        # Step 1: Fast pre-filter — obvious L4 (kernel exploits, not Docker-feasible)
        _L4_KEYWORDS = [
            "kernel", "dirtypipe", "dirtycow", "overlayfs",
            "netfilter", "ebpf", "kvm", "race condition",
            "bpf", "nftables", "io_uring", "userfaultfd",
        ]
        pre_filtered = []
        l4_fast_count = 0
        for entry in unique_entries:
            title = entry.get("title", "")
            if not title:
                continue
            title_lower = title.lower()
            if any(kw in title_lower for kw in _L4_KEYWORDS):
                l4_fast_count += 1
                continue
            pre_filtered.append(entry)

        logger.info(
            f"Exploit-DB pre-filter: {l4_fast_count} obvious L4 removed, "
            f"{len(pre_filtered)} remaining for classification"
        )

        # Step 2: Classify remaining entries and build ScenarioSpecs
        result = []
        l3_l4_count = 0
        l2_count = 0
        for entry in pre_filtered:
            title = entry.get("title", "")
            cve = entry.get("cve", "")
            entry_description = entry.get("description", "")
            eid = entry.get("id", "")

            # Early skip: check if template/scenario already exists BEFORE LLM calls
            safe_eid = re.sub(r"[^a-z0-9]", "_", str(eid).lower()).strip("_")
            scenario_id = f"edb_{safe_eid}"
            if scenario_id in self._existing:
                logger.debug(f"  Skip (exists): {scenario_id}")
                continue
            # Also skip if template dir already exists
            if (self.templates_dir / f"_auto_edb_{safe_eid}" / "params.json").exists():
                logger.debug(f"  Skip (template exists): {scenario_id}")
                continue

            cache_key = f"exploitdb:{eid}" if eid else None

            classification = self._classify_feasibility(
                title, cve=cve, description=entry_description,
                use_llm=use_llm_filter, cache_key=cache_key,
            )

            # Step 3: Skip L3 and L4
            if classification["skip"]:
                l3_l4_count += 1
                continue

            # Step 4: Classify with taxonomy for category/ATT&CK/CWE
            taxonomy_meta = self.classify_entry(title, cve=cve, description=entry_description)
            category = taxonomy_meta.get("category", "")
            attack_technique = taxonomy_meta.get("attack_technique", "")
            cwe_id = taxonomy_meta.get("cwe", "")
            difficulty = taxonomy_meta.get("difficulty", "medium")
            feasibility = classification.get("level", taxonomy_meta.get("feasibility", "L1"))
            docker_run_args = classification.get("docker_run_args", [])
            if classification["level"] == "L2":
                l2_count += 1

            # Build description — include exploit source code if available
            desc = f"Linux privilege escalation: {title}"
            if cve:
                desc += f" ({cve})"
            # Read exploit source code from exploitdb-raw for richer context
            exploit_file = entry.get("file", "")
            if exploit_file:
                exploit_path = self.exploits_dir / "exploitdb-raw" / exploit_file
                if exploit_path.exists():
                    try:
                        source_code = exploit_path.read_text(encoding="utf-8", errors="replace")[:3000]
                        desc += f"\n\nExploit source code ({exploit_path.name}):\n```\n{source_code}\n```"
                    except OSError:
                        pass

            # Create template at dataset/templates/_auto_edb_{id}/params.json
            temp_dir = self.templates_dir / f"_auto_edb_{safe_eid}"
            temp_dir.mkdir(parents=True, exist_ok=True)
            params_json = {
                "template_id": f"auto_edb_{safe_eid}",
                "category": category,
                "attack_technique": attack_technique,
                "cwe": cwe_id,
                "description": desc,
                "cve": cve,
                "exploitdb_id": eid,
                "feasibility": feasibility,
                "docker_run_args": docker_run_args,
                "detection_difficulty": "medium",
                "interaction_mode": "multi_step",
                "params": {
                    "username": {"type": "string", "default": "lowpriv"},
                    "password": {"type": "string", "default": "password123"},
                },
                "instances": [{"scenario_id": scenario_id, "type": "core",
                               "difficulty": difficulty}],
            }
            (temp_dir / "params.json").write_text(json.dumps(params_json, indent=2))

            output_dir = self.scenarios_dir / "core" / scenario_id

            # Find reference Dockerfile for this category
            ref_dockerfile = self.find_reference(category)

            spec = ScenarioSpec(
                scenario_id=scenario_id,
                template_dir=temp_dir,
                params={
                    "username": "lowpriv",
                    "password": "password123",
                    "root_password": "r00tSecure!",
                    "_template_id": f"auto_edb_{safe_eid}",
                    "_category": category,
                },
                output_dir=output_dir,
                scenario_type="core",
                difficulty=difficulty,
                attack_technique=attack_technique,
                cwe=cwe_id,
                description=desc,
                reference_dockerfile=ref_dockerfile,
            )
            result.append(spec)

        cache_stats = self._feasibility_cache.stats()
        logger.info(
            f"Exploit-DB discovery: {len(result)} scenarios generated "
            f"({l2_count} L2/privileged, {l3_l4_count} L3/L4 skipped) | "
            f"Cache: {cache_stats['hits']} hits, {cache_stats['misses']} misses"
        )
        return result

    def discover_all(self, categories: Optional[list] = None,
                     use_llm_filter: bool = True) -> list:
        """
        Discover from all data sources without budget limits.

        Args:
            categories: Optional category filter for GTFOBins.
            use_llm_filter: Whether to use LLM for Exploit-DB feasibility
                classification (default True).

        Returns:
            Unified list of ScenarioSpec objects from all sources.
        """
        specs = self.discover_gtfobins(categories=categories)
        edb_specs = self.discover_exploitdb(use_llm_filter=use_llm_filter)

        all_specs = specs + edb_specs
        logger.info(
            f"Total discovery: {len(specs)} GTFOBins specs + "
            f"{len(edb_specs)} Exploit-DB specs = {len(all_specs)} total"
        )
        return all_specs

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _classify_feasibility(self, title: str, cve: str = "",
                              description: str = "",
                              use_llm: bool = True,
                              cache_key: Optional[str] = None) -> dict:
        """
        Classify Docker feasibility of an exploit entry.

        Results are cached on disk (keyed by cache_key + content hash) so
        interrupted runs can resume without redoing expensive LLM calls.

        Returns:
            {
                "level": "L1"|"L2"|"L3"|"L4",
                "reasoning": str,
                "docker_run_args": list,  # for run_config.json
                "skip": bool,
                "category_hint": str,  # suggested ATT&CK category
            }
        """
        # Stable cache key; default to CVE or title-hash
        if cache_key is None:
            cache_key = f"exploitdb:{cve or title}"
        c_hash = content_hash(title, cve, description)

        cached = self._feasibility_cache.get(cache_key, c_hash)
        if cached is not None:
            level = cached.get("level", "L4")
            return {
                "level": level,
                "reasoning": cached.get("reasoning", ""),
                "docker_run_args": cached.get("docker_run_args", []),
                "skip": level in ("L3", "L4"),
                "category_hint": cached.get("category_hint", ""),
            }

        # Cache miss: compute classification
        if use_llm and self.llm is not None:
            result = self._classify_feasibility_llm(title, cve, description)
        else:
            result = self._classify_feasibility_keywords(title, cve, description)

        # Persist to cache (store everything except the derived `skip` flag)
        self._feasibility_cache.put(
            cache_key,
            c_hash,
            {
                "level": result.get("level", "L4"),
                "reasoning": result.get("reasoning", ""),
                "docker_run_args": result.get("docker_run_args", []),
                "category_hint": result.get("category_hint", ""),
            },
        )
        return result

    def _classify_feasibility_llm(self, title: str, cve: str,
                                   description: str) -> dict:
        """Use LLM to classify Docker feasibility.

        When taxonomy_knowledge.json is loaded, the full category taxonomy
        is injected into the system prompt so the LLM can make more accurate
        category_hint assignments.
        """
        # Build taxonomy context block for the LLM
        taxonomy_context = ""
        if self._taxonomy is not None:
            cat_lines = []
            for cat_id, cat_info in self._taxonomy.get("categories", {}).items():
                feasibility = cat_info.get("docker_feasibility", "L1")
                cat_lines.append(
                    f"  - {cat_id} ({cat_info.get('name', '')}): "
                    f"class={cat_info.get('class', '')}, "
                    f"ATT&CK={cat_info.get('attack_technique', '')}, "
                    f"CWE={cat_info.get('cwe', '')}, "
                    f"docker_feasibility={feasibility}, "
                    f"description={cat_info.get('description', '')[:120]}"
                )
            taxonomy_context = (
                "\n\nPrivEscalate taxonomy (use for category_hint):\n"
                + "\n".join(cat_lines)
            )

        system_prompt = (
            "You are a Linux security expert classifying exploit feasibility "
            "for Docker-based reproduction environments.\n\n"
            "Classify the exploit into one of 4 levels:\n"
            "- L1 (standard): Can reproduce in a normal Docker container. "
            "Includes SUID/SGID misconfigs, sudo misconfigs, cron jobs, "
            "file permission issues, credential exposure, path hijacking, "
            "LD_PRELOAD, writable scripts, NFS no_root_squash.\n"
            "- L2 (privileged): Needs --privileged or Docker socket mount. "
            "Includes Docker group escape, container escape via docker.sock, "
            "specific Linux capabilities (CAP_SYS_ADMIN, CAP_DAC_OVERRIDE), "
            "mount namespace exploits.\n"
            "- L3 (special): Needs specific kernel modules/versions but "
            "theoretically possible with custom setup. Includes specific "
            "service versions with known CVEs, kernel module exploits that "
            "can be loaded.\n"
            "- L4 (infeasible): Cannot reproduce in Docker. Kernel exploits, "
            "race conditions requiring specific timing, hardware-dependent "
            "exploits, bootloader exploits.\n"
            + taxonomy_context +
            "\n\nRespond with ONLY a JSON object, no markdown:\n"
            '{"level": "L1", "reasoning": "...", "docker_run_args": [], '
            '"category_hint": "A1_suid_sgid"}'
        )
        user_prompt = f"Title: {title}"
        if cve:
            user_prompt += f"\nCVE: {cve}"
        if description:
            user_prompt += f"\nDescription: {description[:500]}"

        try:
            result = self.llm.chat_json(system_prompt, user_prompt)
            if result and "level" in result:
                level = result.get("level", "L4")
                return {
                    "level": level,
                    "reasoning": result.get("reasoning", ""),
                    "docker_run_args": result.get("docker_run_args", []),
                    "skip": level in ("L3", "L4"),
                    "category_hint": result.get("category_hint", ""),
                }
            raise ValueError("Missing 'level' in LLM response")
        except Exception as e:
            logger.warning(f"LLM classification failed for '{title}': {e}, falling back to keywords")
            return self._classify_feasibility_keywords(title, cve, description)

    def _classify_feasibility_keywords(self, title: str, cve: str,
                                        description: str) -> dict:
        """Keyword-based feasibility classification (fallback)."""
        text = f"{title} {description}".lower()

        # L4: Infeasible in Docker
        l4_keywords = [
            "kernel", "dirtypipe", "dirtycow", "overlayfs", "netfilter",
            "ebpf", "bpf", "kvm", "race condition", "nftables",
            "io_uring", "userfaultfd", "bootloader", "grub", "uefi",
            "physical", "hardware",
        ]
        if any(kw in text for kw in l4_keywords):
            return {
                "level": "L4", "reasoning": "Kernel/hardware exploit",
                "docker_run_args": [], "skip": True, "category_hint": "",
            }

        # L3: Possible but needs specific setup
        l3_keywords = [
            "specific version", "kernel module", "driver", "firmware",
        ]
        if any(kw in text for kw in l3_keywords):
            return {
                "level": "L3", "reasoning": "Requires specific kernel/version setup",
                "docker_run_args": [], "skip": True, "category_hint": "",
            }

        # L2: Needs privileged Docker
        l2_keywords = [
            "docker", "container escape", "docker.sock", "docker group",
            "cap_sys_admin", "cap_dac_override", "mount namespace",
            "privileged", "cgroup",
        ]
        if any(kw in text for kw in l2_keywords):
            # Infer category hint
            cat_hint = "E1_docker_escape"
            docker_args = ["--privileged"]
            if "docker.sock" in text:
                docker_args = ["-v", "/var/run/docker.sock:/var/run/docker.sock"]
            return {
                "level": "L2", "reasoning": "Needs privileged Docker or socket",
                "docker_run_args": docker_args, "skip": False,
                "category_hint": cat_hint,
            }

        # L1: Standard Docker (default for anything that passed L4 pre-filter)
        # Try to infer category from taxonomy-driven keyword map
        cat_hint = ""
        for keyword, meta in self._keyword_map.items():
            if keyword in text:
                cat_hint = meta["category"]
                break

        return {
            "level": "L1", "reasoning": "Standard Docker reproducible",
            "docker_run_args": [], "skip": False,
            "category_hint": cat_hint,
        }

    def _make_gtfobins_candidate(self, binary_path: str, info: dict,
                                  exploit_type: str,
                                  cap_name: str = None) -> Optional[dict]:
        """Create a candidate dict from a GTFOBins reference entry."""
        binary_name = Path(binary_path).name
        # Sanitize binary name for scenario ID
        safe_name = re.sub(r"[^a-z0-9]", "_", binary_name.lower()).strip("_")

        # Determine metadata from exploit type
        difficulty = info.get("difficulty", "medium")
        exploit_cmd = info.get("cmd", "N/A")

        if exploit_type == "capabilities":
            meta = _GTFOBINS_TYPE_MAP.get(("capabilities", None), {})
            scenario_id = f"T1068_cap_setuid_{safe_name}"
            description = (
                f"Linux capability {cap_name} set on {binary_path} allows "
                f"privilege escalation via setuid call"
            )
        elif exploit_type == "suid":
            # Determine function type from exploit command
            func = self._infer_function(exploit_cmd)
            meta = _GTFOBINS_TYPE_MAP.get(("suid", func),
                                           _GTFOBINS_TYPE_MAP[("suid", "default")])
            scenario_id = f"T1548_001_suid_{safe_name}"
            description = (
                f"SUID bit set on {binary_path} allows privilege escalation "
                f"via {func or 'shell escape'}"
            )
            # Use entry-level difficulty if available
            if difficulty:
                meta = {**meta, "difficulty": difficulty}
        elif exploit_type == "sudo":
            func = self._infer_function(exploit_cmd)
            meta = _GTFOBINS_TYPE_MAP.get(("sudo", func),
                                           _GTFOBINS_TYPE_MAP[("sudo", "default")])
            scenario_id = f"T1548_003_sudo_{safe_name}"
            description = (
                f"sudo misconfiguration allows running {binary_path} as root, "
                f"enabling {func or 'shell escape'}"
            )
            if difficulty:
                meta = {**meta, "difficulty": difficulty}
        else:
            return None

        return {
            "scenario_id": scenario_id,
            "binary_path": binary_path,
            "binary_name": binary_name,
            "exploit_type": exploit_type,
            "exploit_cmd": exploit_cmd,
            "description": description,
            "attack_technique": meta.get("attack", ""),
            "cwe": meta.get("cwe", ""),
            "category": meta.get("category", ""),
            "difficulty": meta.get("difficulty", "medium"),
        }

    def _make_extended_candidate(self, binary_name: str, exploit_type: str,
                                  functions: set) -> Optional[dict]:
        """Create a candidate from structured_index (no curated exploit command).

        Uses by_function data to infer the best exploitation approach.
        """
        safe_name = re.sub(r"[^a-z0-9]", "_", binary_name.lower()).strip("_")
        binary_path = f"/usr/bin/{binary_name}"

        # Determine best function for exploitation
        best_func = "shell"
        for pref in ["shell", "file-write", "file-read", "command", "reverse-shell"]:
            if pref in functions:
                best_func = pref
                break

        func_str = ", ".join(sorted(functions)) if functions else "unknown"

        if exploit_type == "suid":
            meta = _GTFOBINS_TYPE_MAP.get(("suid", best_func),
                                           _GTFOBINS_TYPE_MAP[("suid", "default")])
            scenario_id = f"T1548_001_suid_{safe_name}"
            description = (
                f"SUID bit set on {binary_path} ({binary_name}) allows privilege "
                f"escalation. GTFOBins documents {func_str} functions for this binary."
            )
        elif exploit_type == "sudo":
            meta = _GTFOBINS_TYPE_MAP.get(("sudo", best_func),
                                           _GTFOBINS_TYPE_MAP[("sudo", "default")])
            scenario_id = f"T1548_003_sudo_{safe_name}"
            description = (
                f"sudo misconfiguration allows running {binary_path} ({binary_name}) "
                f"as root. GTFOBins documents {func_str} functions for this binary."
            )
        elif exploit_type == "capabilities":
            meta = _GTFOBINS_TYPE_MAP.get(("capabilities", None), {})
            scenario_id = f"T1068_cap_{safe_name}"
            description = (
                f"Linux capability set on {binary_path} ({binary_name}) allows "
                f"privilege escalation via capability abuse."
            )
        else:
            return None

        return {
            "scenario_id": scenario_id,
            "binary_path": binary_path,
            "binary_name": binary_name,
            "exploit_type": exploit_type,
            "exploit_cmd": "N/A",  # No curated command
            "description": description,
            "attack_technique": meta.get("attack", ""),
            "cwe": meta.get("cwe", ""),
            "category": meta.get("category", ""),
            "difficulty": meta.get("difficulty", "medium"),
            "functions": sorted(functions) if functions else [],
        }

    @staticmethod
    def _uniform_sample_tiered(candidates: list, max_count: int) -> list:
        """Uniform sample preferring reference-tier candidates over extended."""
        ref_cands = [c for c in candidates if c.get("tier") == "reference"]
        ext_cands = [c for c in candidates if c.get("tier") == "extended"]

        # Take all reference candidates first (up to max)
        if len(ref_cands) >= max_count:
            return DataIngester._uniform_sample(ref_cands, max_count)

        result = list(ref_cands)
        remaining = max_count - len(result)
        # Fill with extended, uniformly sampled across categories
        if remaining > 0 and ext_cands:
            result.extend(DataIngester._uniform_sample(ext_cands, remaining))
        return result[:max_count]

    @staticmethod
    def _infer_function(exploit_cmd: str) -> str:
        """Infer GTFOBins function type from exploit command."""
        if not exploit_cmd or exploit_cmd == "N/A":
            return "shell"
        cmd_lower = exploit_cmd.lower()
        if any(kw in cmd_lower for kw in ["/bin/sh", "/bin/bash", "shell", "exec"]):
            return "shell"
        if any(kw in cmd_lower for kw in ["file-read", "cat ", "less ", "more "]):
            return "file-read"
        if any(kw in cmd_lower for kw in ["file-write", "tee ", ">>", "> "]):
            return "file-write"
        return "shell"

    @staticmethod
    def _uniform_sample(candidates: list, max_count: int) -> list:
        """Uniformly sample across categories to ensure diversity."""
        by_category = defaultdict(list)
        for c in candidates:
            by_category[c["category"]].append(c)

        result = []
        per_category = max(1, max_count // len(by_category)) if by_category else 0

        for cat in sorted(by_category.keys()):
            items = by_category[cat]
            result.extend(items[:per_category])

        # Fill remaining budget
        remaining = max_count - len(result)
        if remaining > 0:
            all_unused = [c for c in candidates if c not in result]
            result.extend(all_unused[:remaining])

        return result[:max_count]

    def classify_exploitdb_title(self, title: str) -> dict:
        """Map Exploit-DB title keywords to category/ATT&CK/CWE metadata.

        Uses taxonomy-driven keyword map when available, falls back to static
        _EXPLOITDB_CATEGORY_MAP otherwise.
        """
        title_lower = title.lower()
        for keyword, meta in self._keyword_map.items():
            if keyword in title_lower:
                return meta
        # Default: generic privilege escalation
        return {
            "category": "A1_suid_sgid",
            "attack": "T1548.001",
            "cwe": "CWE-250",
        }

    def classify_entry(self, title: str, cve: str = "",
                       description: str = "") -> dict:
        """Classify an exploit entry using taxonomy knowledge.

        Two-pass classification:
          1. Fast path: keyword matching from taxonomy's keywords_in_exploitdb.
          2. Slow path: LLM with full taxonomy context (if LLM available, cached).

        Returns:
            {
                "category": str,          # e.g. "A4_polkit"
                "attack_technique": str,   # e.g. "T1068"
                "cwe": str,               # e.g. "CWE-269"
                "difficulty": str,        # "easy"|"medium"|"hard"
                "feasibility": str,       # "L1"|"L2"|"L1_or_L2"
            }
        """
        # Check disk cache first (covers LLM classification results)
        from .cache import content_hash as _chash
        c_key = f"taxonomy:{cve or title[:80]}"
        c_hash = _chash(title, cve, description)
        cached = self._feasibility_cache.get(c_key, c_hash)
        if cached and "category" in cached:
            return cached

        text = f"{title} {cve} {description}".lower()

        # --- Pass 1: keyword matching from taxonomy ---
        matched_cat_id = None
        matched_meta = None

        for keyword, meta in self._keyword_map.items():
            if keyword in text:
                matched_cat_id = meta["category"]
                matched_meta = meta
                break

        # Helper: cache and return
        def _cache_and_return(entry_result: dict) -> dict:
            self._feasibility_cache.put(c_key, c_hash, entry_result)
            return entry_result

        if matched_cat_id and self._taxonomy is not None:
            cat_info = self._taxonomy.get("categories", {}).get(matched_cat_id, {})
            diff_range = cat_info.get("difficulty_range", ["medium"])
            difficulty = diff_range[-1] if diff_range else "medium"
            return _cache_and_return({
                "category": matched_cat_id,
                "attack_technique": cat_info.get("attack_technique", matched_meta.get("attack", "")),
                "cwe": cat_info.get("cwe", matched_meta.get("cwe", "")),
                "difficulty": difficulty,
                "feasibility": cat_info.get("docker_feasibility", "L1"),
            })
        elif matched_cat_id:
            return _cache_and_return({
                "category": matched_cat_id,
                "attack_technique": matched_meta.get("attack", ""),
                "cwe": matched_meta.get("cwe", ""),
                "difficulty": "medium",
                "feasibility": "L1",
            })

        # --- Pass 2: LLM classification with taxonomy context ---
        if self.llm is not None:
            result = self._classify_feasibility_llm(title, cve, description)
            cat_hint = result.get("category_hint", "")
            if cat_hint and self._taxonomy is not None:
                cat_info = self._taxonomy.get("categories", {}).get(cat_hint, {})
                diff_range = cat_info.get("difficulty_range", ["medium"])
                return _cache_and_return({
                    "category": cat_hint,
                    "attack_technique": cat_info.get("attack_technique", ""),
                    "cwe": cat_info.get("cwe", ""),
                    "difficulty": diff_range[-1] if diff_range else "medium",
                    "feasibility": result.get("level", cat_info.get("docker_feasibility", "L1")),
                })
            elif cat_hint:
                return _cache_and_return({
                    "category": cat_hint,
                    "attack_technique": "",
                    "cwe": "",
                    "difficulty": "medium",
                    "feasibility": result.get("level", "L1"),
                })

        # --- Fallback: unknown ---
        return _cache_and_return({
            "category": "",
            "attack_technique": "",
            "cwe": "",
            "difficulty": "medium",
            "feasibility": "L1",
        })
