#!/usr/bin/env python3
"""Validate the result-free camera-ready release structure."""

from __future__ import annotations

import csv
import json
from pathlib import Path


ROOT = Path(__file__).resolve().parent.parent
SCENARIOS = ROOT / "dataset" / "scenarios"
REQUIRED = {
    "Dockerfile",
    "Dockerfile.fixed",
    "exploit.sh",
    "metadata.json",
    "run_config.json",
    "verify.sh",
}
REMOVED = {
    "T1548_001_suid_ssh",
    "T1548_001_suid_whois",
    "T1548_001_suid_ssh_v1",
}
FORBIDDEN_PARTS = {
    "output",
    "outputs",
    "result",
    "results",
    "rerun",
    "logs",
    "__pycache__",
    ".cache",
    ".pytest_cache",
    ".venv",
}
FORBIDDEN_SUFFIXES = {".db", ".jsonl", ".log", ".pyc", ".sqlite", ".sqlite3"}
FORBIDDEN_METADATA_KEYS = {
    "expert_authored",
    "hackingbuddy_legacy",
    "hint",
    "legacy_source",
    "source",
}
FORBIDDEN_TEMPLATE_KEYS = {"expert_authored", "source", "status"}


def read_manifest(path: Path, expected_fields: list[str]) -> dict[str, dict]:
    with path.open(newline="", encoding="utf-8") as handle:
        reader = csv.DictReader(handle)
        assert reader.fieldnames == expected_fields, (
            path.name,
            reader.fieldnames,
            expected_fields,
        )
        rows = list(reader)
    return {row["scenario_id"]: row for row in rows}


def scenario_dirs(partition: str) -> dict[str, Path]:
    base = SCENARIOS / partition
    return {path.name: path for path in base.iterdir() if path.is_dir()}


def validate_partition(
    partition: str,
    expected: int,
    manifest_name: str,
    manifest_fields: list[str],
) -> dict[str, dict]:
    directories = scenario_dirs(partition)
    manifest = read_manifest(ROOT / "manifests" / manifest_name, manifest_fields)
    assert len(directories) == expected, (partition, len(directories), expected)
    assert len(manifest) == expected, (manifest_name, len(manifest), expected)
    assert directories.keys() == manifest.keys(), f"{partition} differs from manifest"

    for scenario_id, directory in directories.items():
        names = {path.name for path in directory.iterdir() if path.is_file()}
        assert REQUIRED <= names, f"{scenario_id} missing {sorted(REQUIRED - names)}"
        assert "build.log" not in names, f"{scenario_id} contains build.log"
        metadata = json.loads((directory / "metadata.json").read_text())
        assert metadata.get("scenario_id") == scenario_id, scenario_id
        assert not FORBIDDEN_METADATA_KEYS & metadata.keys(), (
            scenario_id,
            sorted(FORBIDDEN_METADATA_KEYS & metadata.keys()),
        )
        assert metadata.get("ground_truth_exploit") == "exploit.sh", scenario_id
        row = manifest[scenario_id]
        for field in manifest_fields:
            expected_value = metadata.get(field, "")
            if expected_value is None:
                expected_value = ""
            assert row[field] == str(expected_value), (
                scenario_id,
                field,
                row[field],
                expected_value,
            )
    return manifest


def main() -> None:
    removed_field = "training_data_" + "exposure"
    originals = validate_partition(
        "core",
        531,
        "original_531.csv",
        ["scenario_id", "category", "attack_technique", "cwe", "difficulty"],
    )
    variants = validate_partition(
        "variants",
        329,
        "variants_329.csv",
        [
            "scenario_id",
            "variant_of",
            "category",
            "attack_technique",
            "cwe",
            "difficulty",
        ],
    )

    assert not REMOVED & (originals.keys() | variants.keys()), "removed scenario present"
    for scenario_id, row in variants.items():
        variant_of = row["variant_of"]
        assert variant_of in originals, f"{scenario_id} maps to absent original {variant_of}"

    for params_file in (ROOT / "dataset" / "templates").glob("*/params.json"):
        params = json.loads(params_file.read_text(encoding="utf-8"))
        assert not FORBIDDEN_TEMPLATE_KEYS & params.keys(), (
            params_file.relative_to(ROOT),
            sorted(FORBIDDEN_TEMPLATE_KEYS & params.keys()),
        )

    for path in ROOT.rglob("*"):
        relative = path.relative_to(ROOT)
        if ".git" in relative.parts:
            continue
        assert not FORBIDDEN_PARTS & set(relative.parts), f"forbidden path: {relative}"
        if path.is_file():
            assert path.suffix not in FORBIDDEN_SUFFIXES, f"forbidden file: {relative}"
            if path.suffix in {".json", ".py", ".md", ".csv", ".txt"}:
                text = path.read_text(encoding="utf-8", errors="ignore")
                assert removed_field not in text, (
                    f"removed field present: {relative}"
                )

    for required in (
        ROOT / "baselines" / "hackingBuddyGPT" / "LICENSE",
        ROOT / "baselines" / "HackSynth" / "LICENSE.md",
        ROOT / "THIRD_PARTY_NOTICES.md",
    ):
        assert required.is_file(), f"missing {required.relative_to(ROOT)}"

    print("Release validation passed")
    print(f"Original environments: {len(originals)}")
    print(f"Variant environments: {len(variants)}")
    print(f"Total environments: {len(originals) + len(variants)}")


if __name__ == "__main__":
    main()
