#!/usr/bin/env python3
"""Build GTFOBins index files from raw YAML sources.

Reads raw GTFOBins YAML files from dataset/sources/gtfobins-raw/_gtfobins/
and generates:
  - dataset/sources/gtfobins_structured_index.json
  - dataset/sources/gtfobins_reference.json
"""

import argparse
import json
import logging
import os
import sys

import yaml

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    datefmt="%H:%M:%S",
)
logger = logging.getLogger(__name__)

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
GTFOBINS_RAW_DIR = os.path.join(BASE_DIR, "dataset", "sources", "gtfobins-raw", "_gtfobins")
STRUCTURED_INDEX_PATH = os.path.join(BASE_DIR, "dataset", "sources", "gtfobins_structured_index.json")
REFERENCE_PATH = os.path.join(BASE_DIR, "dataset", "sources", "gtfobins_reference.json")


def parse_gtfobins_file(filepath):
    """Parse a single GTFOBins YAML file and return its data.

    Returns None if the file is malformed or empty.
    """
    try:
        with open(filepath, "r", encoding="utf-8") as f:
            content = f.read()
        # YAML front matter is between --- markers
        data = yaml.safe_load(content)
        if data is None or not isinstance(data, dict):
            return None
        return data
    except yaml.YAMLError as e:
        logger.warning("Malformed YAML in %s: %s", filepath, e)
        return None
    except Exception as e:
        logger.warning("Error reading %s: %s", filepath, e)
        return None


def has_context(function_entries, context_name):
    """Check if any function entry has the given context (suid/sudo/capabilities)."""
    if not isinstance(function_entries, list):
        return False
    for entry in function_entries:
        if not isinstance(entry, dict):
            continue
        contexts = entry.get("contexts")
        if not isinstance(contexts, dict):
            continue
        if context_name in contexts:
            return True
    return False


def extract_shell_command(function_entries, context_name, binary_name):
    """Extract exploit command from function entries for a given context.

    Returns the command string or None.
    """
    if not isinstance(function_entries, list):
        return None
    for entry in function_entries:
        if not isinstance(entry, dict):
            continue
        contexts = entry.get("contexts")
        if not isinstance(contexts, dict):
            continue
        if context_name not in contexts:
            continue
        ctx_val = contexts[context_name]
        # Context can be None (meaning use default code), a dict with code, or other
        if isinstance(ctx_val, dict) and "code" in ctx_val:
            return ctx_val["code"]
        # Use the top-level code
        code = entry.get("code")
        if code:
            return code
    return None


def build_structured_index():
    """Build the gtfobins_structured_index.json data."""
    if not os.path.isdir(GTFOBINS_RAW_DIR):
        logger.error("GTFOBins raw directory not found: %s", GTFOBINS_RAW_DIR)
        sys.exit(1)

    filenames = sorted(os.listdir(GTFOBINS_RAW_DIR))
    # Filter out hidden files, directories, __pycache__, etc.
    filenames = [
        fn for fn in filenames
        if not fn.startswith(".") and not fn.startswith("_")
        and os.path.isfile(os.path.join(GTFOBINS_RAW_DIR, fn))
    ]

    function_counts = {}
    suid_exploitable = []
    sudo_exploitable = []
    capabilities_exploitable = []
    by_function = {}

    for fn in filenames:
        filepath = os.path.join(GTFOBINS_RAW_DIR, fn)
        data = parse_gtfobins_file(filepath)
        if data is None:
            logger.warning("Skipping %s: no valid data", fn)
            continue

        binary_name = fn
        functions = data.get("functions")
        if not isinstance(functions, dict):
            continue

        is_suid = False
        is_sudo = False
        is_capabilities = False

        for func_name, func_entries in functions.items():
            # Count functions
            if func_name not in function_counts:
                function_counts[func_name] = 0
            function_counts[func_name] += 1

            # Track by_function
            if func_name not in by_function:
                by_function[func_name] = []
            by_function[func_name].append(binary_name)

            # Check contexts
            if has_context(func_entries, "suid"):
                is_suid = True
            if has_context(func_entries, "sudo"):
                is_sudo = True
            if has_context(func_entries, "capabilities"):
                is_capabilities = True

        if is_suid:
            suid_exploitable.append(binary_name)
        if is_sudo:
            sudo_exploitable.append(binary_name)
        if is_capabilities:
            capabilities_exploitable.append(binary_name)

    # Sort all lists
    suid_exploitable.sort()
    sudo_exploitable.sort()
    capabilities_exploitable.sort()
    for func_name in by_function:
        by_function[func_name].sort()

    # Order function_counts by count descending (matching existing file)
    function_counts_ordered = dict(
        sorted(function_counts.items(), key=lambda x: -x[1])
    )

    # Order by_function to match function_counts order (descending by count)
    by_function_ordered = {}
    for func_name in function_counts_ordered:
        if func_name in by_function:
            by_function_ordered[func_name] = by_function[func_name]
    for func_name in sorted(by_function.keys()):
        if func_name not in by_function_ordered:
            by_function_ordered[func_name] = by_function[func_name]

    total_binaries = len(filenames)

    result = {
        "_description": "GTFOBins structured index for PrivEscalate",
        "_source": "https://gtfobins.github.io/",
        "_total_binaries": total_binaries,
        "function_counts": function_counts_ordered,
        "suid_exploitable": suid_exploitable,
        "suid_count": len(suid_exploitable),
        "sudo_exploitable": sudo_exploitable,
        "sudo_count": len(sudo_exploitable),
        "capabilities_exploitable": capabilities_exploitable,
        "capabilities_count": len(capabilities_exploitable),
        "by_function": by_function_ordered,
    }

    return result


def build_reference():
    """Build the gtfobins_reference.json data."""
    if not os.path.isdir(GTFOBINS_RAW_DIR):
        logger.error("GTFOBins raw directory not found: %s", GTFOBINS_RAW_DIR)
        sys.exit(1)

    filenames = sorted(os.listdir(GTFOBINS_RAW_DIR))
    filenames = [
        fn for fn in filenames
        if not fn.startswith(".") and not fn.startswith("_")
        and os.path.isfile(os.path.join(GTFOBINS_RAW_DIR, fn))
    ]

    suid_entries = {}
    sudo_entries = {}
    capabilities_entries = {}

    for fn in filenames:
        filepath = os.path.join(GTFOBINS_RAW_DIR, fn)
        data = parse_gtfobins_file(filepath)
        if data is None:
            continue

        binary_name = fn
        functions = data.get("functions")
        if not isinstance(functions, dict):
            continue

        # Determine path - use /usr/bin/<name> as default
        bin_path = f"/usr/bin/{binary_name}"

        # Check for shell or command function for SUID context
        for func_name in ("shell", "command"):
            func_entries = functions.get(func_name)
            if func_entries is None:
                continue
            cmd = extract_shell_command(func_entries, "suid", binary_name)
            if cmd is not None and bin_path not in suid_entries:
                difficulty = "easy" if func_name == "shell" else "medium"
                suid_entries[bin_path] = {"cmd": cmd, "difficulty": difficulty}

        # For file-read/file-write in SUID, add with medium difficulty
        for func_name in ("file-read", "file-write"):
            func_entries = functions.get(func_name)
            if func_entries is None:
                continue
            cmd = extract_shell_command(func_entries, "suid", binary_name)
            if cmd is not None and bin_path not in suid_entries:
                suid_entries[bin_path] = {"cmd": cmd, "difficulty": "medium"}

        # Check sudo context
        for func_name in ("shell", "command"):
            func_entries = functions.get(func_name)
            if func_entries is None:
                continue
            cmd = extract_shell_command(func_entries, "sudo", binary_name)
            if cmd is not None and bin_path not in sudo_entries:
                difficulty = "easy" if func_name == "shell" else "medium"
                sudo_entries[bin_path] = {"cmd": cmd, "difficulty": difficulty}

        for func_name in ("file-read", "file-write"):
            func_entries = functions.get(func_name)
            if func_entries is None:
                continue
            cmd = extract_shell_command(func_entries, "sudo", binary_name)
            if cmd is not None and bin_path not in sudo_entries:
                sudo_entries[bin_path] = {"cmd": cmd, "difficulty": "medium"}

        # Check capabilities context
        for func_name in ("shell", "command"):
            func_entries = functions.get(func_name)
            if func_entries is None:
                continue
            cmd = extract_shell_command(func_entries, "capabilities", binary_name)
            if cmd is not None:
                # Capabilities are grouped by capability type
                # Extract the capability list
                cap_list = _get_capability_list(func_entries)
                cap_key = _capability_list_to_key(cap_list)
                if cap_key not in capabilities_entries:
                    capabilities_entries[cap_key] = {}
                if bin_path not in capabilities_entries[cap_key]:
                    difficulty = "easy" if func_name == "shell" else "medium"
                    capabilities_entries[cap_key][bin_path] = {
                        "cmd": cmd,
                        "difficulty": difficulty,
                    }

    result = {
        "_description": "GTFOBins exploit reference database for PrivEscalate. Source: https://gtfobins.github.io/",
        "_note": "This is a curated subset of GTFOBins for the most common SUID/sudo/capabilities exploits.",
        "suid": dict(sorted(suid_entries.items())),
        "sudo": dict(sorted(sudo_entries.items())),
        "capabilities": {},
    }

    # Sort capabilities
    for cap_key in sorted(capabilities_entries.keys()):
        result["capabilities"][cap_key] = dict(
            sorted(capabilities_entries[cap_key].items())
        )

    return result


def _capability_list_to_key(cap_list):
    """Convert a raw capability list like ['CAP_SETUID'] to key like 'cap_setuid+ep'."""
    # Map known capabilities to the format used in the reference file
    CAP_KEY_MAP = {
        "CAP_SETUID": "cap_setuid+ep",
        "CAP_DAC_OVERRIDE": "cap_dac_override+ep",
        "CAP_NET_RAW": "cap_net_raw+ep",
        "CAP_SYS_ADMIN": "cap_sys_admin+ep",
    }
    if not cap_list:
        return "cap_setuid+ep"
    # Use the first capability for the key
    raw = cap_list[0]
    return CAP_KEY_MAP.get(raw, raw.lower() + "+ep")


def _get_capability_list(function_entries):
    """Extract capability list from function entries."""
    if not isinstance(function_entries, list):
        return []
    for entry in function_entries:
        if not isinstance(entry, dict):
            continue
        contexts = entry.get("contexts")
        if not isinstance(contexts, dict):
            continue
        cap_ctx = contexts.get("capabilities")
        if isinstance(cap_ctx, dict):
            cap_list = cap_ctx.get("list", [])
            if cap_list:
                return cap_list
    return []


def validate_json(data, path, label):
    """Validate generated JSON by checking key properties."""
    errors = []
    if not isinstance(data, dict):
        errors.append(f"{label}: root is not a dict")
        return errors

    if label == "structured_index":
        if "_total_binaries" not in data:
            errors.append(f"{label}: missing _total_binaries")
        if "suid_count" not in data:
            errors.append(f"{label}: missing suid_count")
        if "sudo_count" not in data:
            errors.append(f"{label}: missing sudo_count")
        if len(data.get("suid_exploitable", [])) != data.get("suid_count", -1):
            errors.append(f"{label}: suid_exploitable length != suid_count")
        if len(data.get("sudo_exploitable", [])) != data.get("sudo_count", -1):
            errors.append(f"{label}: sudo_exploitable length != sudo_count")
        if len(data.get("capabilities_exploitable", [])) != data.get("capabilities_count", -1):
            errors.append(f"{label}: capabilities_exploitable length != capabilities_count")
    elif label == "reference":
        for section in ("suid", "sudo", "capabilities"):
            if section not in data:
                errors.append(f"{label}: missing section '{section}'")

    if errors:
        for e in errors:
            logger.error("Validation error: %s", e)
    else:
        logger.info("Validation passed for %s", label)
    return errors


def compare_with_existing(generated, existing_path, label):
    """Compare generated data with existing file and report diffs."""
    if not os.path.exists(existing_path):
        logger.warning("Existing file not found for comparison: %s", existing_path)
        return

    with open(existing_path, "r", encoding="utf-8") as f:
        existing = json.load(f)

    diffs = _diff_json(existing, generated, prefix="")
    if diffs:
        logger.warning("Differences found in %s:", label)
        for d in diffs[:50]:  # Cap at 50 diff lines
            logger.warning("  %s", d)
        if len(diffs) > 50:
            logger.warning("  ... and %d more differences", len(diffs) - 50)
    else:
        logger.info("No differences found in %s -- output matches existing file.", label)


def _diff_json(a, b, prefix=""):
    """Recursively diff two JSON-compatible structures."""
    diffs = []
    if type(a) is not type(b):
        diffs.append(f"{prefix}: type mismatch {type(a).__name__} vs {type(b).__name__}")
        return diffs
    if isinstance(a, dict):
        all_keys = sorted(set(list(a.keys()) + list(b.keys())))
        for k in all_keys:
            p = f"{prefix}.{k}" if prefix else k
            if k not in a:
                diffs.append(f"{p}: only in generated")
            elif k not in b:
                diffs.append(f"{p}: only in existing")
            else:
                diffs.extend(_diff_json(a[k], b[k], p))
    elif isinstance(a, list):
        if len(a) != len(b):
            diffs.append(f"{prefix}: list length {len(a)} vs {len(b)}")
        for i in range(min(len(a), len(b))):
            diffs.extend(_diff_json(a[i], b[i], f"{prefix}[{i}]"))
    else:
        if a != b:
            diffs.append(f"{prefix}: {a!r} vs {b!r}")
    return diffs


def main():
    parser = argparse.ArgumentParser(description="Build GTFOBins index files")
    parser.add_argument("--verify", action="store_true",
                        help="Compare generated output with existing files and report diffs")
    args = parser.parse_args()

    # Build structured index
    logger.info("Building GTFOBins structured index...")
    structured = build_structured_index()
    errors = validate_json(structured, STRUCTURED_INDEX_PATH, "structured_index")
    if errors:
        logger.error("Structured index validation failed")
        sys.exit(1)

    logger.info(
        "Structured index: %d binaries, %d SUID, %d sudo, %d capabilities",
        structured["_total_binaries"],
        structured["suid_count"],
        structured["sudo_count"],
        structured["capabilities_count"],
    )

    if args.verify:
        compare_with_existing(structured, STRUCTURED_INDEX_PATH, "structured_index")
    else:
        with open(STRUCTURED_INDEX_PATH, "w", encoding="utf-8") as f:
            json.dump(structured, f, indent=2, ensure_ascii=False)
            f.write("\n")
        logger.info("Wrote %s", STRUCTURED_INDEX_PATH)

    # Build reference
    logger.info("Building GTFOBins reference...")
    reference = build_reference()
    errors = validate_json(reference, REFERENCE_PATH, "reference")
    if errors:
        logger.error("Reference validation failed")
        sys.exit(1)

    total_cmds = (
        len(reference.get("suid", {}))
        + len(reference.get("sudo", {}))
        + sum(len(v) for v in reference.get("capabilities", {}).values())
    )
    logger.info("Reference: %d exploit commands", total_cmds)

    if args.verify:
        compare_with_existing(reference, REFERENCE_PATH, "reference")
    else:
        with open(REFERENCE_PATH, "w", encoding="utf-8") as f:
            json.dump(reference, f, indent=2, ensure_ascii=False)
            f.write("\n")
        logger.info("Wrote %s", REFERENCE_PATH)

    logger.info("GTFOBins index build complete.")


if __name__ == "__main__":
    main()
