#!/usr/bin/env python3
"""Build all PrivEscalate index files from raw data sources.

Wrapper that calls:
  - build_gtfobins_index.py (structured index + reference)
  - build_exploitdb_index.py (Linux local exploit index)
"""

import argparse
import json
import logging
import os
import sys

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    datefmt="%H:%M:%S",
)
logger = logging.getLogger(__name__)

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(BASE_DIR, "scripts"))

from build_gtfobins_index import (  # noqa: E402
    build_structured_index,
    build_reference,
    validate_json as validate_gtfobins,
    compare_with_existing as compare_gtfobins,
    STRUCTURED_INDEX_PATH,
    REFERENCE_PATH,
)
from build_exploitdb_index import (  # noqa: E402
    build_exploitdb_index,
    validate_json as validate_exploitdb,
    compare_with_existing as compare_exploitdb,
    OUTPUT_PATH as EXPLOITDB_OUTPUT_PATH,
)


def main():
    parser = argparse.ArgumentParser(description="Build all PrivEscalate index files")
    parser.add_argument("--verify", action="store_true",
                        help="Compare generated output with existing files and report diffs")
    args = parser.parse_args()

    all_ok = True

    # --- GTFOBins structured index ---
    logger.info("Building GTFOBins structured index...")
    structured = build_structured_index()
    errors = validate_gtfobins(structured, STRUCTURED_INDEX_PATH, "structured_index")
    if errors:
        logger.error("GTFOBins structured index validation failed")
        all_ok = False
    else:
        print(
            f"-> Building GTFOBins structured index... "
            f"{structured['_total_binaries']} binaries, "
            f"{structured['suid_count']} SUID, "
            f"{structured['sudo_count']} sudo, "
            f"{structured['capabilities_count']} capabilities"
        )
        if args.verify:
            compare_gtfobins(structured, STRUCTURED_INDEX_PATH, "structured_index")
        else:
            with open(STRUCTURED_INDEX_PATH, "w", encoding="utf-8") as f:
                json.dump(structured, f, indent=2, ensure_ascii=False)
                f.write("\n")

    # --- GTFOBins reference ---
    logger.info("Building GTFOBins reference...")
    reference = build_reference()
    errors = validate_gtfobins(reference, REFERENCE_PATH, "reference")
    if errors:
        logger.error("GTFOBins reference validation failed")
        all_ok = False
    else:
        total_cmds = (
            len(reference.get("suid", {}))
            + len(reference.get("sudo", {}))
            + sum(len(v) for v in reference.get("capabilities", {}).values())
        )
        print(f"-> Building GTFOBins reference... {total_cmds} exploit commands")
        if args.verify:
            compare_gtfobins(reference, REFERENCE_PATH, "reference")
        else:
            with open(REFERENCE_PATH, "w", encoding="utf-8") as f:
                json.dump(reference, f, indent=2, ensure_ascii=False)
                f.write("\n")

    # --- ExploitDB index ---
    logger.info("Building ExploitDB index...")
    exploitdb = build_exploitdb_index()
    errors = validate_exploitdb(exploitdb)
    if errors:
        logger.error("ExploitDB index validation failed")
        all_ok = False
    else:
        print(
            f"-> Building ExploitDB index... "
            f"{exploitdb['total_linux_local']} Linux local entries, "
            f"{exploitdb['privesc_related']} privesc-related"
        )
        if args.verify:
            compare_exploitdb(exploitdb, EXPLOITDB_OUTPUT_PATH)
        else:
            with open(EXPLOITDB_OUTPUT_PATH, "w", encoding="utf-8") as f:
                json.dump(exploitdb, f, indent=2, ensure_ascii=False)
                f.write("\n")

    if all_ok:
        print("-> All indices built successfully.")
    else:
        print("-> Some indices failed validation. Check logs above.")
        sys.exit(1)


if __name__ == "__main__":
    main()
