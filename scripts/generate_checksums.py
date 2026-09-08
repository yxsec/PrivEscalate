#!/usr/bin/env python3
"""Generate a deterministic SHA-256 manifest for release files."""

from __future__ import annotations

import hashlib
from pathlib import Path


ROOT = Path(__file__).resolve().parent.parent
OUTPUT = ROOT / "manifests" / "SHA256SUMS"


def main() -> None:
    rows = []
    for path in sorted(candidate for candidate in ROOT.rglob("*") if candidate.is_file()):
        if path == OUTPUT or ".git" in path.parts or "__pycache__" in path.parts:
            continue
        digest = hashlib.sha256(path.read_bytes()).hexdigest()
        rows.append(f"{digest}  {path.relative_to(ROOT).as_posix()}")
    OUTPUT.write_text("\n".join(rows) + "\n", encoding="utf-8")
    print(f"Wrote {len(rows)} checksums to {OUTPUT.relative_to(ROOT)}")


if __name__ == "__main__":
    main()
