#!/usr/bin/env python3
"""Protected authority entrypoint for the reviewed v35 connector."""
from __future__ import annotations

import argparse
from pathlib import Path


def main() -> int:
    p = argparse.ArgumentParser()
    p.add_argument("--input-root", required=True, type=Path)
    p.add_argument("--evidence-dir", required=True, type=Path)
    a = p.parse_args()
    root = a.input_root.resolve(strict=True)
    candidate = (root / "candidate").resolve(strict=True)
    if candidate.parent != root or candidate.is_symlink():
        raise SystemExit("candidate path alias")
    evidence = a.evidence_dir.resolve()
    if evidence.exists():
        raise SystemExit("evidence directory already exists")
    from construct_v35_record import construct_record
    construct_record(input_root=root, candidate_root=candidate,
                     evidence_dir=evidence)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
