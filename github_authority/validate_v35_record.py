#!/usr/bin/env python3
"""Authority-side independent record and observed-file validation."""
from __future__ import annotations

import argparse
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from result_attestation import validate_record_and_files  # noqa: E402


def main() -> int:
    p = argparse.ArgumentParser()
    p.add_argument("--record", required=True, type=Path)
    p.add_argument("--evidence-dir", required=True, type=Path)
    p.add_argument("--manifest", required=True, type=Path)
    a = p.parse_args()
    validate_record_and_files(a.record, a.evidence_dir, a.manifest)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
