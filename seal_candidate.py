#!/usr/bin/env python3
"""Seal v35 bytes; never creates an authority or nonce-ledger seal/key."""
from __future__ import annotations
import hashlib
from pathlib import Path

def sha(path: Path) -> str: return hashlib.sha256(path.read_bytes()).hexdigest()

root = Path(__file__).resolve().parent
manifest = root / "SHA256SUMS.txt"; manifest.unlink(missing_ok=True)
files = sorted(p for p in root.rglob("*") if p.is_file())
manifest.write_text("".join(f"{sha(p)}  {p.relative_to(root).as_posix()}\n" for p in files),
                    "ascii", newline="\n")
external = root.parent / "pgk-failclosed-001-submission-v35.EXTERNAL-SHA256SUMS.txt"
external.write_text(
    f"{sha(manifest)}  qa/orchestration/recovery/{root.name}/SHA256SUMS.txt\n",
    "ascii", newline="\n")
print(f"files={len(files)} manifest={sha(manifest)} external={external}")
print("FAIL-CLOSED: independent authority and witnessed nonce-ledger roots remain required.")
