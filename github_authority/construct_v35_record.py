#!/usr/bin/env python3
"""Authority-owned v35 connector; constructs records only from observed bytes."""
from __future__ import annotations

import json
import os
import subprocess
import sys
from pathlib import Path

REQUIRED_DEPLOYMENT_FILES = {
    "external_pin": "external-pin.txt",
    "authority_roster": "authority-roster.json",
    "authorization": "authorization.json",
    "authority_public_key_dir": "authority-public-keys",
    "authority_signature_dir": "authority-signatures",
    "nonce_ledger_public_key": "nonce-ledger.spki.der",
    "nonce_witness_public_key": "nonce-witness.spki.der",
    "checkpoint_a_public_key": "checkpoint-a.spki.der",
    "checkpoint_b_public_key": "checkpoint-b.spki.der",
}


def _deployment_root(input_root: Path) -> Path:
    configured = os.environ.get("PGK_DEPLOYMENT_ROOT")
    if not configured:
        raise RuntimeError("PGK_DEPLOYMENT_ROOT is required")
    root = Path(configured)
    if not root.is_absolute():
        raise RuntimeError("deployment root must be absolute")
    resolved = root.resolve(strict=True)
    input_root = input_root.resolve(strict=True)
    if (resolved == input_root or input_root in resolved.parents
            or resolved in input_root.parents):
        raise RuntimeError("deployment root must be independent from input root")
    if resolved.is_symlink():
        raise RuntimeError("deployment root path alias")
    return resolved


def construct_record(*, input_root: Path, candidate_root: Path,
                     evidence_dir: Path) -> None:
    deployment = _deployment_root(input_root)
    paths = {name: (deployment / relative).resolve(strict=True)
             for name, relative in REQUIRED_DEPLOYMENT_FILES.items()}
    for name, path in paths.items():
        if deployment not in path.parents or path.is_symlink():
            raise RuntimeError(f"deployment path alias: {name}")
        expected_directory = name.endswith("_dir")
        if expected_directory != path.is_dir():
            raise RuntimeError(f"deployment artifact type: {name}")
    authority_root = Path(__file__).resolve().parents[1]
    command = [
        sys.executable, str(authority_root / "run_external.py"),
        "--evidence-dir", str(evidence_dir),
        "--external-pin", str(paths["external_pin"]),
        "--authority-roster", str(paths["authority_roster"]),
        "--authorization", str(paths["authorization"]),
        "--authority-public-key-dir", str(paths["authority_public_key_dir"]),
        "--authority-signature-dir", str(paths["authority_signature_dir"]),
        "--nonce-ledger-public-key", str(paths["nonce_ledger_public_key"]),
        "--nonce-witness-public-key", str(paths["nonce_witness_public_key"]),
        "--checkpoint-a-public-key", str(paths["checkpoint_a_public_key"]),
        "--checkpoint-b-public-key", str(paths["checkpoint_b_public_key"]),
        "--execution-manifest", str((input_root / "execution-manifest.json").resolve(strict=True)),
    ]
    completed = subprocess.run(
        command, cwd=input_root, stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=360,
        check=False, env={**os.environ, "PYTHONDONTWRITEBYTECODE": "1",
                          "PGK_CANDIDATE_DIR": str(candidate_root)})
    if completed.returncode != 0:
        detail = completed.stderr.decode("utf-8", errors="replace")[-2000:]
        raise RuntimeError(f"authority execution rejected: {detail}")
    record_path = evidence_dir / "external-run.json"
    if not record_path.is_file():
        raise RuntimeError("authority execution produced no record")
    if completed.stdout != record_path.read_bytes():
        raise RuntimeError("authority record/stdout mismatch")
    json.loads(completed.stdout.decode("ascii"))
