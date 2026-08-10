#!/usr/bin/env python3
"""Single fail-closed v35 promotion gate; no unauthenticated result path."""
from __future__ import annotations

import argparse
import json
from pathlib import Path

from result_attestation import verify
from tuf_roster import verify_roster


def promotion_decision(*, record: Path, evidence_dir: Path, manifest: Path, bundle: Path,
                       policy: Path, cosign: Path, tuf_root: Path,
                       tuf_targets: Path, authority_roster: Path) -> dict:
    roster = verify_roster(root_path=tuf_root, targets_path=tuf_targets,
                           roster_path=authority_roster)
    attestation = verify(record_path=record, evidence_dir=evidence_dir,
                         manifest_path=manifest,
                         bundle_path=bundle, policy_path=policy,
                         cosign_path=cosign)
    if roster["roster_sha256"] != attestation["authority_roster_sha256"]:
        raise ValueError("attested roster does not match TUF target")
    if roster["authorities"] != attestation["verified_authorities"]:
        raise ValueError("attested authority members do not match TUF roster")
    return {"official_pass": True, "promotion_allowed": True,
            "result_attestation": attestation, "tuf_roster": roster}


def main() -> int:
    p = argparse.ArgumentParser()
    for name in ("record", "evidence-dir", "manifest", "bundle", "policy", "cosign",
                 "tuf-root", "tuf-targets", "authority-roster"):
        p.add_argument("--" + name, required=True, type=Path)
    a = p.parse_args()
    print(json.dumps(promotion_decision(record=a.record,
        evidence_dir=a.evidence_dir, manifest=a.manifest,
        bundle=a.bundle, policy=a.policy,
        cosign=a.cosign, tuf_root=a.tuf_root, tuf_targets=a.tuf_targets,
        authority_roster=a.authority_roster), sort_keys=True,
        separators=(",", ":")))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
