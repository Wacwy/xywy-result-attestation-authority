#!/usr/bin/env python3
from __future__ import annotations

import unittest
import base64
import hashlib
import tempfile
from pathlib import Path
from unittest import mock

from cryptography.hazmat.primitives.asymmetric import ed25519

import promotion_gate as pg
import tuf_roster as tr


class PromotionGateTests(unittest.TestCase):
    def call(self, roster, attestation):
        with mock.patch.object(pg, "verify_roster", return_value=roster), \
             mock.patch.object(pg, "verify", return_value=attestation):
            return pg.promotion_decision(record=Path("r"), evidence_dir=Path("e"),
                manifest=Path("m"), bundle=Path("b"), policy=Path("p"),
                cosign=Path("c"), tuf_root=Path("root"),
                tuf_targets=Path("targets"), authority_roster=Path("roster"))

    def test_exact_members_accept(self):
        members = [{"key_id": "a", "custodian_id": "ca", "spki_sha256": "1" * 64},
                   {"key_id": "b", "custodian_id": "cb", "spki_sha256": "2" * 64}]
        result = self.call({"roster_sha256": "3" * 64, "authorities": members},
                           {"authority_roster_sha256": "3" * 64,
                            "verified_authorities": members})
        self.assertTrue(result["promotion_allowed"])

    def test_invented_members_rejected_despite_matching_digest(self):
        roster_members = [{"key_id": "a", "custodian_id": "ca", "spki_sha256": "1" * 64}]
        invented = [{"key_id": "x", "custodian_id": "cx", "spki_sha256": "9" * 64}]
        with self.assertRaisesRegex(ValueError, "members"):
            self.call({"roster_sha256": "3" * 64, "authorities": roster_members},
                      {"authority_roster_sha256": "3" * 64,
                       "verified_authorities": invented})

    def test_single_tuf_publisher_carries_two_result_authorities_end_to_end(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            private = ed25519.Ed25519PrivateKey.generate()
            public = base64.b64encode(private.public_key().public_bytes_raw()).decode()
            members = [
                {"key_id": "a", "custodian_id": "ca", "spki_sha256": "1" * 64},
                {"key_id": "b", "custodian_id": "cb", "spki_sha256": "2" * 64},
            ]
            roster = {"schema_version": 1, "initiative_id": "PGK-FAILCLOSED-001",
                "candidate_generation": "v35", "threshold": 2, "authorities": members}
            roster_raw = tr.canonical(roster)
            (root / "roster.json").write_bytes(roster_raw)
            targets_signed = {"_type": "targets", "expires": "2030-01-01T00:00:00Z",
                "spec_version": "1.0.31", "targets": {"authority-roster.json": {
                    "hashes": {"sha256": hashlib.sha256(roster_raw).hexdigest()},
                    "length": len(roster_raw)}}, "version": 1}
            root_signed = {"_type": "root", "expires": "2030-01-01T00:00:00Z",
                "keys": {"publisher": {"keytype": "ed25519", "scheme": "ed25519",
                    "keyval": {"public": public}}}, "roles": {
                    "root": {"keyids": ["publisher"], "threshold": 1},
                    "targets": {"keyids": ["publisher"], "threshold": 1}},
                "spec_version": "1.0.31", "version": 1}
            def envelope(signed):
                return {"signatures": [{"keyid": "publisher", "sig": base64.b64encode(
                    private.sign(tr.canonical(signed))).decode()}], "signed": signed}
            (root / "root.json").write_bytes(tr.canonical(envelope(root_signed)))
            (root / "targets.json").write_bytes(tr.canonical(envelope(targets_signed)))
            root_sha = hashlib.sha256((root / "root.json").read_bytes()).hexdigest()
            targets_sha = hashlib.sha256((root / "targets.json").read_bytes()).hexdigest()
            real_verify_roster = lambda **kwargs: tr.verify_roster(
                **kwargs, trusted_root_sha256=root_sha, trusted_targets_sha256=targets_sha)
            attestation = {"authority_roster_sha256": hashlib.sha256(roster_raw).hexdigest(),
                           "verified_authorities": members}
            with mock.patch.object(pg, "verify_roster", side_effect=real_verify_roster), \
                 mock.patch.object(pg, "verify", return_value=attestation):
                result = pg.promotion_decision(record=Path("r"), evidence_dir=Path("e"),
                    manifest=Path("m"), bundle=Path("b"), policy=Path("p"), cosign=Path("c"),
                    tuf_root=root / "root.json", tuf_targets=root / "targets.json",
                    authority_roster=root / "roster.json")
            self.assertTrue(result["promotion_allowed"])
            self.assertEqual(result["tuf_roster"]["custodian_count"], 2)


if __name__ == "__main__":
    unittest.main()
