#!/usr/bin/env python3
from __future__ import annotations

import unittest
from pathlib import Path
from unittest import mock

import promotion_gate as pg


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


if __name__ == "__main__":
    unittest.main()
