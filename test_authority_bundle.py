#!/usr/bin/env python3
from __future__ import annotations

import base64
import hashlib
import json
import tempfile
import unittest
from pathlib import Path

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ed25519

from authority_bundle import DOMAIN, canonical_bytes, verify_threshold_authorization


class AuthorityBundleTest(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="pgk-v35-unit-")
        self.root = Path(self.temp.name)
        self.keys = self.root / "keys"; self.keys.mkdir()
        self.signatures = self.root / "signatures"; self.signatures.mkdir()
        self.private = {}
        authorities = []
        for key_id, custodian in (("authority-a", "custodian-a"),
                                  ("authority-b", "custodian-b")):
            private = ed25519.Ed25519PrivateKey.generate()
            public = private.public_key().public_bytes(
                serialization.Encoding.DER,
                serialization.PublicFormat.SubjectPublicKeyInfo)
            (self.keys / f"{key_id}.spki.der").write_bytes(public)
            self.private[key_id] = private
            authorities.append({"key_id": key_id, "spki_sha256": hashlib.sha256(public).hexdigest(),
                                "custodian_id": custodian})
        self.roster = {"schema_version": 1, "initiative_id": "PGK-FAILCLOSED-001",
                       "candidate_generation": "v35", "threshold": 2, "authorities": authorities}
        self.roster_raw = canonical_bytes(self.roster)
        self.roster_path = self.root / "roster.json"; self.roster_path.write_bytes(self.roster_raw)
        self.roster_sha = hashlib.sha256(self.roster_raw).hexdigest()
        self.authorization = {
            "schema_version": 1, "initiative_id": "PGK-FAILCLOSED-001", "candidate_generation": "v35",
            "manifest_sha256": "1" * 64, "external_pin_sha256": "2" * 64,
            "external_pin_target": "qa/orchestration/recovery/pgk-failclosed-001-submission-v35/SHA256SUMS.txt",
            "release_nonce": "3" * 64, "authority_roster_sha256": self.roster_sha,
        }
        self.authorization_path = self.root / "authorization.json"
        self.authorization_path.write_bytes(canonical_bytes(self.authorization))
        self.sign()

    def tearDown(self): self.temp.cleanup()

    def sign(self):
        message = DOMAIN + self.authorization_path.read_bytes()
        for key_id, private in self.private.items():
            signature = base64.b64encode(private.sign(message)).decode("ascii") + "\n"
            (self.signatures / f"{key_id}.ed25519.b64").write_text(signature, "ascii", newline="\n")

    def verify(self):
        return verify_threshold_authorization(
            roster_path=self.roster_path, authorization_path=self.authorization_path,
            public_key_dir=self.keys, signature_dir=self.signatures,
            trusted_roster_sha256=self.roster_sha,
            expected_manifest_sha256="1" * 64, expected_pin_sha256="2" * 64,
            expected_pin_target=self.authorization["external_pin_target"])

    def test_valid_unanimous_authorization(self):
        result = self.verify()
        self.assertEqual(result["threshold"], 2)
        self.assertEqual(len(result["verified_authorities"]), 2)

    def test_missing_signature_fails_closed(self):
        (self.signatures / "authority-b.ed25519.b64").unlink()
        with self.assertRaises((ValueError, FileNotFoundError)): self.verify()

    def test_wrong_roster_pin_fails_closed(self):
        with self.assertRaisesRegex(ValueError, "not trusted"):
            verify_threshold_authorization(
                roster_path=self.roster_path, authorization_path=self.authorization_path,
                public_key_dir=self.keys, signature_dir=self.signatures,
                trusted_roster_sha256="0" * 64, expected_manifest_sha256="1" * 64,
                expected_pin_sha256="2" * 64,
                expected_pin_target=self.authorization["external_pin_target"])

    def test_manifest_rewrite_with_reused_signatures_fails(self):
        changed = dict(self.authorization); changed["manifest_sha256"] = "4" * 64
        self.authorization_path.write_bytes(canonical_bytes(changed))
        with self.assertRaisesRegex(ValueError, "authority signature"):
            verify_threshold_authorization(
                roster_path=self.roster_path, authorization_path=self.authorization_path,
                public_key_dir=self.keys, signature_dir=self.signatures,
                trusted_roster_sha256=self.roster_sha, expected_manifest_sha256="4" * 64,
                expected_pin_sha256="2" * 64,
                expected_pin_target=self.authorization["external_pin_target"])

    def test_nonce_is_mandatory_and_exact(self):
        changed = dict(self.authorization); changed["release_nonce"] = "short"
        self.authorization_path.write_bytes(canonical_bytes(changed)); self.sign()
        with self.assertRaisesRegex(ValueError, "exact release"): self.verify()


if __name__ == "__main__":
    unittest.main(verbosity=2)
