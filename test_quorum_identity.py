#!/usr/bin/env python3
"""Hostile unit controls for v28 quorum identity anti-aliasing."""
from __future__ import annotations

import dataclasses
import tempfile
import unittest
from pathlib import Path

import checkpoint_quorum as quorum
from test_checkpoint_quorum import EPOCH, Fixture


class IdentityAliasTest(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="pgk-v28-identity-")
        root = Path(self.temp.name)
        self.a = Fixture(root, "witness-a").service()
        self.b = Fixture(root, "witness-b").service()

    def tearDown(self):
        self.temp.cleanup()

    def assert_alias_rejected(self, field: str, value: str, message: str):
        calls = []
        aliased = dataclasses.replace(
            self.b, **{field: value}, post=lambda raw: calls.append(raw))
        with self.assertRaisesRegex(quorum.QuorumReject, message):
            quorum.read_current((self.a, aliased), EPOCH)
        self.assertEqual(calls, [], "identity aliases must fail before network I/O")

    def test_duplicate_signing_key_pin_rejected(self):
        self.assert_alias_rejected("public_key_spki_sha256",
                                   self.a.public_key_spki_sha256,
                                   "distinct signing keys")

    def test_duplicate_tls_pin_rejected(self):
        self.assert_alias_rejected("tls_leaf_cert_sha256",
                                   self.a.tls_leaf_cert_sha256,
                                   "distinct TLS pins")

    def test_duplicate_custodian_rejected(self):
        self.assert_alias_rejected("custodian_id", self.a.custodian_id,
                                   "distinct custodians")

    def test_equivalent_endpoint_origin_rejected(self):
        # Default 443 and explicit :443 are the same authority boundary.
        self.assert_alias_rejected("endpoint_origin",
                                   "https://checkpoint-a.example/",
                                   "distinct endpoint origins")

    def test_endpoint_with_path_is_not_an_origin(self):
        self.assert_alias_rejected("endpoint_origin",
                                   "https://checkpoint-b.example/api",
                                   "endpoint origin")


if __name__ == "__main__":
    unittest.main(verbosity=2)
