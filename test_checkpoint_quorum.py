#!/usr/bin/env python3
from __future__ import annotations

import base64
import json
import tempfile
import unittest
from pathlib import Path

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ed25519

import checkpoint_quorum as quorum


EPOCH = "e" * 64
ANCHOR = "a" * 64


class Fixture:
    def __init__(self, root: Path, name: str):
        self.name = name
        self.key = ed25519.Ed25519PrivateKey.generate()
        self.path = root / f"{name}.pem"
        public = self.key.public_key()
        self.path.write_bytes(public.public_bytes(serialization.Encoding.PEM,
                                                  serialization.PublicFormat.SubjectPublicKeyInfo))
        spki = public.public_bytes(serialization.Encoding.DER,
                                   serialization.PublicFormat.SubjectPublicKeyInfo)
        self.pin = quorum.digest(spki)
        self.head = (1, ANCHOR)

    def service(self):
        marker = "a" if self.name.endswith("a") else "b"
        return quorum.Service(self.name, f"custodian-{marker}",
                              f"https://checkpoint-{marker}.example:443",
                              marker * 64, self.path, self.pin, self.post)

    def post(self, raw):
        req = json.loads(raw)
        if req["operation"] == "CURRENT":
            response = {**req, "service_id": self.name,
                        "request_sha256": quorum.digest(raw),
                        "tree_size": self.head[0], "tree_root_sha256": self.head[1]}
        else:
            result = "COMMITTED" if (req["prior_tree_size"], req["prior_tree_root_sha256"]) == self.head else "STALE"
            if result == "COMMITTED": self.head = (req["tree_size"], req["tree_root_sha256"])
            response = {**req, "service_id": self.name,
                        "request_sha256": quorum.digest(raw), "result": result}
        out = quorum.canonical(response)
        sig = base64.b64encode(self.key.sign(quorum.DOMAIN + out)).decode("ascii")
        return out, sig


class QuorumTest(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="pgk-v27-quorum-")
        root = Path(self.temp.name)
        self.a, self.b = Fixture(root, "witness-a"), Fixture(root, "witness-b")
        self.services = (self.a.service(), self.b.service())

    def tearDown(self): self.temp.cleanup()

    def receipt(self, marker):
        value = {"ledger_epoch": EPOCH, "prior_tree_size": 1,
                 "prior_tree_root_sha256": ANCHOR, "tree_size": 2,
                 "tree_root_sha256": marker * 64}
        return value, quorum.canonical(value)

    def test_successor_commits_to_both_services(self):
        before = quorum.read_current(self.services, EPOCH)
        receipt, raw = self.receipt("b")
        self.assertEqual(quorum.commit(self.services, before, raw, receipt)["tree_size"], 2)
        self.assertEqual(self.a.head, self.b.head)

    def test_restoring_any_local_file_cannot_reopen_sibling(self):
        # v26's vulnerable current.json does not exist in this protocol.
        before = quorum.read_current(self.services, EPOCH)
        first, raw = self.receipt("b")
        quorum.commit(self.services, before, raw, first)
        sibling, sibling_raw = self.receipt("c")
        with self.assertRaises(quorum.QuorumReject):
            quorum.commit(self.services, before, sibling_raw, sibling)

    def test_split_view_fails_closed(self):
        self.b.head = (2, "b" * 64)
        with self.assertRaisesRegex(quorum.QuorumReject, "split view"):
            quorum.read_current(self.services, EPOCH)

    def test_partial_commit_wedges_closed_not_allow(self):
        before = quorum.read_current(self.services, EPOCH)
        self.b.head = (2, "c" * 64)
        receipt, raw = self.receipt("b")
        with self.assertRaises(quorum.QuorumReject):
            quorum.commit(self.services, before, raw, receipt)
        with self.assertRaises(quorum.QuorumReject):
            quorum.read_current(self.services, EPOCH)

    def test_replayed_signed_response_fails_fresh_challenge(self):
        original = self.b.post
        first = [None]
        def replay(raw):
            if first[0] is None: first[0] = original(raw)
            return first[0]
        services = (self.a.service(),
                    quorum.Service("witness-b", "custodian-b",
                                   "https://checkpoint-b.example:443", "b" * 64,
                                   self.b.path, self.b.pin, replay))
        self.assertEqual(quorum.read_current(services, EPOCH)["tree_size"], 1)
        # A new invocation has a different challenge/request digest, but B
        # replays its previously valid signed response.
        with self.assertRaises(quorum.QuorumReject):
            quorum.read_current(services, EPOCH)


if __name__ == "__main__": unittest.main(verbosity=2)
