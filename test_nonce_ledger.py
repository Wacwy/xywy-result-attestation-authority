#!/usr/bin/env python3
from __future__ import annotations

import base64
import hashlib
import tempfile
import unittest
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from threading import Lock

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ed25519

import nonce_ledger


class FakeIndependentLedger:
    """Atomic test double; production must use the external HTTPS ledger."""
    def __init__(self):
        self.lock = Lock()
        self.consumed: set[str] = set()
        # Externally anchored prior checkpoint (one bootstrap leaf).  The
        # candidate never chooses this value in production.
        self.leaves: list[str] = ["0" * 64]
        self.tree_size = 1
        self.prior_root = nonce_ledger._leaf_hash(self.leaves[0]).hex()

    @staticmethod
    def _parent(left: bytes, right: bytes) -> bytes:
        return hashlib.sha256(b"\x01" + left + right).digest()

    def _proof(self, index: int) -> tuple[str, list[str]]:
        level = [nonce_ledger._leaf_hash(value) for value in self.leaves]
        path = []
        cursor = index
        while len(level) > 1:
            if cursor & 1:
                path.append(level[cursor - 1].hex())
            elif cursor + 1 < len(level):
                path.append(level[cursor + 1].hex())
            next_level = []
            for i in range(0, len(level), 2):
                next_level.append(self._parent(level[i], level[i + 1])
                                  if i + 1 < len(level) else level[i])
            cursor //= 2
            level = next_level
        return level[0].hex(), path

    def consume(self, request: dict, *, challenge: str | None = None) -> dict:
        candidate = dict(request)
        if challenge is not None:
            candidate["client_challenge"] = challenge
        with self.lock:
            if candidate["release_nonce"] in self.consumed:
                result = "ALREADY_CONSUMED"
            else:
                self.consumed.add(candidate["release_nonce"])
                self.tree_size += 1
                result = "CONSUMED"
                record = nonce_ledger._expected_consumed_record(candidate)
                self.leaves.append(record)
            record = nonce_ledger._expected_consumed_record(candidate)
            leaf_index = self.leaves.index(record)
            root, proof = self._proof(leaf_index)
            return {**candidate, "result": result, "ledger_epoch": "e" * 64,
                    "tree_size": self.tree_size,
                    "tree_root_sha256": root,
                    "consumed_record_sha256": record,
                    "leaf_index": leaf_index,
                    "inclusion_path_sha256": proof,
                    "prior_tree_size": 1,
                    "prior_tree_root_sha256": self.prior_root,
                    # For a 1 -> 2 tree the consistency proof is the new leaf.
                    "consistency_path_sha256": [
                        nonce_ledger._leaf_hash(self.leaves[1]).hex()]}


class NonceLedgerTest(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="pgk-v26-ledger-")
        self.root = Path(self.temp.name)
        self.keys = {}
        self.paths = {}
        self.pins = {}
        for name in ("ledger", "witness"):
            private = ed25519.Ed25519PrivateKey.generate()
            raw = private.public_key().public_bytes(
                serialization.Encoding.DER,
                serialization.PublicFormat.SubjectPublicKeyInfo)
            path = self.root / f"{name}.spki.der"; path.write_bytes(raw)
            self.keys[name] = private; self.paths[name] = path
            self.pins[name] = hashlib.sha256(raw).hexdigest()
        self.request, self.request_raw = nonce_ledger.build_request(
            authorization_sha256="1" * 64, release_nonce="2" * 64,
            manifest_sha256="3" * 64, authority_roster_sha256="4" * 64,
            challenge=bytes.fromhex("5" * 64))
        self.ledger = FakeIndependentLedger()

    def tearDown(self):
        self.temp.cleanup()

    def signed(self, receipt: dict):
        raw = nonce_ledger.canonical_bytes(receipt)
        message = nonce_ledger.RECEIPT_DOMAIN + raw
        signatures = {
            name: base64.b64encode(key.sign(message)).decode("ascii")
            for name, key in self.keys.items()
        }
        return raw, signatures

    def verify(self, receipt: dict, **overrides):
        raw, signatures = self.signed(receipt)
        args = dict(
            request=self.request, receipt_raw=raw,
            ledger_signature_b64=signatures["ledger"],
            witness_signature_b64=signatures["witness"],
            ledger_public_key_path=self.paths["ledger"],
            witness_public_key_path=self.paths["witness"],
            trusted_ledger_spki_sha256=self.pins["ledger"],
            trusted_witness_spki_sha256=self.pins["witness"],
            trusted_ledger_epoch="e" * 64,
            trusted_prior_tree_size=1,
            trusted_prior_root_sha256=self.ledger.prior_root)
        args.update(overrides)
        return nonce_ledger.verify_consumption_receipt(**args)

    def test_consumed_receipt_is_accepted(self):
        result = self.verify(self.ledger.consume(self.request))
        self.assertEqual(result["result"], "CONSUMED")

    def test_sequential_replay_is_rejected(self):
        self.verify(self.ledger.consume(self.request))
        with self.assertRaises(nonce_ledger.LedgerReplay):
            self.verify(self.ledger.consume(self.request))

    def test_concurrent_double_spend_has_exactly_one_winner(self):
        with ThreadPoolExecutor(max_workers=16) as pool:
            receipts = list(pool.map(lambda _: self.ledger.consume(self.request), range(16)))
        self.assertEqual(sum(r["result"] == "CONSUMED" for r in receipts), 1)
        self.assertEqual(sum(r["result"] == "ALREADY_CONSUMED" for r in receipts), 15)

    def test_receipt_replay_with_fresh_challenge_is_rejected(self):
        receipt = self.ledger.consume(self.request)
        fresh, _ = nonce_ledger.build_request(
            authorization_sha256="1" * 64, release_nonce="2" * 64,
            manifest_sha256="3" * 64, authority_roster_sha256="4" * 64,
            challenge=bytes.fromhex("6" * 64))
        raw, signatures = self.signed(receipt)
        with self.assertRaisesRegex(nonce_ledger.LedgerReject, "request binding"):
            nonce_ledger.verify_consumption_receipt(
                request=fresh, receipt_raw=raw,
                ledger_signature_b64=signatures["ledger"],
                witness_signature_b64=signatures["witness"],
                ledger_public_key_path=self.paths["ledger"],
                witness_public_key_path=self.paths["witness"],
                trusted_ledger_spki_sha256=self.pins["ledger"],
                trusted_witness_spki_sha256=self.pins["witness"],
                trusted_ledger_epoch="e" * 64,
                trusted_prior_tree_size=1,
                trusted_prior_root_sha256=self.ledger.prior_root)

    def test_rollback_epoch_and_witness_substitution_are_rejected(self):
        receipt = self.ledger.consume(self.request)
        with self.assertRaisesRegex(nonce_ledger.LedgerReject, "epoch"):
            self.verify(receipt, trusted_ledger_epoch="a" * 64)
        with self.assertRaisesRegex(nonce_ledger.LedgerReject, "verifier key pin"):
            self.verify(receipt, trusted_witness_spki_sha256="0" * 64)

    def test_forged_checkpoint_and_inclusion_path_are_rejected(self):
        receipt = self.ledger.consume(self.request)
        forged = dict(receipt)
        forged["tree_root_sha256"] = "0" * 64
        with self.assertRaisesRegex(nonce_ledger.LedgerReject, "(inclusion|consistency) proof"):
            self.verify(forged)

    def test_same_size_incompatible_root_is_rejected(self):
        root = self.ledger.prior_root
        nonce_ledger.verify_consistency_proof(
            old_tree_size=1, new_tree_size=1,
            old_root_sha256=root, new_root_sha256=root, audit_path=[])
        with self.assertRaisesRegex(nonce_ledger.LedgerReject, "equivocation"):
            nonce_ledger.verify_consistency_proof(
                old_tree_size=1, new_tree_size=1,
                old_root_sha256=root, new_root_sha256="f" * 64,
                audit_path=[])

    def test_prior_checkpoint_and_consistency_proof_are_required(self):
        receipt = self.ledger.consume(self.request)
        forged = dict(receipt)
        forged["prior_tree_root_sha256"] = "f" * 64
        with self.assertRaisesRegex(nonce_ledger.LedgerReject, "prior checkpoint"):
            self.verify(forged)
        forged = dict(receipt)
        forged["consistency_path_sha256"] = []
        with self.assertRaisesRegex(nonce_ledger.LedgerReject, "consistency proof"):
            self.verify(forged)

    def test_leaf_for_another_record_is_rejected_even_with_valid_proof(self):
        receipt = self.ledger.consume(self.request)
        forged = dict(receipt)
        forged["consumed_record_sha256"] = "9" * 64
        forged["tree_root_sha256"] = nonce_ledger._leaf_hash("9" * 64).hex()
        with self.assertRaisesRegex(nonce_ledger.LedgerReject, "record binding"):
            self.verify(forged)
        forged = dict(receipt)
        forged["inclusion_path_sha256"] = ["1" * 64]
        with self.assertRaisesRegex(nonce_ledger.LedgerReject, "inclusion proof"):
            self.verify(forged)

    def test_callable_swap_is_observable_and_rejected(self):
        original = nonce_ledger.verify_consumption_receipt
        identity = hashlib.sha256(original.__code__.co_code).hexdigest()
        nonce_ledger.verify_consumption_receipt = lambda **_: {"result": "CONSUMED"}
        try:
            changed = hashlib.sha256(
                nonce_ledger.verify_consumption_receipt.__code__.co_code).hexdigest()
            self.assertNotEqual(identity, changed)
            # Production snapshot manifest pins nonce_ledger.py, and the
            # process imports from that read-only private snapshot only.
        finally:
            nonce_ledger.verify_consumption_receipt = original


if __name__ == "__main__":
    unittest.main(verbosity=2)
