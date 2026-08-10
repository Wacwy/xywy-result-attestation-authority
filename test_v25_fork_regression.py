#!/usr/bin/env python3
"""Regression: v25's two co-signed siblings cannot both advance v26 state."""
from __future__ import annotations

import base64
import hashlib
import tempfile
import unittest
from pathlib import Path

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ed25519

import checkpoint_monitor
import nonce_ledger as nl


class ForkRegressionTest(unittest.TestCase):
    def test_only_one_signed_sibling_advances(self):
        with tempfile.TemporaryDirectory(prefix="pgk-v26-fork-") as td:
            temp = Path(td); keys = {}; pins = {}; paths = {}
            for name in ("ledger", "witness"):
                key = ed25519.Ed25519PrivateKey.generate()
                der = key.public_key().public_bytes(
                    serialization.Encoding.DER,
                    serialization.PublicFormat.SubjectPublicKeyInfo)
                path = temp / f"{name}.der"; path.write_bytes(der)
                keys[name], paths[name] = key, path
                pins[name] = hashlib.sha256(der).hexdigest()
            prior_leaf = nl._leaf_hash("0" * 64)
            prior_root = prior_leaf.hex()
            monitor = temp / "monitor"
            checkpoint_monitor.initialise_for_test(
                monitor, tree_size=1, tree_root_sha256=prior_root,
                ledger_epoch="e" * 64)
            outcomes = []
            for marker in ("1", "2"):
                request, _ = nl.build_request(
                    authorization_sha256=marker * 64,
                    release_nonce=("a" if marker == "1" else "b") * 64,
                    manifest_sha256="c" * 64,
                    authority_roster_sha256="d" * 64,
                    challenge=bytes([int(marker)]) * 32)
                record = nl._expected_consumed_record(request)
                new_leaf = nl._leaf_hash(record)
                root = hashlib.sha256(b"\x01" + prior_leaf + new_leaf).hexdigest()
                receipt = {**request, "result": "CONSUMED",
                    "ledger_epoch": "e" * 64, "tree_size": 2,
                    "tree_root_sha256": root,
                    "consumed_record_sha256": record, "leaf_index": 1,
                    "inclusion_path_sha256": [prior_root], "prior_tree_size": 1,
                    "prior_tree_root_sha256": prior_root,
                    "consistency_path_sha256": [new_leaf.hex()]}
                raw = nl.canonical_bytes(receipt); msg = nl.RECEIPT_DOMAIN + raw
                def verify(size, current_root):
                    return nl.verify_consumption_receipt(
                        request=request, receipt_raw=raw,
                        ledger_signature_b64=base64.b64encode(keys["ledger"].sign(msg)).decode(),
                        witness_signature_b64=base64.b64encode(keys["witness"].sign(msg)).decode(),
                        ledger_public_key_path=paths["ledger"],
                        witness_public_key_path=paths["witness"],
                        trusted_ledger_spki_sha256=pins["ledger"],
                        trusted_witness_spki_sha256=pins["witness"],
                        trusted_ledger_epoch="e" * 64,
                        trusted_prior_tree_size=size,
                        trusted_prior_root_sha256=current_root)
                try:
                    checkpoint_monitor.advance(monitor, receipt, verify)
                    outcomes.append("ALLOW")
                except (checkpoint_monitor.MonitorReject, nl.LedgerReject):
                    outcomes.append("DENY")
            self.assertEqual(outcomes, ["ALLOW", "DENY"])


if __name__ == "__main__": unittest.main(verbosity=2)
