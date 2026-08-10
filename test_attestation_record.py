#!/usr/bin/env python3
from __future__ import annotations

import copy
import hashlib
import unittest

from attestation_record import canonical, digest, validate_record

H = lambda c: c * 64


def complete_record():
    authority = {"authority_roster_sha256": H("3"),
        "authorization_sha256": H("4"), "release_nonce": H("5"),
        "threshold": 2, "verified_authorities": [
            {"key_id": "auth-a", "custodian_id": "custodian-a", "spki_sha256": H("6")},
            {"key_id": "auth-b", "custodian_id": "custodian-b", "spki_sha256": H("7")}]}
    request = {"schema_version": 1, "initiative_id": "PGK-FAILCLOSED-001",
        "candidate_generation": "v35", "authorization_sha256": H("4"),
        "release_nonce": H("5"), "manifest_sha256": H("1"),
        "authority_roster_sha256": H("3"), "client_challenge": H("8")}
    receipt = dict(request)
    receipt.update({"result": "CONSUMED", "ledger_epoch": H("9"), "tree_size": 2,
        "tree_root_sha256": H("a"), "consumed_record_sha256": H("b"),
        "leaf_index": 1, "inclusion_path_sha256": [], "prior_tree_size": 1,
        "prior_tree_root_sha256": H("c"), "consistency_path_sha256": []})
    snapshot = {"test_kernel.py": H("d"), "kernel.py": H("e")}
    result = {"suite_exit_code": 0, "candidate_unchanged": True,
        "execution_snapshot_unchanged": True,
        "executed_entrypoint_relative": "test_kernel.py",
        "executed_entrypoint_sha256": H("d"),
        "execution_snapshot_file_digests_sha256": digest(snapshot),
        "stdout_sha256": H("f"), "stdout_bytes": 1, "stderr_sha256": H("0"),
        "stderr_bytes": 0, "result_artifact_relative": "builder-test-results.json",
        "result_artifact_sha256": H("1"), "result_artifact_bytes": 2}
    bindings = {"candidate_generation": "v35", "candidate_manifest_sha256": H("1"),
        "execution_manifest_sha256": H("f"),
        "external_pin_sha256": H("2"), "authority_roster_sha256": H("3"),
        "authorization_sha256": H("4"), "nonce_consumption_request_sha256": digest(request),
        "nonce_consumption_receipt_sha256": hashlib.sha256(canonical(receipt)).hexdigest(),
        "checkpoint_before": {"ledger_epoch": H("9"), "tree_size": 1,
                              "tree_root_sha256": H("c")},
        "checkpoint_after": {"ledger_epoch": H("9"), "tree_size": 2,
                             "tree_root_sha256": H("a")},
        "checkpoint_service_bindings": [
            {"service_id": "a", "custodian_id": "service-custodian-a",
             "origin": "https://a.example:443", "tls_leaf_sha256": H("2"),
             "signing_spki_sha256": H("3")},
            {"service_id": "b", "custodian_id": "service-custodian-b",
             "origin": "https://b.example:443", "tls_leaf_sha256": H("4"),
             "signing_spki_sha256": H("5")}], "result_sha256": digest(result)}
    return {"schema_version": 1, "kind": "PGKv35AuthorityObservedExternalRun",
        "candidate_generation": "v35", "external_pin_manifest_sha256": H("1"),
        "manifest_sha256": H("1"), "execution_manifest_sha256": H("f"),
        "threshold_authorization": authority,
        "nonce_consumption_receipt": receipt,
        "nonce_consumption_request_sha256": digest(request),
        "nonce_consumption_receipt_sha256": hashlib.sha256(canonical(receipt)).hexdigest(),
        "execution_snapshot_file_digests": snapshot, "result": result,
        "result_sha256": digest(result), "bindings": bindings,
        "bindings_sha256": digest(bindings)}


def recompute(record):
    record["result_sha256"] = digest(record["result"])
    record["bindings"]["result_sha256"] = record["result_sha256"]
    record["bindings_sha256"] = digest(record["bindings"])


class RecordTests(unittest.TestCase):
    def test_complete_record(self):
        record = complete_record()
        validate_record(record, expected_manifest_files=record["execution_snapshot_file_digests"])

    def test_hostile_recomputed_semantics_rejected(self):
        mutations = [
            ("bad_manifest", lambda r: r["bindings"].__setitem__("candidate_manifest_sha256", "x")),
            ("null_authorization", lambda r: r["bindings"].__setitem__("authorization_sha256", None)),
            ("rollback", lambda r: r["bindings"]["checkpoint_after"].__setitem__("tree_size", 1)),
            ("empty_services", lambda r: r["bindings"].__setitem__("checkpoint_service_bindings", [])),
            ("same_custodian", lambda r: r["bindings"]["checkpoint_service_bindings"][1].__setitem__("custodian_id", "service-custodian-a")),
            ("failed_suite", lambda r: r["result"].__setitem__("suite_exit_code", 1)),
        ]
        for name, mutate in mutations:
            with self.subTest(name=name):
                record = copy.deepcopy(complete_record()); mutate(record); recompute(record)
                with self.assertRaises(ValueError): validate_record(
                    record, expected_manifest_files=record["execution_snapshot_file_digests"])

    def test_extra_claim_is_rejected(self):
        record = complete_record(); record["candidate_root"] = "/operator/path"
        with self.assertRaises(ValueError): validate_record(
            record, expected_manifest_files=record["execution_snapshot_file_digests"])

    def test_incomplete_snapshot_rejected_against_manifest(self):
        record = complete_record()
        expected = dict(record["execution_snapshot_file_digests"])
        record["execution_snapshot_file_digests"].pop("kernel.py")
        record["result"]["execution_snapshot_file_digests_sha256"] = digest(
            record["execution_snapshot_file_digests"])
        recompute(record)
        with self.assertRaisesRegex(ValueError, "snapshot binding"):
            validate_record(record, expected_manifest_files=expected)


if __name__ == "__main__":
    unittest.main()
