#!/usr/bin/env python3
"""Generation and provenance regressions inherited and advanced for v31."""
from __future__ import annotations

import ast
import hashlib
import json
import unittest
from pathlib import Path

HERE = Path(__file__).resolve().parent
EXPECTED_KIND = (
    "PGKv31ExternalCheckpointQuorumConsumedThresholdAuthorizedImmutableSnapshotRun"
)
STALE_KINDS = {
    "PGKv27ExternalCheckpointQuorumConsumedThresholdAuthorizedImmutableSnapshotRun",
    "PGKv28ExternalCheckpointQuorumConsumedThresholdAuthorizedImmutableSnapshotRun",
    "PGKv30ExternalCheckpointQuorumConsumedThresholdAuthorizedImmutableSnapshotRun",
}
REQUIRED_BINDINGS = {
    "candidate_generation", "candidate_manifest_sha256", "external_pin_sha256",
    "authority_roster_sha256", "authorization_sha256",
    "nonce_consumption_request_sha256", "nonce_consumption_receipt_sha256",
    "checkpoint_before", "checkpoint_after", "checkpoint_service_bindings",
    "result_sha256",
}
REQUIRED_RESULT = {
    "suite_exit_code", "candidate_unchanged", "execution_snapshot_unchanged",
    "executed_entrypoint_relative", "executed_entrypoint_sha256",
    "execution_snapshot_file_digests_sha256", "stdout_sha256", "stdout_bytes",
    "stderr_sha256", "stderr_bytes", "result_artifact_relative",
    "result_artifact_sha256", "result_artifact_bytes",
}


def binding_digest(bindings: dict) -> str:
    raw = json.dumps(bindings, sort_keys=True, separators=(",", ":")).encode(
        "ascii") + b"\n"
    return hashlib.sha256(raw).hexdigest()


def canonical_digest(value: object) -> str:
    raw = json.dumps(value, sort_keys=True, separators=(",", ":")).encode(
        "ascii") + b"\n"
    return hashlib.sha256(raw).hexdigest()


def valid_sha256(value: object) -> bool:
    return (isinstance(value, str) and len(value) == 64
            and all(c in "0123456789abcdef" for c in value))


def validate_external_record(record: object) -> None:
    """Strict evidence consumer: prior/unknown generations are inadmissible."""
    if not isinstance(record, dict) or record.get("kind") != EXPECTED_KIND:
        raise ValueError("external-run evidence kind is not exact v30")
    if record.get("candidate_generation") != "v30":
        raise ValueError("external-run candidate generation")
    bindings = record.get("bindings")
    if not isinstance(bindings, dict) or set(bindings) != REQUIRED_BINDINGS:
        raise ValueError("external-run binding set")
    if record.get("bindings_sha256") != binding_digest(bindings):
        raise ValueError("external-run binding digest")
    if bindings.get("candidate_generation") != "v30":
        raise ValueError("external-run binding generation")
    if bindings.get("candidate_manifest_sha256") != record.get("manifest_sha256"):
        raise ValueError("external-run manifest binding")
    if bindings.get("external_pin_sha256") != record.get("external_pin_sha256"):
        raise ValueError("external-run pin binding")
    authority = record.get("threshold_authorization")
    receipt = record.get("nonce_consumption_receipt")
    if not isinstance(authority, dict) or not isinstance(receipt, dict):
        raise ValueError("external-run authority or receipt")
    checks = {
        "authority_roster_sha256": authority.get("authority_roster_sha256"),
        "authorization_sha256": authority.get("authorization_sha256"),
        "nonce_consumption_request_sha256": record.get(
            "nonce_consumption_request_sha256"),
        "nonce_consumption_receipt_sha256": record.get(
            "nonce_consumption_receipt_sha256"),
    }
    if any(bindings.get(key) != value for key, value in checks.items()):
        raise ValueError("external-run digest binding")
    services = bindings.get("checkpoint_service_bindings")
    required_service_fields = {
        "service_id", "custodian_id", "origin", "tls_leaf_sha256",
        "signing_spki_sha256",
    }
    if (not isinstance(services, list) or len(services) != 2
            or any(not isinstance(service, dict)
                   or set(service) != required_service_fields for service in services)):
        raise ValueError("external-run checkpoint identity binding")
    if bindings.get("checkpoint_after") != {
        key: receipt.get(key)
        for key in ("ledger_epoch", "tree_size", "tree_root_sha256")
    }:
        raise ValueError("external-run checkpoint binding")
    result = record.get("result")
    if not isinstance(result, dict) or set(result) != REQUIRED_RESULT:
        raise ValueError("external-run result set")
    if (record.get("result_sha256") != canonical_digest(result)
            or bindings.get("result_sha256") != record.get("result_sha256")):
        raise ValueError("external-run result digest binding")
    if result.get("suite_exit_code") != 0:
        raise ValueError("external-run suite failed")
    if result.get("candidate_unchanged") is not True:
        raise ValueError("external-run candidate changed")
    if result.get("execution_snapshot_unchanged") is not True:
        raise ValueError("external-run execution snapshot changed")
    if result.get("executed_entrypoint_relative") != "test_kernel.py":
        raise ValueError("external-run entrypoint")
    for key in (
        "executed_entrypoint_sha256", "execution_snapshot_file_digests_sha256",
        "stdout_sha256", "stderr_sha256", "result_artifact_sha256",
    ):
        if not valid_sha256(result.get(key)):
            raise ValueError("external-run result digest")
    for key in ("stdout_bytes", "stderr_bytes", "result_artifact_bytes"):
        if (not isinstance(result.get(key), int) or isinstance(result.get(key), bool)
                or result[key] < 0):
            raise ValueError("external-run result size")
    if result.get("result_artifact_relative") != "builder-test-results.json":
        raise ValueError("external-run result artifact")


class V31ProvenanceTests(unittest.TestCase):
    def test_runner_emits_exact_v31_kind_and_no_stale_literal(self):
        source = (HERE / "run_external.py").read_text("utf-8")
        tree = ast.parse(source)
        strings = {node.value for node in ast.walk(tree)
                   if isinstance(node, ast.Constant) and isinstance(node.value, str)}
        self.assertIn(EXPECTED_KIND, strings)
        self.assertTrue(STALE_KINDS.isdisjoint(strings))

    def test_v27_and_v28_kind_confusion_is_rejected(self):
        for kind in sorted(STALE_KINDS):
            with self.subTest(kind=kind), self.assertRaises(ValueError):
                validate_external_record({"kind": kind})

    def test_complete_binding_record_accepts_and_mutations_reject(self):
        record = self.complete_record()
        validate_external_record(record)
        for path, replacement in [
            (("bindings", "candidate_manifest_sha256"), "f" * 64),
            (("bindings", "authority_roster_sha256"), "f" * 64),
            (("bindings", "authorization_sha256"), "f" * 64),
            (("bindings", "nonce_consumption_receipt_sha256"), "f" * 64),
            (("bindings", "checkpoint_after", "tree_size"), 3),
            (("result", "suite_exit_code"), 1),
            (("result", "candidate_unchanged"), False),
            (("result", "execution_snapshot_unchanged"), False),
            (("result", "stdout_sha256"), "2" * 64),
            (("result", "result_artifact_sha256"), "3" * 64),
        ]:
            mutated = json.loads(json.dumps(record))
            target = mutated
            for key in path[:-1]:
                target = target[key]
            target[path[-1]] = replacement
            with self.subTest(path=path), self.assertRaises(ValueError):
                validate_external_record(mutated)

    def test_recomputed_failed_result_and_binding_still_rejected(self):
        record = self.complete_record()
        for key, replacement in (
            ("suite_exit_code", 1),
            ("candidate_unchanged", False),
            ("execution_snapshot_unchanged", False),
        ):
            mutated = json.loads(json.dumps(record))
            mutated["result"][key] = replacement
            mutated["result_sha256"] = canonical_digest(mutated["result"])
            mutated["bindings"]["result_sha256"] = mutated["result_sha256"]
            mutated["bindings_sha256"] = binding_digest(mutated["bindings"])
            with self.subTest(key=key), self.assertRaises(ValueError):
                validate_external_record(mutated)

    @staticmethod
    def complete_record():
        manifest = "1" * 64
        pin = "2" * 64
        roster = "3" * 64
        authorization = "4" * 64
        request = "5" * 64
        receipt_digest = "6" * 64
        receipt = {"ledger_epoch": "epoch-1", "tree_size": 2,
                   "tree_root_sha256": "7" * 64}
        record = {
            "kind": EXPECTED_KIND, "candidate_generation": "v30",
            "manifest_sha256": manifest, "external_pin_sha256": pin,
            "threshold_authorization": {
                "authority_roster_sha256": roster,
                "authorization_sha256": authorization,
            },
            "nonce_consumption_request_sha256": request,
            "nonce_consumption_receipt_sha256": receipt_digest,
            "nonce_consumption_receipt": receipt,
            "result": {
                "suite_exit_code": 0,
                "candidate_unchanged": True,
                "execution_snapshot_unchanged": True,
                "executed_entrypoint_relative": "test_kernel.py",
                "executed_entrypoint_sha256": "d" * 64,
                "execution_snapshot_file_digests_sha256": "e" * 64,
                "stdout_sha256": "f" * 64,
                "stdout_bytes": 12,
                "stderr_sha256": "0" * 64,
                "stderr_bytes": 0,
                "result_artifact_relative": "builder-test-results.json",
                "result_artifact_sha256": "1" * 64,
                "result_artifact_bytes": 42,
            },
            "bindings": {
                "candidate_generation": "v30",
                "candidate_manifest_sha256": manifest,
                "external_pin_sha256": pin,
                "authority_roster_sha256": roster,
                "authorization_sha256": authorization,
                "nonce_consumption_request_sha256": request,
                "nonce_consumption_receipt_sha256": receipt_digest,
                "checkpoint_before": {"ledger_epoch": "epoch-1", "tree_size": 1,
                                      "tree_root_sha256": "8" * 64},
                "checkpoint_after": receipt,
                "checkpoint_service_bindings": [
                    {"service_id": "a", "custodian_id": "custodian-a",
                     "origin": "https://a.example:443", "tls_leaf_sha256": "9" * 64,
                     "signing_spki_sha256": "a" * 64},
                    {"service_id": "b", "custodian_id": "custodian-b",
                     "origin": "https://b.example:443", "tls_leaf_sha256": "b" * 64,
                     "signing_spki_sha256": "c" * 64},
                ],
            },
        }
        record["result_sha256"] = canonical_digest(record["result"])
        record["bindings"]["result_sha256"] = record["result_sha256"]
        record["bindings_sha256"] = binding_digest(record["bindings"])
        return record


if __name__ == "__main__":
    unittest.main()
