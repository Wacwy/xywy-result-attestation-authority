#!/usr/bin/env python3
"""Closed-schema validator for authority-observed PGK v35 run records."""
from __future__ import annotations

import hashlib
import json
import re
from pathlib import Path

HEX64 = re.compile(r"^[0-9a-f]{64}$")
HTTPS = re.compile(r"^https://[^\s]+$")
KIND = "PGKv35AuthorityObservedExternalRun"
RESULT_FIELDS = {
    "suite_exit_code", "candidate_unchanged", "execution_snapshot_unchanged",
    "executed_entrypoint_relative", "executed_entrypoint_sha256",
    "execution_snapshot_file_digests_sha256", "stdout_sha256", "stdout_bytes",
    "stderr_sha256", "stderr_bytes", "result_artifact_relative",
    "result_artifact_sha256", "result_artifact_bytes",
}
BINDING_FIELDS = {
    "candidate_generation", "candidate_manifest_sha256",
    "execution_manifest_sha256", "external_pin_sha256",
    "authority_roster_sha256", "authorization_sha256",
    "nonce_consumption_request_sha256", "nonce_consumption_receipt_sha256",
    "checkpoint_before", "checkpoint_after", "checkpoint_service_bindings",
    "result_sha256",
}
CHECKPOINT_FIELDS = {"ledger_epoch", "tree_size", "tree_root_sha256"}
SERVICE_FIELDS = {"service_id", "custodian_id", "origin", "tls_leaf_sha256",
                  "signing_spki_sha256"}


def canonical(value: object) -> bytes:
    return (json.dumps(value, ensure_ascii=True, sort_keys=True,
                       separators=(",", ":")) + "\n").encode("ascii")


def digest(value: object) -> str:
    return hashlib.sha256(canonical(value)).hexdigest()


def _hex(value: object, label: str) -> str:
    if not isinstance(value, str) or not HEX64.fullmatch(value):
        raise ValueError(label)
    return value


def _checkpoint(value: object, label: str) -> dict:
    if not isinstance(value, dict) or set(value) != CHECKPOINT_FIELDS:
        raise ValueError(label)
    _hex(value["ledger_epoch"], label)
    _hex(value["tree_root_sha256"], label)
    if (not isinstance(value["tree_size"], int) or isinstance(value["tree_size"], bool)
            or value["tree_size"] < 0):
        raise ValueError(label)
    return value


def validate_record(record: object, *, expected_manifest_files: dict[str, str]) -> dict:
    if (not isinstance(expected_manifest_files, dict) or not expected_manifest_files
            or any(not isinstance(name, str) or not name or not HEX64.fullmatch(value)
                   for name, value in expected_manifest_files.items())):
        raise ValueError("expected manifest file map")
    if not isinstance(record, dict):
        raise ValueError("record object")
    required = {"schema_version", "kind", "candidate_generation",
                "external_pin_manifest_sha256", "manifest_sha256",
                "execution_manifest_sha256",
                "threshold_authorization", "nonce_consumption_receipt",
                "nonce_consumption_request_sha256",
                "nonce_consumption_receipt_sha256",
                "execution_snapshot_file_digests", "result", "result_sha256",
                "bindings", "bindings_sha256"}
    if set(record) != required or record["schema_version"] != 1 \
            or record["kind"] != KIND or record["candidate_generation"] != "v35":
        raise ValueError("record scope or fields")
    manifest = _hex(record["manifest_sha256"], "manifest digest")
    execution_manifest = _hex(record["execution_manifest_sha256"],
                              "execution manifest digest")
    if record["external_pin_manifest_sha256"] != manifest:
        raise ValueError("external pin manifest binding")
    authority = record["threshold_authorization"]
    if (not isinstance(authority, dict)
            or set(authority) != {"authority_roster_sha256", "authorization_sha256",
                                  "release_nonce", "threshold", "verified_authorities"}
            or authority["threshold"] != 2
            or not isinstance(authority["verified_authorities"], list)
            or len(authority["verified_authorities"]) != 2):
        raise ValueError("threshold authority")
    for field in ("authority_roster_sha256", "authorization_sha256", "release_nonce"):
        _hex(authority[field], field)
    ids, custodians, keys = set(), set(), set()
    for item in authority["verified_authorities"]:
        if (not isinstance(item, dict)
                or set(item) != {"key_id", "custodian_id", "spki_sha256"}):
            raise ValueError("authority member")
        ids.add(item["key_id"]); custodians.add(item["custodian_id"])
        keys.add(_hex(item["spki_sha256"], "authority key"))
    if len(ids) != 2 or len(custodians) != 2 or len(keys) != 2:
        raise ValueError("independent authorities")
    request_digest = _hex(record["nonce_consumption_request_sha256"], "request")
    receipt_digest = _hex(record["nonce_consumption_receipt_sha256"], "receipt")
    receipt = record["nonce_consumption_receipt"]
    receipt_required = {"schema_version", "initiative_id", "candidate_generation",
        "authorization_sha256", "release_nonce", "manifest_sha256",
        "authority_roster_sha256", "client_challenge", "result", "ledger_epoch",
        "tree_size", "tree_root_sha256", "consumed_record_sha256", "leaf_index",
        "inclusion_path_sha256", "prior_tree_size", "prior_tree_root_sha256",
        "consistency_path_sha256"}
    if not isinstance(receipt, dict) or set(receipt) != receipt_required:
        raise ValueError("receipt fields")
    if (receipt["schema_version"] != 1 or receipt["initiative_id"] != "PGK-FAILCLOSED-001"
            or receipt["candidate_generation"] != "v35" or receipt["result"] != "CONSUMED"
            or receipt["authorization_sha256"] != authority["authorization_sha256"]
            or receipt["authority_roster_sha256"] != authority["authority_roster_sha256"]
            or receipt["manifest_sha256"] != manifest
            or receipt["release_nonce"] != authority["release_nonce"]):
        raise ValueError("receipt binding")
    if digest({key: receipt[key] for key in ("schema_version", "initiative_id",
            "candidate_generation", "authorization_sha256", "release_nonce", "manifest_sha256",
            "authority_roster_sha256", "client_challenge")}) != request_digest:
        raise ValueError("request digest binding")
    if hashlib.sha256(canonical(receipt)).hexdigest() != receipt_digest:
        raise ValueError("receipt digest binding")
    result = record["result"]
    if not isinstance(result, dict) or set(result) != RESULT_FIELDS:
        raise ValueError("result fields")
    result_digest = digest(result)
    if record["result_sha256"] != result_digest:
        raise ValueError("result digest")
    if (result["suite_exit_code"] != 0 or result["candidate_unchanged"] is not True
            or result["execution_snapshot_unchanged"] is not True
            or result["executed_entrypoint_relative"] != "test_kernel.py"
            or result["result_artifact_relative"] != "builder-test-results.json"):
        raise ValueError("run outcome")
    for field in ("executed_entrypoint_sha256", "execution_snapshot_file_digests_sha256",
                  "stdout_sha256", "stderr_sha256", "result_artifact_sha256"):
        _hex(result[field], field)
    for field in ("stdout_bytes", "stderr_bytes", "result_artifact_bytes"):
        if not isinstance(result[field], int) or isinstance(result[field], bool) or result[field] < 0:
            raise ValueError(field)
    snapshot = record["execution_snapshot_file_digests"]
    if (not isinstance(snapshot, dict) or snapshot != expected_manifest_files
            or any(not isinstance(name, str) or not name or not HEX64.fullmatch(value)
                   for name, value in snapshot.items())
            or digest(snapshot) != result["execution_snapshot_file_digests_sha256"]
            or snapshot.get("test_kernel.py") != result["executed_entrypoint_sha256"]):
        raise ValueError("snapshot binding")
    bindings = record["bindings"]
    if not isinstance(bindings, dict) or set(bindings) != BINDING_FIELDS:
        raise ValueError("binding fields")
    if record["bindings_sha256"] != digest(bindings):
        raise ValueError("binding digest")
    for field in ("candidate_manifest_sha256", "execution_manifest_sha256",
                  "external_pin_sha256",
                  "authority_roster_sha256", "authorization_sha256",
                  "nonce_consumption_request_sha256", "nonce_consumption_receipt_sha256",
                  "result_sha256"):
        _hex(bindings[field], field)
    expected = {"candidate_generation": "v35", "candidate_manifest_sha256": manifest,
        "execution_manifest_sha256": execution_manifest,
        "authority_roster_sha256": authority["authority_roster_sha256"],
        "authorization_sha256": authority["authorization_sha256"],
        "nonce_consumption_request_sha256": request_digest,
        "nonce_consumption_receipt_sha256": receipt_digest, "result_sha256": result_digest}
    if any(bindings[key] != value for key, value in expected.items()):
        raise ValueError("semantic binding")
    before = _checkpoint(bindings["checkpoint_before"], "checkpoint before")
    after = _checkpoint(bindings["checkpoint_after"], "checkpoint after")
    if (after["ledger_epoch"] != before["ledger_epoch"]
            or after["tree_size"] <= before["tree_size"]
            or after["ledger_epoch"] != receipt["ledger_epoch"]
            or after["tree_size"] != receipt["tree_size"]
            or after["tree_root_sha256"] != receipt["tree_root_sha256"]
            or before["tree_size"] != receipt["prior_tree_size"]
            or before["tree_root_sha256"] != receipt["prior_tree_root_sha256"]):
        raise ValueError("monotonic checkpoint transition")
    services = bindings["checkpoint_service_bindings"]
    if not isinstance(services, list) or len(services) != 2:
        raise ValueError("checkpoint service quorum")
    service_ids, service_custodians, origins, tls, spki = set(), set(), set(), set(), set()
    for service in services:
        if not isinstance(service, dict) or set(service) != SERVICE_FIELDS:
            raise ValueError("checkpoint service fields")
        if not isinstance(service["origin"], str) or not HTTPS.fullmatch(service["origin"]):
            raise ValueError("checkpoint service origin")
        service_ids.add(service["service_id"]); service_custodians.add(service["custodian_id"])
        origins.add(service["origin"]); tls.add(_hex(service["tls_leaf_sha256"], "TLS pin"))
        spki.add(_hex(service["signing_spki_sha256"], "service SPKI"))
    if any(len(values) != 2 for values in (service_ids, service_custodians, origins, tls, spki)):
        raise ValueError("independent checkpoint services")
    return record


def load_and_validate(path: Path, *, expected_manifest_files: dict[str, str]) -> tuple[dict, bytes]:
    raw = path.resolve(strict=True).read_bytes()
    try:
        value = json.loads(raw.decode("ascii"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ValueError("record JSON") from exc
    if raw != canonical(value):
        raise ValueError("record canonical form")
    return validate_record(value, expected_manifest_files=expected_manifest_files), raw
