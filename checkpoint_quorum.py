#!/usr/bin/env python3
"""Rollback-resistant external checkpoint quorum for PGK v28.

No local file is authoritative.  Two independently administered, pinned
services must report the same head in response to a fresh challenge and must
then compare-and-swap that exact head to the verified ledger receipt.  Calls
are always made in the configured order: a concurrent sibling cannot obtain
two commits, while a crash or partition can only wedge the gate closed.
"""
from __future__ import annotations

import base64
import hashlib
import http.client
import json
import os
import ssl
import urllib.parse
from dataclasses import dataclass
from pathlib import Path
from typing import Callable

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ed25519


class QuorumReject(Exception):
    pass


HEX64 = set("0123456789abcdef")
DOMAIN = b"PGK-FAILCLOSED-001-V28-CHECKPOINT-RESPONSE\n"


def canonical(value: object) -> bytes:
    return (json.dumps(value, sort_keys=True, separators=(",", ":")) + "\n").encode("ascii")


def digest(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def post_https(url: str, tls_leaf_cert_sha256: str, request_raw: bytes,
               timeout_seconds: int = 20) -> tuple[bytes, str]:
    """POST to an independently pinned service and return signed response."""
    parsed = urllib.parse.urlsplit(url)
    if (parsed.scheme != "https" or not parsed.hostname
            or len(tls_leaf_cert_sha256) != 64
            or any(c not in HEX64 for c in tls_leaf_cert_sha256)):
        raise QuorumReject("checkpoint endpoint is not provisioned")
    connection = http.client.HTTPSConnection(
        parsed.hostname, parsed.port or 443, timeout=timeout_seconds,
        context=ssl.create_default_context())
    try:
        connection.connect()
        if digest(connection.sock.getpeercert(binary_form=True)) != tls_leaf_cert_sha256:
            raise QuorumReject("checkpoint TLS leaf pin")
        connection.request("POST", parsed.path or "/", body=request_raw, headers={
            "Content-Type": "application/json", "Content-Length": str(len(request_raw))})
        response = connection.getresponse()
        body = response.read(1024 * 1024 + 1)
        signature = response.getheader("X-PGK-Checkpoint-Signature")
        if response.status != 200 or len(body) > 1024 * 1024 or not signature:
            raise QuorumReject("checkpoint service response")
        return body, signature
    finally:
        connection.close()


def hex64(value: object, label: str) -> str:
    if not isinstance(value, str) or len(value) != 64 or any(c not in HEX64 for c in value):
        raise QuorumReject(label)
    return value


@dataclass(frozen=True)
class Service:
    service_id: str
    custodian_id: str
    endpoint_origin: str
    tls_leaf_cert_sha256: str
    public_key_path: Path
    public_key_spki_sha256: str
    post: Callable[[bytes], tuple[bytes, str]]


def _origin(value: str) -> str:
    """Return one canonical HTTPS origin; paths/userinfo/fragments are forbidden."""
    parsed = urllib.parse.urlsplit(value)
    if (parsed.scheme != "https" or not parsed.hostname or parsed.username is not None
            or parsed.password is not None or parsed.path not in ("", "/")
            or parsed.query or parsed.fragment):
        raise QuorumReject("checkpoint endpoint origin")
    hostname = parsed.hostname.lower()
    port = parsed.port or 443
    return f"https://{hostname}:{port}"


def validate_services(services: tuple[Service, ...]) -> None:
    """Reject quorum identity aliases before contacting any member."""
    if len(services) < 2:
        raise QuorumReject("checkpoint quorum requires at least two services")
    identities = {
        "service ids": [s.service_id for s in services],
        "custodians": [s.custodian_id for s in services],
        "signing keys": [hex64(s.public_key_spki_sha256, "checkpoint SPKI pin")
                         for s in services],
        "TLS pins": [hex64(s.tls_leaf_cert_sha256, "checkpoint TLS pin")
                     for s in services],
        "endpoint origins": [_origin(s.endpoint_origin) for s in services],
    }
    for label, values in identities.items():
        if (any(not isinstance(v, str) or not v for v in values)
                or len(set(values)) != len(values)):
            raise QuorumReject(f"checkpoint quorum requires distinct {label}")


def _key(service: Service) -> ed25519.Ed25519PublicKey:
    raw = service.public_key_path.resolve(strict=True).read_bytes()
    try:
        key = serialization.load_pem_public_key(raw)
        spki = key.public_bytes(serialization.Encoding.DER,
                                serialization.PublicFormat.SubjectPublicKeyInfo)
    except (ValueError, TypeError) as exc:
        raise QuorumReject("checkpoint service public key") from exc
    if not isinstance(key, ed25519.Ed25519PublicKey) or digest(spki) != service.public_key_spki_sha256:
        raise QuorumReject("checkpoint service public key pin")
    return key


def _call(service: Service, request: dict) -> dict:
    request_raw = canonical(request)
    response_raw, signature_b64 = service.post(request_raw)
    try:
        response = json.loads(response_raw.decode("ascii"))
        if canonical(response) != response_raw:
            raise QuorumReject("checkpoint response canonical form")
        signature = base64.b64decode(signature_b64.strip(), validate=True)
        _key(service).verify(signature, DOMAIN + response_raw)
    except (UnicodeDecodeError, json.JSONDecodeError, ValueError,
            InvalidSignature) as exc:
        raise QuorumReject("checkpoint response authentication") from exc
    if (not isinstance(response, dict)
            or response.get("service_id") != service.service_id
            or response.get("request_sha256") != digest(request_raw)
            or response.get("challenge") != request.get("challenge")):
        raise QuorumReject("checkpoint response request binding")
    return response


def read_current(services: tuple[Service, ...], ledger_epoch: str) -> dict:
    """Read one fresh, unanimous head; signed old responses cannot be replayed."""
    validate_services(services)
    challenge = os.urandom(32).hex()
    request = {"schema_version": 1, "operation": "CURRENT",
               "challenge": challenge, "ledger_epoch": hex64(ledger_epoch, "epoch")}
    heads = []
    expected_fields = {"schema_version", "operation", "service_id", "request_sha256",
                       "challenge", "ledger_epoch", "tree_size", "tree_root_sha256"}
    for service in services:
        response = _call(service, request)
        if (set(response) != expected_fields or response["schema_version"] != 1
                or response["operation"] != "CURRENT"
                or response["ledger_epoch"] != ledger_epoch
                or not isinstance(response["tree_size"], int)
                or isinstance(response["tree_size"], bool) or response["tree_size"] < 1):
            raise QuorumReject("checkpoint current schema")
        heads.append((response["tree_size"],
                      hex64(response["tree_root_sha256"], "checkpoint root")))
    if len(set(heads)) != 1:
        raise QuorumReject("checkpoint split view")
    return {"ledger_epoch": ledger_epoch, "tree_size": heads[0][0],
            "tree_root_sha256": heads[0][1]}


def commit(services: tuple[Service, ...], before: dict, receipt_raw: bytes,
           receipt: dict) -> dict:
    """Require ordered unanimous CAS commits for the already verified receipt."""
    validate_services(services)
    if (receipt.get("ledger_epoch") != before.get("ledger_epoch")
            or receipt.get("prior_tree_size") != before.get("tree_size")
            or receipt.get("prior_tree_root_sha256") != before.get("tree_root_sha256")
            or not isinstance(receipt.get("tree_size"), int)
            or receipt["tree_size"] <= before["tree_size"]):
        raise QuorumReject("receipt is not current-head successor")
    challenge = os.urandom(32).hex()
    request = {"schema_version": 1, "operation": "COMMIT", "challenge": challenge,
               "ledger_epoch": before["ledger_epoch"],
               "prior_tree_size": before["tree_size"],
               "prior_tree_root_sha256": before["tree_root_sha256"],
               "tree_size": receipt["tree_size"],
               "tree_root_sha256": hex64(receipt.get("tree_root_sha256"), "receipt root"),
               "receipt_sha256": digest(receipt_raw)}
    expected_fields = set(request) | {"service_id", "request_sha256", "result"}
    for service in services:  # fixed order is a safety property
        response = _call(service, request)
        if (set(response) != expected_fields or response["schema_version"] != 1
                or response["operation"] != "COMMIT"
                or response["result"] != "COMMITTED"
                or any(response.get(k) != v for k, v in request.items())):
            raise QuorumReject("checkpoint commit rejected")
    return {"ledger_epoch": before["ledger_epoch"], "tree_size": receipt["tree_size"],
            "tree_root_sha256": receipt["tree_root_sha256"]}
