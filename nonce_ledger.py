#!/usr/bin/env python3
"""Client and receipt verifier for the externally administered v35 nonce ledger.

The builder owns no ledger key and cannot provision the constants used by the
production runner.  A successful response is bound to a fresh client challenge
and is co-signed by the ledger and an independent append-only-log witness.
"""
from __future__ import annotations

import base64
import hashlib
import http.client
import json
import os
import re
import ssl
import urllib.parse
from pathlib import Path

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ed25519

REQUEST_DOMAIN = b"PGK-FAILCLOSED-001-V26-NONCE-CONSUME-REQUEST\n"
RECEIPT_DOMAIN = b"PGK-FAILCLOSED-001-V26-NONCE-CONSUME-RECEIPT\n"
INCLUSION_DOMAIN = b"PGK-FAILCLOSED-001-V35-LOG-INCLUSION\n"
CONSISTENCY_LEAF_DOMAIN = INCLUSION_DOMAIN
HEX64 = re.compile(r"^[0-9a-f]{64}$")
HTTPS_URL = re.compile(r"^https://[^/?#]+/[^?#]+$")


class LedgerReject(Exception):
    pass


class LedgerReplay(LedgerReject):
    pass


def canonical_bytes(value: object) -> bytes:
    return (json.dumps(value, ensure_ascii=True, sort_keys=True,
                       separators=(",", ":")) + "\n").encode("ascii")


def sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _leaf_hash(record_sha256: str) -> bytes:
    return hashlib.sha256(INCLUSION_DOMAIN + bytes.fromhex(record_sha256)).digest()


def _expected_consumed_record(request: dict) -> str:
    """Bind the leaf to the exact canonical consume request."""
    return sha256(REQUEST_DOMAIN + canonical_bytes(request))


def verify_inclusion_proof(*, record_sha256: str, leaf_index: int,
                           tree_size: int, audit_path: list[str],
                           expected_root_sha256: str) -> None:
    """Verify an RFC6962-style Merkle inclusion proof with domain separation.

    This makes the witnessed checkpoint cryptographically meaningful: the
    consumed record must be an actual leaf in the signed tree, rather than a
    self-declared digest merely co-signed by ledger and witness.
    """
    if (not isinstance(record_sha256, str) or not HEX64.fullmatch(record_sha256)
            or not isinstance(leaf_index, int) or isinstance(leaf_index, bool)
            or not isinstance(tree_size, int) or isinstance(tree_size, bool)
            or tree_size < 1 or leaf_index < 0 or leaf_index >= tree_size
            or not isinstance(audit_path, list)
            or not all(isinstance(item, str) and HEX64.fullmatch(item)
                       for item in audit_path)
            or not isinstance(expected_root_sha256, str)
            or not HEX64.fullmatch(expected_root_sha256)):
        raise LedgerReject("nonce-ledger inclusion proof format")
    node = _leaf_hash(record_sha256)
    index = leaf_index
    last = tree_size - 1
    consumed = 0
    while last:
        if consumed >= len(audit_path):
            raise LedgerReject("nonce-ledger inclusion proof incomplete")
        sibling = bytes.fromhex(audit_path[consumed])
        consumed += 1
        if index & 1:
            node = hashlib.sha256(b"\x01" + sibling + node).digest()
        elif index < last:
            node = hashlib.sha256(b"\x01" + node + sibling).digest()
        else:
            consumed -= 1
        index >>= 1
        last >>= 1
    if consumed != len(audit_path) or node.hex() != expected_root_sha256:
        raise LedgerReject("nonce-ledger inclusion proof")


def verify_consistency_proof(*, old_tree_size: int, new_tree_size: int,
                             old_root_sha256: str, new_root_sha256: str,
                             audit_path: list[str]) -> None:
    """Verify an RFC6962 consistency proof between trusted checkpoints.

    The prior checkpoint is verifier input, not response data.  Equal-size
    checkpoints must have the exact same root and an empty proof, which closes
    the v24 same-epoch split-view acceptance.  Growth requires a standard
    history consistency proof and therefore cannot rewrite any prior leaf.
    """
    if (not isinstance(old_tree_size, int) or isinstance(old_tree_size, bool)
            or not isinstance(new_tree_size, int) or isinstance(new_tree_size, bool)
            or old_tree_size < 1 or new_tree_size < old_tree_size
            or not isinstance(old_root_sha256, str)
            or not HEX64.fullmatch(old_root_sha256)
            or not isinstance(new_root_sha256, str)
            or not HEX64.fullmatch(new_root_sha256)
            or not isinstance(audit_path, list)
            or not all(isinstance(item, str) and HEX64.fullmatch(item)
                       for item in audit_path)):
        raise LedgerReject("nonce-ledger consistency proof format")
    if old_tree_size == new_tree_size:
        if audit_path or old_root_sha256 != new_root_sha256:
            raise LedgerReject("nonce-ledger checkpoint equivocation")
        return

    # RFC6962 2.1.2 iterative verifier.  When the old tree size is a power of
    # two, its root is the initial accumulator; otherwise the first proof node
    # initializes both old and new accumulators.
    fn = old_tree_size - 1
    sn = new_tree_size - 1
    while fn & 1:
        fn >>= 1
        sn >>= 1
    proof = [bytes.fromhex(item) for item in audit_path]
    if fn == 0:
        fr = sr = bytes.fromhex(old_root_sha256)
    else:
        if not proof:
            raise LedgerReject("nonce-ledger consistency proof incomplete")
        fr = sr = proof.pop(0)
    for sibling in proof:
        if sn == 0:
            raise LedgerReject("nonce-ledger consistency proof excess")
        if (fn & 1) or fn == sn:
            fr = hashlib.sha256(b"\x01" + sibling + fr).digest()
            sr = hashlib.sha256(b"\x01" + sibling + sr).digest()
            while fn and not (fn & 1):
                fn >>= 1
                sn >>= 1
        else:
            sr = hashlib.sha256(b"\x01" + sr + sibling).digest()
        fn >>= 1
        sn >>= 1
    if (sn != 0 or fr.hex() != old_root_sha256
            or sr.hex() != new_root_sha256):
        raise LedgerReject("nonce-ledger consistency proof")


def _public_key(path: Path, expected_spki_sha256: str) -> ed25519.Ed25519PublicKey:
    if not HEX64.fullmatch(expected_spki_sha256):
        raise LedgerReject("nonce-ledger verifier key is not provisioned")
    raw = path.resolve(strict=True).read_bytes()
    if sha256(raw) != expected_spki_sha256:
        raise LedgerReject("nonce-ledger verifier key pin")
    key = serialization.load_der_public_key(raw)
    if not isinstance(key, ed25519.Ed25519PublicKey):
        raise LedgerReject("nonce-ledger verifier key algorithm")
    return key


def build_request(*, authorization_sha256: str, release_nonce: str,
                  manifest_sha256: str, authority_roster_sha256: str,
                  challenge: bytes | None = None) -> tuple[dict, bytes]:
    values = (authorization_sha256, release_nonce, manifest_sha256,
              authority_roster_sha256)
    if not all(isinstance(item, str) and HEX64.fullmatch(item) for item in values):
        raise LedgerReject("nonce-ledger request digest")
    challenge = os.urandom(32) if challenge is None else challenge
    if not isinstance(challenge, bytes) or len(challenge) != 32:
        raise LedgerReject("nonce-ledger client challenge")
    request = {
        "schema_version": 1,
        "initiative_id": "PGK-FAILCLOSED-001",
        "candidate_generation": "v35",
        "authorization_sha256": authorization_sha256,
        "release_nonce": release_nonce,
        "manifest_sha256": manifest_sha256,
        "authority_roster_sha256": authority_roster_sha256,
        "client_challenge": challenge.hex(),
    }
    return request, canonical_bytes(request)


def verify_consumption_receipt(*, request: dict, receipt_raw: bytes,
                               ledger_signature_b64: str,
                               witness_signature_b64: str,
                               ledger_public_key_path: Path,
                               witness_public_key_path: Path,
                               trusted_ledger_spki_sha256: str,
                               trusted_witness_spki_sha256: str,
                               trusted_ledger_epoch: str,
                               trusted_prior_tree_size: int,
                               trusted_prior_root_sha256: str) -> dict:
    try:
        receipt = json.loads(receipt_raw.decode("ascii"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise LedgerReject("nonce-ledger receipt JSON") from exc
    if not isinstance(receipt, dict) or canonical_bytes(receipt) != receipt_raw:
        raise LedgerReject("nonce-ledger receipt canonical form")
    fields = set(request) | {
        "result", "ledger_epoch", "tree_size", "tree_root_sha256",
        "consumed_record_sha256", "leaf_index", "inclusion_path_sha256",
        "prior_tree_size", "prior_tree_root_sha256", "consistency_path_sha256",
    }
    if set(receipt) != fields or any(receipt.get(k) != v for k, v in request.items()):
        raise LedgerReject("nonce-ledger receipt request binding")
    if receipt["result"] == "ALREADY_CONSUMED":
        raise LedgerReplay("release nonce already consumed")
    if receipt["result"] != "CONSUMED":
        raise LedgerReject("nonce-ledger result")
    if receipt["consumed_record_sha256"] != _expected_consumed_record(request):
        raise LedgerReject("nonce-ledger consumed record binding")
    if (receipt["ledger_epoch"] != trusted_ledger_epoch
            or not HEX64.fullmatch(trusted_ledger_epoch)):
        raise LedgerReject("nonce-ledger epoch")
    if (not isinstance(receipt["tree_size"], int) or isinstance(receipt["tree_size"], bool)
            or receipt["tree_size"] < 1
            or not isinstance(receipt["tree_root_sha256"], str)
            or not HEX64.fullmatch(receipt["tree_root_sha256"])
            or not isinstance(receipt["consumed_record_sha256"], str)
            or not HEX64.fullmatch(receipt["consumed_record_sha256"])
            or not isinstance(receipt["leaf_index"], int)
            or isinstance(receipt["leaf_index"], bool)
            or not isinstance(receipt["inclusion_path_sha256"], list)):
        raise LedgerReject("nonce-ledger append-only checkpoint")
    if (receipt["prior_tree_size"] != trusted_prior_tree_size
            or receipt["prior_tree_root_sha256"] != trusted_prior_root_sha256):
        raise LedgerReject("nonce-ledger prior checkpoint binding")
    verify_consistency_proof(
        old_tree_size=trusted_prior_tree_size,
        new_tree_size=receipt["tree_size"],
        old_root_sha256=trusted_prior_root_sha256,
        new_root_sha256=receipt["tree_root_sha256"],
        audit_path=receipt["consistency_path_sha256"],
    )
    verify_inclusion_proof(
        record_sha256=receipt["consumed_record_sha256"],
        leaf_index=receipt["leaf_index"], tree_size=receipt["tree_size"],
        audit_path=receipt["inclusion_path_sha256"],
        expected_root_sha256=receipt["tree_root_sha256"],
    )
    message = RECEIPT_DOMAIN + receipt_raw
    for name, signature_text, key_path, key_pin in (
        ("ledger", ledger_signature_b64, ledger_public_key_path,
         trusted_ledger_spki_sha256),
        ("witness", witness_signature_b64, witness_public_key_path,
         trusted_witness_spki_sha256),
    ):
        try:
            signature = base64.b64decode(signature_text.strip(), validate=True)
            _public_key(key_path, key_pin).verify(signature, message)
        except (InvalidSignature, ValueError) as exc:
            raise LedgerReject(f"nonce-ledger {name} signature") from exc
    return receipt


def consume_once_https(*, url: str, tls_leaf_cert_sha256: str, request_raw: bytes,
                       timeout_seconds: int = 20) -> tuple[bytes, str, str]:
    """POST through a leaf-certificate-pinned TLS channel.

    The response body is canonical receipt JSON.  Signatures are transported
    in headers and then cryptographically checked by the caller.
    """
    if not HTTPS_URL.fullmatch(url) or not HEX64.fullmatch(tls_leaf_cert_sha256):
        raise LedgerReject("nonce-ledger endpoint is not provisioned")
    parsed = urllib.parse.urlsplit(url)
    context = ssl.create_default_context()
    connection = http.client.HTTPSConnection(parsed.hostname, parsed.port or 443,
                                              timeout=timeout_seconds,
                                              context=context)
    try:
        connection.connect()
        cert = connection.sock.getpeercert(binary_form=True)
        if sha256(cert) != tls_leaf_cert_sha256:
            raise LedgerReject("nonce-ledger TLS leaf pin")
        connection.request("POST", parsed.path, body=request_raw, headers={
            "Content-Type": "application/json",
            "Content-Length": str(len(request_raw)),
        })
        response = connection.getresponse()
        body = response.read(1024 * 1024 + 1)
        if response.status != 200 or len(body) > 1024 * 1024:
            raise LedgerReject(f"nonce-ledger HTTP status {response.status}")
        ledger_sig = response.getheader("X-PGK-Ledger-Signature")
        witness_sig = response.getheader("X-PGK-Witness-Signature")
        if not ledger_sig or not witness_sig:
            raise LedgerReject("nonce-ledger signatures missing")
        return body, ledger_sig, witness_sig
    finally:
        connection.close()
