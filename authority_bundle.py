#!/usr/bin/env python3
"""Threshold authorization verification for PGK v35.

This module verifies bytes supplied by independently administered custodians.
It never creates keys, rosters, authorizations, or signatures.
"""
from __future__ import annotations

import base64
import hashlib
import json
import re
from pathlib import Path

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ed25519

DOMAIN = b"PGK-FAILCLOSED-001-V35-AUTHORIZATION\n"
HEX64 = re.compile(r"^[0-9a-f]{64}$")
KEY_ID = re.compile(r"^[a-z0-9][a-z0-9_-]{0,63}$")


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def canonical_bytes(value: object) -> bytes:
    return (json.dumps(value, ensure_ascii=True, sort_keys=True,
                       separators=(",", ":")) + "\n").encode("ascii")


def load_canonical_json(path: Path) -> tuple[dict, bytes]:
    raw = path.resolve(strict=True).read_bytes()
    try:
        value = json.loads(raw.decode("ascii"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ValueError(f"non-canonical JSON: {path.name}") from exc
    if not isinstance(value, dict) or canonical_bytes(value) != raw:
        raise ValueError(f"non-canonical JSON: {path.name}")
    return value, raw


def verify_threshold_authorization(
    *, roster_path: Path, authorization_path: Path, public_key_dir: Path,
    signature_dir: Path, trusted_roster_sha256: str,
    expected_manifest_sha256: str, expected_pin_sha256: str,
    expected_pin_target: str,
) -> dict:
    """Verify a frozen roster and every required custodian signature.

    `trusted_roster_sha256` is a verifier-generation constant, not deployment
    input. Production callers must never obtain it from a CLI argument.
    """
    if not HEX64.fullmatch(trusted_roster_sha256):
        raise ValueError("independent authority roster is not provisioned")
    roster, roster_raw = load_canonical_json(roster_path)
    if sha256_bytes(roster_raw) != trusted_roster_sha256:
        raise ValueError("authority roster is not trusted by this verifier")
    required_roster = {
        "schema_version", "initiative_id", "candidate_generation", "threshold",
        "authorities",
    }
    if set(roster) != required_roster:
        raise ValueError("authority roster fields")
    if (roster["schema_version"] != 1
            or roster["initiative_id"] != "PGK-FAILCLOSED-001"
            or roster["candidate_generation"] != "v35"):
        raise ValueError("authority roster scope")
    authorities = roster["authorities"]
    if not isinstance(authorities, list) or len(authorities) < 2:
        raise ValueError("at least two independent authorities are required")
    if roster["threshold"] != len(authorities):
        raise ValueError("v35 requires unanimous threshold authorization")

    normalized = []
    seen_ids, seen_keys, seen_custodians = set(), set(), set()
    for authority in authorities:
        if not isinstance(authority, dict) or set(authority) != {
                "key_id", "spki_sha256", "custodian_id"}:
            raise ValueError("authority fields")
        key_id = authority["key_id"]
        key_digest = authority["spki_sha256"]
        custodian = authority["custodian_id"]
        if (not isinstance(key_id, str) or not KEY_ID.fullmatch(key_id)
                or not isinstance(key_digest, str) or not HEX64.fullmatch(key_digest)
                or not isinstance(custodian, str) or not KEY_ID.fullmatch(custodian)):
            raise ValueError("authority identity format")
        if key_id in seen_ids or key_digest in seen_keys or custodian in seen_custodians:
            raise ValueError("authorities must have unique keys and custodians")
        seen_ids.add(key_id); seen_keys.add(key_digest); seen_custodians.add(custodian)
        normalized.append((key_id, key_digest, custodian))
    if normalized != sorted(normalized):
        raise ValueError("authorities must be sorted by identity")

    authorization, authorization_raw = load_canonical_json(authorization_path)
    required_auth = {
        "schema_version", "initiative_id", "candidate_generation", "manifest_sha256",
        "external_pin_sha256", "external_pin_target", "release_nonce",
        "authority_roster_sha256",
    }
    if set(authorization) != required_auth:
        raise ValueError("authorization fields")
    if (authorization["schema_version"] != 1
            or authorization["initiative_id"] != "PGK-FAILCLOSED-001"
            or authorization["candidate_generation"] != "v35"
            or authorization["manifest_sha256"] != expected_manifest_sha256
            or authorization["external_pin_sha256"] != expected_pin_sha256
            or authorization["external_pin_target"] != expected_pin_target
            or authorization["authority_roster_sha256"] != trusted_roster_sha256
            or not isinstance(authorization["release_nonce"], str)
            or not HEX64.fullmatch(authorization["release_nonce"])):
        raise ValueError("authorization does not bind exact release")

    public_key_dir = public_key_dir.resolve(strict=True)
    signature_dir = signature_dir.resolve(strict=True)
    message = DOMAIN + authorization_raw
    verified = []
    for key_id, expected_spki, custodian in normalized:
        public_der = (public_key_dir / f"{key_id}.spki.der").read_bytes()
        if sha256_bytes(public_der) != expected_spki:
            raise ValueError(f"authority public key mismatch: {key_id}")
        public_key = serialization.load_der_public_key(public_der)
        if not isinstance(public_key, ed25519.Ed25519PublicKey):
            raise ValueError(f"authority key algorithm: {key_id}")
        try:
            signature = base64.b64decode(
                (signature_dir / f"{key_id}.ed25519.b64").read_text("ascii").strip(),
                validate=True)
            public_key.verify(signature, message)
        except (InvalidSignature, ValueError) as exc:
            raise ValueError(f"authority signature: {key_id}") from exc
        verified.append({"key_id": key_id, "custodian_id": custodian,
                         "spki_sha256": expected_spki})
    return {
        "authority_roster_sha256": trusted_roster_sha256,
        "authorization_sha256": sha256_bytes(authorization_raw),
        "release_nonce": authorization["release_nonce"],
        "threshold": len(normalized),
        "verified_authorities": verified,
    }
