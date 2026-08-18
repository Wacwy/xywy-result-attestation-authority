#!/usr/bin/env python3
"""Strict offline verifier for a roster published by one TUF custodian.

This module intentionally creates no keys and trusts no caller-provided root
digest. A production generation must replace TRUSTED_TUF_ROOT_SHA256 with the
digest of root.json after the configured custodian publishes it.
"""
from __future__ import annotations

import base64
import hashlib
import json
import re
from datetime import datetime, timezone
from pathlib import Path

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric import ed25519

HEX64 = re.compile(r"^[0-9a-f]{64}$")
KEY_ID = re.compile(r"^[a-z0-9][a-z0-9_-]{0,63}$")
TRUSTED_TUF_ROOT_SHA256 = "UNPROVISIONED_EXTERNAL_TUF_ROOT"
TRUSTED_TUF_TARGETS_SHA256 = "UNPROVISIONED_EXTERNAL_TUF_TARGETS"


def canonical(value: object) -> bytes:
    return (json.dumps(value, ensure_ascii=True, sort_keys=True,
                       separators=(",", ":")) + "\n").encode("ascii")


def load_canonical(path: Path) -> tuple[dict, bytes]:
    raw = path.resolve(strict=True).read_bytes()
    try:
        value = json.loads(raw.decode("ascii"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ValueError("non-canonical TUF metadata") from exc
    if not isinstance(value, dict) or raw != canonical(value):
        raise ValueError("non-canonical TUF metadata")
    return value, raw


def _sha(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def _require_live_expiry(value: object, now: datetime) -> None:
    if not isinstance(value, str) or not value.endswith("Z"):
        raise ValueError("TUF expiry format")
    try:
        expires = datetime.fromisoformat(value[:-1] + "+00:00")
    except ValueError as exc:
        raise ValueError("TUF expiry format") from exc
    if expires.tzinfo is None or expires <= now.astimezone(timezone.utc):
        raise ValueError("TUF metadata expired")


def _verify_envelope(envelope: dict, keys: dict, role: dict) -> dict:
    if set(envelope) != {"signatures", "signed"}:
        raise ValueError("TUF envelope fields")
    signed = envelope["signed"]
    signatures = envelope["signatures"]
    if not isinstance(signed, dict) or not isinstance(signatures, list):
        raise ValueError("TUF envelope types")
    message = canonical(signed)
    accepted = set()
    for item in signatures:
        if not isinstance(item, dict) or set(item) != {"keyid", "sig"}:
            raise ValueError("TUF signature fields")
        keyid = item["keyid"]
        if keyid in accepted or keyid not in role["keyids"]:
            continue
        try:
            signature = base64.b64decode(item["sig"], validate=True)
            public = base64.b64decode(keys[keyid]["keyval"]["public"], validate=True)
            ed25519.Ed25519PublicKey.from_public_bytes(public).verify(
                signature, message)
        except (KeyError, ValueError, InvalidSignature) as exc:
            raise ValueError(f"invalid TUF signature: {keyid}") from exc
        accepted.add(keyid)
    if len(accepted) < role["threshold"]:
        raise ValueError("TUF signature threshold")
    return signed


def verify_roster(*, root_path: Path, targets_path: Path,
                  roster_path: Path, trusted_root_sha256: str =
                  TRUSTED_TUF_ROOT_SHA256, trusted_targets_sha256: str =
                  TRUSTED_TUF_TARGETS_SHA256, now: datetime | None = None) -> dict:
    if (not isinstance(trusted_root_sha256, str)
            or not isinstance(trusted_targets_sha256, str)
            or not HEX64.fullmatch(trusted_root_sha256)
            or not HEX64.fullmatch(trusted_targets_sha256)):
        raise ValueError("external TUF root/targets are not provisioned")
    if now is None:
        now = datetime.now(timezone.utc)
    if now.tzinfo is None:
        raise ValueError("TUF verifier time must be timezone-aware")
    root, root_raw = load_canonical(root_path)
    if _sha(root_raw) != trusted_root_sha256:
        raise ValueError("TUF root is not trusted by this verifier")
    if set(root) != {"signatures", "signed"}:
        raise ValueError("TUF root envelope fields")
    signed = root["signed"]
    if set(signed) != {"_type", "expires", "keys", "roles", "spec_version", "version"}:
        raise ValueError("TUF root fields")
    if (signed["_type"] != "root" or signed["spec_version"] != "1.0.31"
            or not isinstance(signed["version"], int)
            or isinstance(signed["version"], bool) or signed["version"] < 1):
        raise ValueError("TUF root scope")
    _require_live_expiry(signed["expires"], now)
    keys, roles = signed["keys"], signed["roles"]
    if not isinstance(keys, dict):
        raise ValueError("TUF keys")
    if not isinstance(roles, dict) or set(roles) != {"root", "targets"}:
        raise ValueError("TUF roles")
    for keyid, key in keys.items():
        if (not isinstance(keyid, str) or not KEY_ID.fullmatch(keyid)
                or not isinstance(key, dict)
                or set(key) != {"keytype", "scheme", "keyval"}
                or key["keytype"] != "ed25519" or key["scheme"] != "ed25519"
                or not isinstance(key["keyval"], dict)
                or set(key["keyval"]) != {"public"}
                or not isinstance(key["keyval"]["public"], str)):
            raise ValueError("TUF key")
        try:
            if len(base64.b64decode(key["keyval"]["public"], validate=True)) != 32:
                raise ValueError("TUF public key length")
        except (TypeError, ValueError) as exc:
            raise ValueError("TUF public key") from exc
    for name in ("root", "targets"):
        role = roles[name]
        if (not isinstance(role, dict) or set(role) != {"keyids", "threshold"}
                or not isinstance(role["keyids"], list)
                or len(role["keyids"]) != 1
                or any(not isinstance(keyid, str)
                       or not KEY_ID.fullmatch(keyid)
                       for keyid in role["keyids"])
                or not isinstance(role["threshold"], int)
                or isinstance(role["threshold"], bool)
                or role["threshold"] != 1
                or len(set(role["keyids"])) != 1
                or any(keyid not in keys for keyid in role["keyids"])):
            raise ValueError(f"TUF {name} must be exact 1-of-1")
    if roles["root"]["keyids"] != roles["targets"]["keyids"]:
        raise ValueError("TUF root and targets must use the same sole custodian key")
    sole_custodian_key = roles["root"]["keyids"][0]
    if set(keys) != {sole_custodian_key}:
        raise ValueError("TUF root must contain exactly the sole custodian key")
    _verify_envelope(root, keys, roles["root"])

    targets, targets_raw = load_canonical(targets_path)
    if _sha(targets_raw) != trusted_targets_sha256:
        raise ValueError("TUF targets are not trusted by this verifier")
    targets_signed = _verify_envelope(targets, keys, roles["targets"])
    if set(targets_signed) != {"_type", "expires", "spec_version", "targets", "version"}:
        raise ValueError("TUF targets fields")
    if (targets_signed["_type"] != "targets"
            or targets_signed["spec_version"] != "1.0.31"
            or not isinstance(targets_signed["version"], int)
            or isinstance(targets_signed["version"], bool)
            or targets_signed["version"] < 1):
        raise ValueError("TUF targets scope")
    _require_live_expiry(targets_signed["expires"], now)
    targets_map = targets_signed["targets"]
    if not isinstance(targets_map, dict):
        raise ValueError("TUF targets map")
    target = targets_map.get("authority-roster.json")
    if (not isinstance(target, dict) or set(target) != {"hashes", "length"}
            or not isinstance(target["hashes"], dict)
            or set(target["hashes"]) != {"sha256"}
            or not isinstance(target["hashes"]["sha256"], str)
            or not HEX64.fullmatch(target["hashes"]["sha256"])
            or not isinstance(target["length"], int)
            or isinstance(target["length"], bool) or target["length"] < 0):
        raise ValueError("TUF roster target")
    roster_raw = roster_path.resolve(strict=True).read_bytes()
    if len(roster_raw) != target["length"] or _sha(roster_raw) != target["hashes"]["sha256"]:
        raise ValueError("TUF roster target mismatch")
    roster, _ = load_canonical(roster_path)
    if (set(roster) != {"schema_version", "initiative_id", "candidate_generation",
                        "threshold", "authorities"}
            or type(roster["schema_version"]) is not int
            or roster["schema_version"] != 1
            or roster["initiative_id"] != "PGK-FAILCLOSED-001"
            or roster["candidate_generation"] != "v35"
            or type(roster["threshold"]) is not int
            or roster["threshold"] != 2
            or not isinstance(roster["authorities"], list)
            or len(roster["authorities"]) != 2):
        raise ValueError("authority roster scope")
    custodians, authority_keys = set(), set()
    for authority in roster["authorities"]:
        if (not isinstance(authority, dict)
                or set(authority) != {"key_id", "spki_sha256", "custodian_id"}
                or not isinstance(authority["key_id"], str)
                or not KEY_ID.fullmatch(authority["key_id"])
                or not isinstance(authority["spki_sha256"], str)
                or not HEX64.fullmatch(authority["spki_sha256"])
                or not isinstance(authority["custodian_id"], str)
                or not KEY_ID.fullmatch(authority["custodian_id"])):
            raise ValueError("authority roster member")
        custodians.add(authority["custodian_id"])
        authority_keys.add(authority["spki_sha256"])
    if len(custodians) != 2 or len(authority_keys) != 2:
        raise ValueError("roster requires two distinct authority custodians and keys")
    normalized_authorities = sorted(
        ({"key_id": item["key_id"], "custodian_id": item["custodian_id"],
          "spki_sha256": item["spki_sha256"]} for item in roster["authorities"]),
        key=lambda item: item["key_id"])
    return {"verified": True, "root_sha256": trusted_root_sha256,
            "targets_sha256": _sha(targets_raw), "roster_sha256": _sha(roster_raw),
            "threshold": 2, "custodian_count": 2,
            "authorities": normalized_authorities}
