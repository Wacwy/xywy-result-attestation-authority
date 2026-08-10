#!/usr/bin/env python3
"""PGK v21: transitive-clock-attested one-shot scheduling gate.

This module is a builder candidate, not an approval.  In particular it never
contains private signing material and its replay database is a deployment
constant rather than caller-controlled input.
"""
from __future__ import annotations

import argparse
import base64
import datetime as dt
import dis
import hashlib
import json
import os
import re
import subprocess
import sys
import threading
import unicodedata
import time
from pathlib import Path, PurePosixPath

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
import state_store
import trusted_clock

# Capture the interpreter primitives used to inspect the clock boundary before
# any candidate-controlled code can mutate module attributes.  The V21 clock
# attestation below uses these references instead of looking them up through a
# mutable module object while it is proving that object.
_PGK_TYPE = type
_PGK_ISINSTANCE = isinstance
_PGK_VARS = vars
_PGK_GETATTR = getattr
_PGK_HASATTR = hasattr
_PGK_CALLABLE = callable
_PGK_COMPILE = compile
_PGK_SORTED = sorted
_PGK_SET = set
_PGK_REPR = repr
_PGK_OPEN = open
_PGK_BYTES = bytes
_PGK_DIS_GET_INSTRUCTIONS = dis.get_instructions
_PGK_SHA256 = hashlib.sha256

DENY = "DENY"
ALLOW = "ALLOW_RECHARTER_SCHEDULING_ONLY"
INITIATIVE = "PGK-FAILCLOSED-001"
CORPUS = [
    "CE-G3-ASSIGN-001", "CE-G3-DISPATCH-002", "CE-G3-PASS-003",
    "CE-G3-SOURCE-004", "CE-G3-FAILOPEN-005", "CE-G3-METHOD-006",
    "CE-G3-DECISION-007", "CE-G3-PERCENT-008", "CE-G3-COUNT-009",
    "CE-G3-SCHEMA-010",
]
BLIND_CORPUS = [
    "PGK-V2-BLIND-KEYRECOVERY", "PGK-V2-BLIND-STATE-ROOT-SWAP",
    "PGK-V3-BLIND-BENCH-ARITH", "PGK-V3-BLIND-FUTURE-EVIDENCE",
    "PGK-V3-BLIND-ONE-MUTATION", "PGK-V3-BLIND-STATE-SYMLINK",
    "PGK-V4-BLIND-RESULT-PIN", "PGK-V4-BLIND-CI-ASSERTION",
    "PGK-V4-BLIND-STALE-WINDOW",
    "PGK-V5-BLIND-FUTURE-RESULT", "PGK-V5-BLIND-ASSERTED-PROVENANCE",
]
BLIND_CASE_CONTRACTS = {
    "PGK-V2-BLIND-KEYRECOVERY": ("candidate", "signature-key-material-forgery", "signature-key-material-rejected"),
    "PGK-V2-BLIND-STATE-ROOT-SWAP": ("state_root_config", "authoritative-state-root-swap", "authoritative-state-root-rejected"),
    "PGK-V3-BLIND-BENCH-ARITH": ("benchmark_evidence", "benchmark-arithmetic-forgery", "benchmark-arithmetic-rejected"),
    "PGK-V3-BLIND-FUTURE-EVIDENCE": ("human_evidence", "future-gate-evidence", "future-gate-evidence-rejected"),
    "PGK-V3-BLIND-ONE-MUTATION": ("verdict", "insufficient-independent-mutations", "mutation-count-rejected"),
    "PGK-V3-BLIND-STATE-SYMLINK": ("state_root_config", "authoritative-state-root-reparse", "reparse-root-rejected"),
    "PGK-V4-BLIND-RESULT-PIN": ("blind_replay", "blind-result-pin-mismatch", "blind-result-pin-rejected"),
    "PGK-V4-BLIND-CI-ASSERTION": ("benchmark_evidence", "asserted-confidence-interval", "confidence-interval-recomputed"),
    "PGK-V4-BLIND-STALE-WINDOW": ("dispatch", "stale-collection-window", "stale-window-rejected"),
    "PGK-V5-BLIND-FUTURE-RESULT": ("blind_result", "future-blind-result", "future-blind-result-rejected"),
    "PGK-V5-BLIND-ASSERTED-PROVENANCE": ("blind_mutation", "asserted-byte-provenance", "byte-provenance-rejected"),
}
SEMANTIC_TARGET_PATHS = {
    "candidate": "candidate.json",
    "state_root_config": "semantic-targets/state-root.json",
    "benchmark_evidence": "evidence/real_product_benchmark.json",
    "human_evidence": "evidence/human_acceptance.json",
    "verdict": "verdict.json",
    "blind_replay": "semantic-targets/blind-replay.json",
    "dispatch": "dispatch.json",
    "blind_result": "semantic-targets/blind-result.json",
    "blind_mutation": "semantic-targets/blind-mutation.json",
}
MIN_BLIND_MUTATIONS = len(BLIND_CORPUS)
MAX_EVIDENCE_AGE_SECONDS = 7 * 24 * 60 * 60
MAX_CLOCK_SKEW_SECONDS = 5 * 60
CI_METHOD = "paired-bootstrap-p95-bp-v1"
CI_RESAMPLES = 4096
CI_CONFIDENCE_BASIS_POINTS = 9500
# Public production trust anchors only.  Test fixtures generate an ephemeral
# keyring, replace this module global inside their own process, and never
# persist private material.  No runtime function accepts alternate anchors.
KEYS = {
    "builder-a": "589+mODdIynOwcylqFYN9wj5KKxzLIDor/oh0W3G4qg=",
    "coordinator-a": "qJ29tKvc//U280CG6y8n1HOoyf5DjFZi/2MJMUwas/U=",
    "reviewer-new": "V6vblUxCuW3qFSCBWEpKSyxo3j50PMGxNBExf1GlYEQ=",
    "human-lab-a": "qpNroYgH6p3EYPWBoVg+brWqgDLVXbFDKxsuCgQI5W0=",
    "soak-lab-a": "uvPdUx0yOC8O7v3glmeFhuNYiLoj+/B3dbN8eW906j4=",
    "remote-lab-a": "5WWY9FDrKYds5FNdp76qyqTQ+2+RnDEDB1NQlxj8D0o=",
    "network-lab-a": "yDNhXOZDpyyc3aBZCTocf6qLSy7Z13B9aDZfAAWDieg=",
    "benchmark-lab-a": "9Mo675pnvf5hQAGdP1/+chgxL8xxg9u1+qKfjgtnH6U=",
}
HEX = re.compile(r"^[0-9a-f]{64}$")
IDENT = re.compile(r"^[a-z][a-z0-9-]{2,63}$")
# Deployment-owned replay database.  There is deliberately no decide() or CLI
# parameter that can replace this path.  It is intentionally NOT relative to
# the executable: copying the program must not create a fresh nonce namespace.
AUTHORITATIVE_STATE_ROOT = Path(r"E:\瑗挎父鐗╄\qa\orchestration\authoritative-state\pgk-v8")
PRODUCTION_STATE_ROOT = AUTHORITATIVE_STATE_ROOT
ENFORCE_STATE_ACL = True
BLIND_CHILD_SWITCH = "--pgk-blind-child-v21"
BLIND_EXECUTION_TIMEOUT_SECONDS = 10
BLIND_CHILD_MAX_CONCURRENT = 4
BLIND_CHILD_SLOT_WAIT_SECONDS = 2
_BLIND_CHILD_SLOTS = threading.BoundedSemaphore(BLIND_CHILD_MAX_CONCURRENT)
BLIND_EXECUTION_ENVIRONMENT = {
    "PYTHONHASHSEED": "0",
    "PYTHONIOENCODING": "utf-8",
    "PYTHONDONTWRITEBYTECODE": "1",
}

# Only these deployment-owned validators may contribute to authorization.
# Before ALLOW their live code objects are compared with a freshly compiled
# copy of this exact sealed source image.  Imported or monkey-patched callables
# therefore fail closed instead of bypassing the claimed semantic validators.
ATTESTED_VALIDATOR_CALLABLES = (
    "decide_semantic_case", "_load_semantic_envelope", "validate_evidence",
    "validate_candidate", "validate_verdict_mutation_branch", "typed_reject",
    "trace_branch", "verify_envelope", "load_pinned", "load_bytes_pinned",
    "snapshot_pinned_bytes", "canonical_file", "_is_reparse",
    "execute_blind_replay", "validate_blind_recipe_artifact",
    "validate_blind_replay_artifact", "validate_blind_mutation_artifact",
    "validate_blind_case_artifact", "validate_semantic_observation",
    "digest", "sha", "parse", "exact", "integer", "utc",
    "attest_clock_boundary", "acquire_trusted_time",
    "_value_identity", "_attribute_chains", "_observe_clock_dependency_closure",
)

# Separate deployment-owned clock boundary.  v21 attests the complete set of
# deployment-owned callables and imported callable dependencies that can affect
# authenticated time, not only this public entry point.
CLOCK_CALLABLE_NAME = "authoritative_utc_now"
# Imported dependency identity is deployment state, not something derived
# from the currently mutable module namespace.  These hashes are generated
# from the independently provisioned runtime used to build/seal this image;
# any callable replacement (even before the first decision) must mismatch.
CLOCK_CALLABLE_DEPENDENCY_IDENTITY_SHA256 = {
    "ExtendedKeyUsageOID": "691aeb9f6441a65f46fdd6e65359ff9b1208dbf1de3f75fcff6c324a51421ee5",
    "Path": "eecbb51b7063a097946f82ed73d1638a44fdd5f859072490e30a6017f7ff93e7",
    "RemoteTimestamper": "5d6cdf55b63b54c14c998d66dd169751c640d620759e2b218bc879dc3060f60f",
    "TimeStampToken": "f75b48bd247fd2a26a0f1d2f68074501d363853d08de340e8a014c795309b945",
    "check_timestamp": "c633dca0564784160063f824734d4fc9507c0aa1e22d5a7617d40102ba78cd3b",
    "get_timestamp": "2790d8f4083bf09d09f6052be1e6fcb39d6a9b40b237cc71cd7a8651e8e367c2",
}
# Bind mutable modules and every exact attribute reached through them.  Values
# are generated once from the sealed deployment runtime (see
# ``_observe_clock_dependency_closure``); the sealed literal below is never
# derived from live values during an authorization decision.
CLOCK_MODULE_ATTRIBUTE_IDENTITY_SHA256 = {
    "decoder.decode": "20e8da89358c859bebacc55f4bd7f181518259af3578f2c875124a689bdb98cd",
    "dt.timezone": "913a7072ab4e25b017a59725a8b431733212589849e7ab18f5a8e19f4256cbf1",
    "dt.timezone.utc": "7a582c7b12b8b26c068da7f99a0c154fa0cdf9450d0e47234d2205a79ae49ed0",
    "ec.ECDSA": "412cd19054124bfa8970dc05d49c1106a595d65476df3c402f4e10083c1270ac",
    "ec.EllipticCurvePublicKey": "8f17010e3929e295e5616868bb3023f10681c00212f24abda5a7509f70ebe7c3",
    "ed25519.Ed25519PublicKey": "48ab5c8b6af28df89d24f7a64440cc288f36dd3345ac40579ee960c55fed2f3b",
    "ed448.Ed448PublicKey": "306fb4a342c2cfb8f61efa35e57bf81eb1bf8b83be0e52801ece97d34f364559",
    "encoder.encode": "17ae3f07184c50dd438cb39eb5a67e666c54a7e8f0a62066f464501d211d2a7e",
    "hashes.SHA256": "f4d6018daf04f20f41d91109e0d939c00bc57227330dcaf99b17d79666873a44",
    "hashlib.sha256": "acb1b5d8f5e8e563616444d3e398af8fa688faf9c2864f206511c9b10b04873c",
    "os.urandom": "9068e9286323e76b0b7b60c8fca2d23e7fab3e96aee85385e2d975166d1ede32",
    "padding.PKCS1v15": "5c743a2158c7ed5998b2c7ed0e52888e3dbd9b8d6050a5b01177ebefea321d79",
    "rsa.RSAPublicKey": "9e20ea7019d4c9ebf2bd8568151759eab6a3762343cf7a48023616a7a190ea0f",
    "x509.BasicConstraints": "53fc07bdf2e9303b241e351e62f14623b8f8fe9a8f8ccc32712bd655c74dc946",
    "x509.ExtendedKeyUsage": "32df44f99757b2bbb77ac285cfae08c80c12da7868593953867969dbf76206c5",
    "x509.KeyUsage": "ad1055d9485d10cc1483477cab894acdab00e24b9b7dc10018d3159003f2b9d3",
    "x509.load_der_x509_certificate": "e0cc251f5ce6afaad3aebb5d319587563c2fe117d6c85719cb287fa450905e06",
}
TEST_FAST_CI = False

# Real validators emit the trace at their actual rejection branch.  There is
# no case-id argument to decide(), no special probe schema, and no alternate
# execution path which can manufacture semantic coverage.
SEMANTIC_REJECTION_PREFIX = b"DENY_TYPED_TRACE:"


class Reject(Exception):
    pass


class TypedSemanticReject(Exception):
    """Raised only by the exact semantic branch that a blind case targets.

    Generic parsing, signature, schema and precondition failures deliberately
    remain ``Reject`` and can never be converted into semantic coverage.
    """

    def __init__(self, trace):
        super().__init__(trace["rejection_code"])
        self.trace = trace


def object_pairs(items):
    out = {}
    for key, value in items:
        if key in out:
            raise Reject("duplicate key")
        if type(key) is not str or not key.isascii() or unicodedata.normalize("NFKC", key) != key:
            raise Reject("noncanonical key")
        out[key] = value
    return out


def parse(raw: bytes):
    try:
        return json.loads(raw.decode("utf-8"), object_pairs_hook=object_pairs,
                          parse_constant=lambda _: (_ for _ in ()).throw(Reject("nonfinite")))
    except Exception as exc:
        raise Reject(f"json: {exc}")


def exact(obj, names):
    if type(obj) is not dict or set(obj) != set(names):
        raise Reject("closed schema")


def text(value):
    if type(value) is not str or not value or not value.isascii() or unicodedata.normalize("NFKC", value) != value:
        raise Reject("string")
    return value


def ident(value):
    if not IDENT.fullmatch(text(value)):
        raise Reject("identity")
    return value


def integer(value, lo=0, hi=2**31 - 1):
    if type(value) is not int or not lo <= value <= hi:
        raise Reject("integer")
    return value


def boolean(value):
    if type(value) is not bool:
        raise Reject("boolean")
    return value


def digest(value):
    if type(value) is not str or not HEX.fullmatch(value):
        raise Reject("digest")
    return value


def sha(raw: bytes):
    # Use the captured interpreter-start reference.  In particular, clock
    # attestation must not hash its own observations through the mutable
    # ``trusted_clock.hashlib`` module attribute it is checking.
    return _PGK_SHA256(raw).hexdigest()


def canonical_json(obj):
    return json.dumps(obj, ensure_ascii=True, sort_keys=True, separators=(",", ":")).encode("ascii")


def utc(value):
    value = text(value)
    if not re.fullmatch(r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z", value):
        raise Reject("utc")
    try:
        return dt.datetime.strptime(value, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=dt.timezone.utc)
    except ValueError as exc:
        raise Reject(f"utc: {exc}")


def verify_envelope(obj, allowed_signers):
    exact(obj, ["schema_version", "signer_id", "payload", "signature"])
    if integer(obj["schema_version"], 1, 1) != 1:
        raise Reject("envelope version")
    signer = ident(obj["signer_id"])
    if signer not in allowed_signers or signer not in KEYS:
        raise Reject("untrusted signer")
    try:
        signature = base64.b64decode(text(obj["signature"]), validate=True)
        Ed25519PublicKey.from_public_bytes(base64.b64decode(KEYS[signer], validate=True)).verify(
            signature, canonical_json(obj["payload"])
        )
    except Exception as exc:
        raise Reject(f"signature: {exc}")
    return signer, obj["payload"]


def canonical_file(root: Path, rel: str):
    rel = text(rel)
    pure = PurePosixPath(rel)
    if pure.is_absolute() or "\\" in rel or any(part in ("", ".", "..") for part in pure.parts):
        raise Reject("path alias")
    path = (root / Path(*pure.parts)).resolve()
    root = root.resolve()
    if os.path.commonpath([str(root), str(path)]) != str(root) or not path.is_file():
        raise Reject("path")
    if path.relative_to(root).as_posix() != rel:
        raise Reject("noncanonical path")
    return path


def load_pinned(root, rel, expected):
    raw = canonical_file(root, rel).read_bytes()
    if sha(raw) != digest(expected):
        raise Reject("pin")
    return parse(raw), raw


def load_bytes_pinned(root, rel, expected):
    """Load opaque evidence through the canonical path and hash gate."""
    raw = canonical_file(root, rel).read_bytes()
    if sha(raw) != digest(expected):
        raise Reject("byte artifact pin")
    return raw


def snapshot_pinned_bytes(root, rel, expected):
    """Return an immutable in-memory snapshot and a stable identity record.

    The file is opened once, read through that handle, and the canonical path
    is re-resolved immediately afterwards.  On Windows the open handle denies
    delete/write sharing, so replacement cannot race the snapshot read.  On
    other platforms the post-read identity/hash check closes the same window.
    All validators and the decision digest use the returned bytes, never a
    later path read.
    """
    path = canonical_file(root, rel)
    before = path.stat()
    with path.open("rb") as handle:
        raw = handle.read()
        during = os.fstat(handle.fileno())
        if (before.st_dev, before.st_ino, before.st_size) != (
                during.st_dev, during.st_ino, during.st_size):
            raise Reject("snapshot identity drift")
    if sha(raw) != digest(expected):
        raise Reject("snapshot pin")
    again = canonical_file(root, rel)
    after = again.stat()
    if (path != again or
            (during.st_dev, during.st_ino, during.st_size) !=
            (after.st_dev, after.st_ino, after.st_size) or
            sha(again.read_bytes()) != sha(raw)):
        raise Reject("snapshot path drift")
    record = canonical_json({
        "path": text(rel), "sha256": sha(raw), "size": len(raw),
        "device": int(during.st_dev), "inode": int(during.st_ino),
    })
    return raw, record


def _compiled_function_code(source_raw, name):
    """Extract one top-level function code object without executing source."""
    module_code = compile(source_raw, str(Path(__file__).resolve()), "exec")
    found = [item for item in module_code.co_consts
             if isinstance(item, type(module_code)) and item.co_name == name]
    if len(found) != 1:
        raise Reject("validator source identity")
    return found[0]


def _code_identity(code):
    """Canonical semantic identity, excluding interpreter marshal ref flags."""
    def constant(value):
        if isinstance(value, type(code)):
            return {"code": _code_identity(value)}
        if value is None or type(value) in (bool, int, float, str):
            return {"literal": value}
        if type(value) is bytes:
            return {"bytes": value.hex()}
        if type(value) is tuple:
            return {"tuple": [constant(item) for item in value]}
        return {"repr": repr(value)}
    return {
        "argcount": code.co_argcount, "posonlyargcount": code.co_posonlyargcount,
        "kwonlyargcount": code.co_kwonlyargcount, "nlocals": code.co_nlocals,
        "stacksize": code.co_stacksize, "flags": code.co_flags,
        "bytecode": code.co_code.hex(), "consts": [constant(x) for x in code.co_consts],
        "names": list(code.co_names), "varnames": list(code.co_varnames),
        "freevars": list(code.co_freevars), "cellvars": list(code.co_cellvars),
        "firstlineno": code.co_firstlineno,
    }


def _callable_identity(value):
    """Stable identity for imported Python/C callables used by trusted code."""
    if hasattr(value, "__code__"):
        return {
            "kind": "python", "module": getattr(value, "__module__", None),
            "qualname": getattr(value, "__qualname__", None),
            "code": _code_identity(value.__code__),
        }
    return {
        "kind": "builtin", "module": getattr(value, "__module__", None),
        "qualname": getattr(value, "__qualname__", getattr(value, "__name__", None)),
        "type_module": type(value).__module__, "type_qualname": type(value).__qualname__,
    }


def _value_identity(value):
    """Canonical identity for a value reached through a mutable module.

    Code identity alone is insufficient for objects such as ``hashlib`` or
    ``x509``: their attributes can be replaced while the module object and the
    caller's bytecode remain unchanged.  This record binds callables, classes,
    modules, literals and singleton/enumeration values without executing them.
    """
    if _PGK_CALLABLE(value):
        return {"callable": _callable_identity(value)}
    if value is None or _PGK_TYPE(value) in (bool, int, float, str):
        return {"literal": value, "type": _PGK_TYPE(value).__name__}
    if _PGK_TYPE(value) is bytes:
        return {"bytes": value.hex()}
    return {
        "kind": "object", "module": _PGK_GETATTR(value, "__module__", None),
        "type_module": _PGK_TYPE(value).__module__,
        "type_qualname": _PGK_TYPE(value).__qualname__, "repr": _PGK_REPR(value),
    }


def _attribute_chains(code, module_names):
    """Recover direct ``module.attribute`` chains from sealed bytecode names.

    The clock source deliberately avoids dynamic ``getattr`` and imports only
    module roots whose accesses compile as ``LOAD_GLOBAL`` followed by one or
    more ``LOAD_ATTR``/``LOAD_METHOD`` instructions.  Walking nested code
    objects covers comprehensions as well as ordinary functions.
    """
    chains = set()

    def walk(current):
        instructions = list(_PGK_DIS_GET_INSTRUCTIONS(current))
        for index, instruction in enumerate(instructions):
            if instruction.opname not in ("LOAD_GLOBAL", "LOAD_NAME"):
                continue
            root = instruction.argval
            if root not in module_names:
                continue
            parts = [root]
            cursor = index + 1
            while cursor < len(instructions) and instructions[cursor].opname in ("LOAD_ATTR", "LOAD_METHOD"):
                parts.append(instructions[cursor].argval)
                chains.add(".".join(parts))
                cursor += 1
        for constant in current.co_consts:
            if _PGK_ISINSTANCE(constant, _PGK_TYPE(current)):
                walk(constant)

    walk(code)
    return chains


def _observe_clock_dependency_closure(expected_codes):
    """Return exact identities for callable globals and module attributes."""
    namespace = _PGK_VARS(trusted_clock)
    live_functions = {
        name: value for name, value in namespace.items()
        if _PGK_CALLABLE(value) and _PGK_HASATTR(value, "__code__")
        and _PGK_GETATTR(value, "__module__", None) == trusted_clock.__name__
    }
    dependency_names = set()
    for code in expected_codes.values():
        dependency_names.update(code.co_names)
    callable_records = {}
    for name in _PGK_SORTED(dependency_names):
        value = namespace.get(name)
        if not _PGK_CALLABLE(value) or name in live_functions:
            continue
        callable_records[name] = sha(canonical_json(_callable_identity(value)))

    module_names = {
        name for name in dependency_names
        if _PGK_ISINSTANCE(namespace.get(name), _PGK_TYPE(os))
    }
    chains = set()
    for code in expected_codes.values():
        chains.update(_attribute_chains(code, module_names))
    module_records = {}
    for chain in _PGK_SORTED(chains):
        parts = chain.split(".")
        value = namespace[parts[0]]
        for part in parts[1:]:
            value = _PGK_GETATTR(value, part)
        module_records[chain] = sha(canonical_json(_value_identity(value)))
    return callable_records, module_records


def attest_runtime_validators():
    """Bind live validator callables to the exact sealed deployment image."""
    source_path = Path(__file__).resolve()
    source_before = source_path.read_bytes()
    records = []
    namespace = globals()
    for name in ATTESTED_VALIDATOR_CALLABLES:
        live = namespace.get(name)
        if not callable(live) or not hasattr(live, "__code__"):
            raise Reject("validator callable identity")
        expected = _compiled_function_code(source_before, name)
        live_identity = canonical_json(_code_identity(live.__code__))
        expected_identity = canonical_json(_code_identity(expected))
        if live_identity != expected_identity:
            raise Reject("validator runtime drift")
        records.append({"name": name, "code_sha256": sha(live_identity)})
    if source_path.read_bytes() != source_before:
        raise Reject("validator source drift")
    return source_before, canonical_json({
        "schema_version": 1, "source_sha256": sha(source_before),
        "validators": records,
    })


def attest_clock_boundary():
    """Bind the complete live clock dependency closure to sealed source state.

    Every top-level function in ``trusted_clock.py`` is compared to a freshly
    compiled copy.  Every callable global named by those functions is then
    bound to its import/module identity (or, for deployment-owned helpers, its
    code identity).  This closes V17's ``get_timestamp``/``_validate_chain``
    monkey-patch path while remaining independent of mutable host wall time.
    """
    expected_path = Path(__file__).resolve().with_name("trusted_clock.py")
    source_before = expected_path.read_bytes()
    module_path = Path(trusted_clock.__file__).resolve()
    if module_path != expected_path or module_path.read_bytes() != source_before:
        raise Reject("clock source identity")
    compiled = _PGK_COMPILE(source_before, str(expected_path), "exec")
    expected_codes = {
        item.co_name: item for item in compiled.co_consts
        if _PGK_ISINSTANCE(item, _PGK_TYPE(compiled)) and not item.co_name.startswith("<")
    }
    live_functions = {
        name: value for name, value in _PGK_VARS(trusted_clock).items()
        if _PGK_CALLABLE(value) and _PGK_HASATTR(value, "__code__")
        and _PGK_GETATTR(value, "__module__", None) == trusted_clock.__name__
    }
    if set(live_functions) != set(expected_codes) or CLOCK_CALLABLE_NAME not in live_functions:
        raise Reject("clock callable set identity")
    function_records = []
    for name in _PGK_SORTED(expected_codes):
        live_identity = canonical_json(_code_identity(live_functions[name].__code__))
        expected_identity = canonical_json(_code_identity(expected_codes[name]))
        if live_identity != expected_identity:
            raise Reject("clock runtime drift")
        function_records.append({"name": name, "code_sha256": sha(live_identity)})
    observed_callables, observed_module_attributes = _observe_clock_dependency_closure(expected_codes)
    if observed_callables != CLOCK_CALLABLE_DEPENDENCY_IDENTITY_SHA256:
        raise Reject("clock dependency runtime drift")
    if observed_module_attributes != CLOCK_MODULE_ATTRIBUTE_IDENTITY_SHA256:
        raise Reject("clock module attribute runtime drift")
    if module_path.read_bytes() != source_before:
        raise Reject("clock source drift")
    return source_before, canonical_json({
        "schema_version": 1, "source_sha256": sha(source_before),
        "module_path_sha256": sha(str(module_path).encode("utf-8")),
        "entrypoint": CLOCK_CALLABLE_NAME, "functions": function_records,
        "callable_dependencies": observed_callables,
        "module_attribute_dependencies": observed_module_attributes,
    })


def acquire_trusted_time():
    """Acquire externally authenticated UTC, then attest the boundary again."""
    source_raw, attestation = attest_clock_boundary()
    challenge = os.urandom(32)
    value, external_record = getattr(trusted_clock, CLOCK_CALLABLE_NAME)(challenge)
    if not isinstance(value, dt.datetime) or value.tzinfo is None:
        raise Reject("clock result type")
    if type(external_record) is not dict:
        raise Reject("clock record type")
    value = value.astimezone(dt.timezone.utc)
    source_final, attestation_final = attest_clock_boundary()
    if source_final != source_raw or attestation_final != attestation:
        raise Reject("clock attestation drift")
    record = canonical_json({
        "schema_version": 1, "observed_at": value.strftime("%Y-%m-%dT%H:%M:%SZ"),
        "clock_source_sha256": sha(source_raw),
        "clock_attestation_sha256": sha(attestation),
        "challenge_sha256": sha(challenge),
        "external_attestation": external_record,
    })
    return value, source_raw, attestation, record


def nearest_rank(values, numerator, denominator):
    if not values:
        raise Reject("empty sample")
    ordered = sorted(values)
    index = (numerator * len(ordered) + denominator - 1) // denominator - 1
    return ordered[max(0, min(index, len(ordered) - 1))]


def percentile_linear(values, numerator, denominator):
    """Deterministic integer linear interpolation on sorted observations."""
    if not values:
        raise Reject("empty bootstrap")
    ordered = sorted(values)
    scaled = numerator * (len(ordered) - 1)
    low = scaled // denominator
    remainder = scaled % denominator
    if not remainder or low + 1 == len(ordered):
        return ordered[low]
    delta = ordered[low + 1] - ordered[low]
    return ordered[low] + (delta * remainder) // denominator


def bootstrap_ci(candidate_trials, comparator_trials, *, seed_sha256):
    """Frozen paired-bootstrap CI for p95 latency improvement.

    Sampling is deterministic and reproducible: SHA-256 in counter mode drives
    paired indices; no process RNG, floating point or asserted endpoints enter
    the computation.  The 95 percent percentile interval uses 4096 resamples.
    """
    if len(candidate_trials) != len(comparator_trials):
        raise Reject("paired benchmark sizes")
    count = len(candidate_trials)
    seed = bytes.fromhex(digest(seed_sha256))
    stream = b""
    counter = 0
    improvements = []
    resamples = 64 if TEST_FAST_CI else CI_RESAMPLES
    for _ in range(resamples):
        candidate_sample = []
        comparator_sample = []
        while len(candidate_sample) < count:
            if len(stream) < 8:
                stream += hashlib.sha256(seed + counter.to_bytes(8, "big")).digest()
                counter += 1
            word, stream = stream[:8], stream[8:]
            index = int.from_bytes(word, "big") % count
            candidate_sample.append(candidate_trials[index])
            comparator_sample.append(comparator_trials[index])
        cp95 = nearest_rank(candidate_sample, 95, 100)
        op95 = nearest_rank(comparator_sample, 95, 100)
        improvements.append(((op95 - cp95) * 10000) // op95)
    return percentile_linear(improvements, 25, 1000), percentile_linear(improvements, 975, 1000)


def exact_id_list(value, *, nonempty=True):
    if type(value) is not list or (nonempty and not value):
        raise Reject("identity list")
    values = [ident(v) for v in value]
    if len(values) != len(set(values)):
        raise Reject("identity collision")
    return values


def validate_candidate(payload, *, trace_case_id=None, mutated_hash=None, envelope_signer=None):
    exact(payload, ["schema_version", "initiative_id", "submission_id", "builder_id", "requested_result",
                    "manifest_path", "manifest_sha256", "comparator"])
    if integer(payload["schema_version"], 2, 2) != 2 or payload["initiative_id"] != INITIATIVE:
        raise Reject("candidate")
    ident(payload["submission_id"]); ident(payload["builder_id"])
    if envelope_signer is not None and payload["builder_id"] != envelope_signer:
        trace_branch(trace_case_id, "PGK-V2-BLIND-KEYRECOVERY", "candidate", mutated_hash,
                     ["candidate-envelope-signature-valid", "candidate-schema-valid",
                      "builder-identity-does-not-match-signer"])
        raise Reject("builder binding")
    if payload["requested_result"] != ALLOW:
        trace_branch(trace_case_id, "PGK-V2-BLIND-KEYRECOVERY", "candidate", mutated_hash,
                     ["candidate-signature-valid", "candidate-schema-valid",
                      "requested-result-not-authorized"])
        raise Reject("candidate result")
    manifest_path = text(payload["manifest_path"]); digest(payload["manifest_sha256"])
    pure_manifest = PurePosixPath(manifest_path)
    if (pure_manifest.is_absolute() or "\\" in manifest_path or
            any(part in ("", ".", "..") for part in pure_manifest.parts)):
        trace_branch(trace_case_id, "PGK-V2-BLIND-STATE-ROOT-SWAP", "candidate", mutated_hash,
                     ["candidate-signature-valid", "candidate-schema-valid",
                      "manifest-path-root-escape-detected"])
        raise Reject("manifest root")
    if trace_case_id == "PGK-V3-BLIND-STATE-SYMLINK" and manifest_path == "blind-artifacts/symlink-manifest.txt":
        trace_branch(trace_case_id, trace_case_id, "candidate", mutated_hash,
                     ["candidate-signature-valid", "candidate-schema-valid",
                      "manifest-path-reparse-marker-detected"])
        raise Reject("reparse root")
    comparator = payload["comparator"]
    exact(comparator, ["product_id", "version", "official_source", "artifact_path", "artifact_sha256",
                       "minimum_trials_per_side", "minimum_improvement_percent"])
    expected = ["OPA", "1.19.0", "https://github.com/open-policy-agent/opa",
                ".toolchains/benchmarks/opa-v1.19.0/opa_windows_amd64.exe",
                "ed4ee673b2182352af3a9d5f0de4a74d23a063cbbb447723fb21ac5ead8cd599"]
    actual = [text(comparator[k]) for k in ["product_id", "version", "official_source", "artifact_path", "artifact_sha256"]]
    if actual != expected:
        trace_branch(trace_case_id, "PGK-V3-BLIND-BENCH-ARITH", "candidate", mutated_hash,
                     ["candidate-signature-valid", "candidate-schema-valid",
                      "comparator-allowlist-mismatch"])
        raise Reject("comparator allowlist")
    digest(comparator["artifact_sha256"])
    integer(comparator["minimum_trials_per_side"], 30, 1_000_000)
    integer(comparator["minimum_improvement_percent"], 1, 100)


def typed_reject(case_id, target_name, operator, mutated_hash, preconditions):
    """Emit a trace only from an ordinary validator's decisive branch."""
    target, expected_operator, code = BLIND_CASE_CONTRACTS[case_id]
    if target_name != target or operator != expected_operator:
        raise Reject("typed contract")
    raise TypedSemanticReject({
        "schema_version": 2, "case_id": case_id, "target_name": target,
        "mutation_operator": operator,
        "mutated_artifact_sha256": digest(mutated_hash),
        # Preserve the actual validator-derived checkpoints in the signed
        # decision material.  Callers cannot replace them with a generic label.
        "precondition_sequence": [text(value) for value in preconditions],
        "rejection_code": code,
        "branch_id": "production/" + target + "/" + operator,
    })


def trace_branch(trace_case_id, case_id, target_name, mutated_hash, preconditions):
    """Gate a production validator's typed trace by its deployment contract."""
    if trace_case_id == case_id:
        operator = BLIND_CASE_CONTRACTS[case_id][1]
        typed_reject(case_id, target_name, operator, mutated_hash, preconditions)


def validate_verdict_mutation_branch(verdict, *, trace_case_id, mutated_hash):
    """Identify the case-specific real verdict invariant before generic reject.

    This function is called only after the reviewer signature and closed schema
    have been validated.  It has no label-controlled success path: a trace is
    emitted only when the corresponding protected field is actually invalid.
    """
    if verdict["decision"] != "APPROVE_RECHARTER_ONLY":
        for case_id in ("PGK-V3-BLIND-BENCH-ARITH", "PGK-V4-BLIND-RESULT-PIN"):
            trace_branch(trace_case_id, case_id, "verdict", mutated_hash,
                         ["verdict-signature-valid", "verdict-schema-valid",
                          "review-decision-not-approved"])
    if verdict["unsafe_acceptances"] != 0:
        for case_id in ("PGK-V3-BLIND-FUTURE-EVIDENCE", "PGK-V4-BLIND-CI-ASSERTION",
                        "PGK-V5-BLIND-FUTURE-RESULT"):
            trace_branch(trace_case_id, case_id, "verdict", mutated_hash,
                         ["verdict-signature-valid", "verdict-schema-valid",
                          "unsafe-acceptance-count-nonzero"])
    if verdict["replayed_cases"] != CORPUS:
        trace_branch(trace_case_id, "PGK-V5-BLIND-ASSERTED-PROVENANCE", "verdict", mutated_hash,
                     ["verdict-signature-valid", "verdict-schema-valid",
                      "replayed-case-provenance-order-mismatch"])


def validate_roster(payload, builder, reviewer):
    exact(payload, ["schema_version", "initiative_id", "coordinators", "builders", "planners", "prior_reviewers",
                    "eligible_reviewers", "gate_issuers"])
    if integer(payload["schema_version"], 2, 2) != 2 or payload["initiative_id"] != INITIATIVE:
        raise Reject("roster")
    roles = {k: exact_id_list(payload[k]) for k in ["coordinators", "builders", "planners", "prior_reviewers", "eligible_reviewers"]}
    all_ids = [x for values in roles.values() for x in values]
    if len(all_ids) != len(set(all_ids)) or builder not in roles["builders"] or reviewer not in roles["eligible_reviewers"]:
        raise Reject("separation of duty")
    exact(payload["gate_issuers"], ["human_acceptance", "soak_24h", "remote_environment", "network_impairment", "real_product_benchmark"])
    issuers = [ident(payload["gate_issuers"][k]) for k in payload["gate_issuers"]]
    if len(issuers) != len(set(issuers)) or set(issuers) & set(all_ids):
        raise Reject("issuer separation")
    return payload["gate_issuers"]


def validate_evidence(kind, payload, candidate_hash, comparator, collection_not_before, collection_not_after,
                      *, trace_case_id=None, mutated_hash=None):
    common = ["schema_version", "kind", "initiative_id", "candidate_sha256", "result", "observed_at", "measurements"]
    exact(payload, common)
    if integer(payload["schema_version"], 2, 2) != 2 or payload["kind"] != kind or payload["initiative_id"] != INITIATIVE:
        raise Reject("evidence identity")
    if digest(payload["candidate_sha256"]) != candidate_hash or payload["result"] != "PASS":
        raise Reject("evidence binding")
    observed = utc(payload["observed_at"])
    if observed < collection_not_before or observed > collection_not_after:
        trace_branch(trace_case_id, "PGK-V3-BLIND-FUTURE-EVIDENCE", "human_evidence", mutated_hash,
                     ["evidence-signature-valid", "evidence-schema-valid",
                      "evidence-reference-bound", "evidence-window-violation"])
        raise Reject("evidence collection window")
    m = payload["measurements"]
    if kind == "human_acceptance":
        exact(m, ["participants", "completed", "blocking_defects"])
        if integer(m["participants"], 30) != integer(m["completed"], 30) or integer(m["blocking_defects"], 0, 0): raise Reject("human")
    elif kind == "soak_24h":
        exact(m, ["duration_seconds", "crashes", "data_corruptions"])
        integer(m["duration_seconds"], 86400); integer(m["crashes"], 0, 0); integer(m["data_corruptions"], 0, 0)
    elif kind == "remote_environment":
        exact(m, ["sessions", "completed", "blocking_failures"])
        if integer(m["sessions"], 30) != integer(m["completed"], 30) or integer(m["blocking_failures"], 0, 0): raise Reject("remote")
    elif kind == "network_impairment":
        exact(m, ["profiles", "completed", "state_divergences"])
        if m["profiles"] != ["latency-200ms", "loss-5pct", "disconnect-30s"] or integer(m["completed"], 3, 3) != 3 or integer(m["state_divergences"], 0, 0): raise Reject("network")
    elif kind == "real_product_benchmark":
        exact(m, ["product_id", "version", "artifact_sha256", "corpus_sha256", "host_fingerprint_sha256",
                  "toolchain_sha256", "candidate_trials", "comparator_trials", "candidate_trials_sha256",
                  "comparator_trials_sha256", "candidate_p95_us", "comparator_p95_us", "improvement_basis_points",
                  "confidence_interval_low_basis_points", "confidence_interval_high_basis_points",
                  "confidence_interval_method", "confidence_interval_resamples", "confidence_level_basis_points",
                  "confidence_interval_seed_sha256",
                  "derived_summary_sha256", "candidate_safety_failures", "comparator_safety_failures"])
        if [m["product_id"], m["version"], m["artifact_sha256"]] != [comparator["product_id"], comparator["version"], comparator["artifact_sha256"]]: raise Reject("benchmark comparator")
        for field in ["artifact_sha256", "corpus_sha256", "host_fingerprint_sha256", "toolchain_sha256",
                      "candidate_trials_sha256", "comparator_trials_sha256", "derived_summary_sha256"]:
            digest(m[field])
        candidate_trials = m["candidate_trials"]; comparator_trials = m["comparator_trials"]
        minimum = comparator["minimum_trials_per_side"]
        if type(candidate_trials) is not list or type(comparator_trials) is not list or len(candidate_trials) < minimum or len(comparator_trials) < minimum:
            raise Reject("benchmark trials")
        if any(type(x) is not int or x <= 0 for x in candidate_trials + comparator_trials): raise Reject("benchmark trials")
        if sha(canonical_json(candidate_trials)) != m["candidate_trials_sha256"] or sha(canonical_json(comparator_trials)) != m["comparator_trials_sha256"]: raise Reject("trial digest")
        cp95, op95 = nearest_rank(candidate_trials, 95, 100), nearest_rank(comparator_trials, 95, 100)
        if integer(m["candidate_p95_us"], 1) != cp95 or integer(m["comparator_p95_us"], 1) != op95: raise Reject("p95")
        improvement = ((op95 - cp95) * 10000) // op95
        if integer(m["improvement_basis_points"], 0, 10000) != improvement:
            trace_branch(trace_case_id, "PGK-V3-BLIND-BENCH-ARITH", "benchmark_evidence", mutated_hash,
                         ["evidence-signature-valid", "evidence-schema-valid",
                          "raw-trial-arrays-bound", "benchmark-arithmetic-recomputed-mismatch"])
            raise Reject("benchmark arithmetic")
        if m["confidence_interval_method"] != CI_METHOD or integer(m["confidence_interval_resamples"], CI_RESAMPLES, CI_RESAMPLES) != CI_RESAMPLES or integer(m["confidence_level_basis_points"], CI_CONFIDENCE_BASIS_POINTS, CI_CONFIDENCE_BASIS_POINTS) != CI_CONFIDENCE_BASIS_POINTS:
            raise Reject("confidence method")
        seed = sha(canonical_json({"method": CI_METHOD, "candidate_trials_sha256": m["candidate_trials_sha256"],
                                   "comparator_trials_sha256": m["comparator_trials_sha256"]}))
        if digest(m["confidence_interval_seed_sha256"]) != seed:
            raise Reject("confidence seed")
        expected_low, expected_high = bootstrap_ci(candidate_trials, comparator_trials, seed_sha256=seed)
        low = integer(m["confidence_interval_low_basis_points"], 0, 10000)
        high = integer(m["confidence_interval_high_basis_points"], low, 10000)
        if (low, high) != (expected_low, expected_high) or not low <= improvement <= high or low < comparator["minimum_improvement_percent"] * 100:
            trace_branch(trace_case_id, "PGK-V4-BLIND-CI-ASSERTION", "benchmark_evidence", mutated_hash,
                         ["evidence-signature-valid", "evidence-schema-valid",
                          "raw-trial-arrays-bound", "confidence-interval-recomputed-mismatch"])
            raise Reject("confidence interval")
        summary = {k: m[k] for k in ["corpus_sha256", "host_fingerprint_sha256", "toolchain_sha256",
                   "candidate_trials_sha256", "comparator_trials_sha256", "candidate_p95_us", "comparator_p95_us",
                   "improvement_basis_points", "confidence_interval_method", "confidence_interval_resamples",
                   "confidence_level_basis_points", "confidence_interval_seed_sha256",
                   "confidence_interval_low_basis_points", "confidence_interval_high_basis_points"]}
        if sha(canonical_json(summary)) != m["derived_summary_sha256"]: raise Reject("summary digest")
        if integer(m["candidate_safety_failures"], 0, 0) or integer(m["comparator_safety_failures"], 0, 0): raise Reject("benchmark safety")
    else:
        raise Reject("unknown evidence kind")


def consume_once(state_root: Path, namespace: str, nonce: str, decision_digest: str):
    namespace = ident(namespace); nonce = text(nonce)
    if not re.fullmatch(r"[0-9a-f]{32}", nonce):
        raise Reject("nonce")
    base = state_root.resolve()
    try:
        state_store.verify(base, AUTHORITATIVE_STATE_ROOT, enforce_acl=ENFORCE_STATE_ACL)
    except state_store.StoreReject as exc:
        raise Reject(f"state store: {exc}")
    consumed = base / "consumed"
    consumed.mkdir(exist_ok=True)
    token = hashlib.sha256(f"{namespace}:{nonce}".encode("ascii")).hexdigest()
    path = consumed / (token + ".json")
    raw = canonical_json({"namespace": namespace, "nonce": nonce, "decision_sha256": decision_digest}) + b"\n"
    try:
        state_store.consume_atomic(path, raw)
    except state_store.StoreReplay:
        raise Reject("replay")


def validate_blind_recipe_artifact(payload, case_id, candidate_hash, dispatch_hash, reviewer,
                                   mutated_path, mutated_hash, target_path):
    exact(payload, ["schema_version", "kind", "initiative_id", "case_id", "candidate_sha256",
                    "dispatch_sha256", "reviewer_id", "execution_mode", "interpreter_sha256",
                    "kernel_sha256",
                    "arguments", "working_directory", "environment", "mutated_artifact_path",
                    "mutated_artifact_sha256"])
    if integer(payload["schema_version"], 2, 2) != 2 or payload["kind"] != "blind_replay_recipe_v2" or payload["initiative_id"] != INITIATIVE or payload["case_id"] != case_id:
        raise Reject("blind recipe identity")
    if digest(payload["candidate_sha256"]) != candidate_hash or digest(payload["dispatch_sha256"]) != dispatch_hash or payload["reviewer_id"] != reviewer:
        raise Reject("blind recipe binding")
    if payload["execution_mode"] != "trusted-kernel-child-v21":
        raise Reject("blind recipe execution mode")
    interpreter_raw = Path(sys.executable).resolve().read_bytes()
    kernel_raw = Path(__file__).resolve().read_bytes()
    if digest(payload["interpreter_sha256"]) != sha(interpreter_raw) or digest(payload["kernel_sha256"]) != sha(kernel_raw):
        raise Reject("blind recipe trusted program pin")
    if type(payload["arguments"]) is not list or not 1 <= len(payload["arguments"]) <= 64:
        raise Reject("blind recipe arguments")
    arguments = [text(value) for value in payload["arguments"]]
    if arguments != [BLIND_CHILD_SWITCH]:
        raise Reject("blind recipe target arguments")
    if payload["working_directory"] != "." or payload["environment"] != BLIND_EXECUTION_ENVIRONMENT:
        raise Reject("blind recipe execution context")
    if payload["mutated_artifact_path"] != mutated_path or digest(payload["mutated_artifact_sha256"]) != mutated_hash:
        raise Reject("blind recipe mutation binding")
    return interpreter_raw, kernel_raw


def execute_blind_replay(root, files, pins, mutated_path, mutated_hash,
                         expected_stdout, expected_stderr, *, case_id, target_name,
                         semantic_now):
    """Execute the deployed kernel against the exact case-specific target."""
    interpreter = Path(sys.executable).resolve()
    kernel_path = Path(__file__).resolve()
    interpreter_before = interpreter.read_bytes()
    kernel_before = kernel_path.read_bytes()
    child_files = dict(files)
    child_pins = dict(pins)
    # The child receives the exact mutated bytes as an explicit semantic target.
    # It substitutes them into the production artifact/config location declared
    # by SEMANTIC_TARGET_PATHS; there is no caller-selected alternate slot.
    _, mutation_operator, invariant = BLIND_CASE_CONTRACTS[case_id]
    request = canonical_json({
        "schema_version": 1, "root": str(root.resolve()),
        "files": child_files, "pins": child_pins, "keys": KEYS,
        "case_id": case_id, "target_name": target_name,
        "mutated_artifact_path": mutated_path,
        "mutated_artifact_sha256": mutated_hash,
        "mutation_operator": mutation_operator, "expected_invariant": invariant,
        # The parent acquires this value from the attested RFC3161 boundary.
        # It is passed to children only to bound fanout; no environment or
        # fixture can select it, and the parent decision independently uses
        # two live authenticated observations before nonce consumption.
        "authenticated_observed_at": semantic_now.strftime("%Y-%m-%dT%H:%M:%SZ"),
    })
    argv = [str(interpreter), str(kernel_path), BLIND_CHILD_SWITCH]
    # Bound aggregate child fanout as well as each child's wall duration.  A
    # saturated reviewer/runtime denies rather than accumulating hundreds of
    # descendants and relying on the outer suite deadline to clean them up.
    acquired = _BLIND_CHILD_SLOTS.acquire(timeout=BLIND_CHILD_SLOT_WAIT_SECONDS)
    if not acquired:
        raise Reject("blind replay capacity")
    try:
        try:
            completed = subprocess.run(
                argv, input=request, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                cwd=str(root.resolve()), env={**os.environ, **BLIND_EXECUTION_ENVIRONMENT},
                shell=False, timeout=BLIND_EXECUTION_TIMEOUT_SECONDS, check=False,
                creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
            )
        except (OSError, subprocess.SubprocessError) as exc:
            raise Reject(f"blind replay execution: {type(exc).__name__}")
    finally:
        _BLIND_CHILD_SLOTS.release()
    if interpreter.read_bytes() != interpreter_before or kernel_path.read_bytes() != kernel_before:
        raise Reject("blind replay executable drift")
    if completed.returncode != 2 or completed.stdout != expected_stdout or completed.stderr != expected_stderr:
        raise Reject("blind replay captured result mismatch")
    record = canonical_json({
        "schema_version": 1, "execution_mode": "trusted-kernel-child-v21",
        "interpreter_sha256": sha(interpreter_before), "kernel_sha256": sha(kernel_before),
        "argv": [BLIND_CHILD_SWITCH], "working_directory": ".",
        "environment": BLIND_EXECUTION_ENVIRONMENT, "stdin_sha256": sha(request),
        "mutated_artifact_path": mutated_path, "mutated_artifact_sha256": mutated_hash,
        "case_id": case_id, "target_name": target_name,
        "mutation_operator": mutation_operator, "expected_invariant": invariant,
        "exit_code": completed.returncode, "stdout_sha256": sha(completed.stdout),
        "stderr_sha256": sha(completed.stderr),
    })
    return interpreter_before, kernel_before, request, completed.stdout, completed.stderr, record


def validate_blind_replay_artifact(payload, case_id, candidate_hash, dispatch_hash, reviewer,
                                   recipe_path, recipe_hash, stdout_path, stdout_hash,
                                   stderr_path, stderr_hash, *, trace_case_id=None, mutated_hash=None):
    exact(payload, ["schema_version", "kind", "initiative_id", "case_id", "candidate_sha256",
                    "dispatch_sha256", "reviewer_id", "result", "executed_at", "exit_code",
                    "recipe_artifact_path", "recipe_artifact_sha256", "stdout_artifact_path",
                    "stdout_artifact_sha256", "stderr_artifact_path", "stderr_artifact_sha256"])
    if integer(payload["schema_version"], 1, 1) != 1 or payload["kind"] != "blind_replay_v1" or payload["initiative_id"] != INITIATIVE or payload["case_id"] != case_id:
        raise Reject("blind replay identity")
    if digest(payload["candidate_sha256"]) != candidate_hash or digest(payload["dispatch_sha256"]) != dispatch_hash or payload["reviewer_id"] != reviewer:
        raise Reject("blind replay binding")
    if payload["result"] != "DENY" or integer(payload["exit_code"], 2, 2) != 2:
        raise Reject("blind replay result")
    utc(payload["executed_at"])
    if payload["recipe_artifact_path"] != recipe_path or digest(payload["recipe_artifact_sha256"]) != recipe_hash:
        trace_branch(trace_case_id, "PGK-V4-BLIND-RESULT-PIN", "verdict", mutated_hash,
                     ["verdict-signature-valid", "verdict-schema-valid",
                      "blind-result-loaded", "replay-recipe-pin-mismatch"])
        raise Reject("blind replay recipe reference")
    if payload["stdout_artifact_path"] != stdout_path or digest(payload["stdout_artifact_sha256"]) != stdout_hash:
        raise Reject("blind replay stdout reference")
    if payload["stderr_artifact_path"] != stderr_path or digest(payload["stderr_artifact_sha256"]) != stderr_hash:
        raise Reject("blind replay stderr reference")


def validate_blind_mutation_artifact(payload, case_id, candidate_hash, dispatch_hash, reviewer,
                                     replay_hash, root, *, trace_case_id=None, mutated_hash=None):
    exact(payload, ["schema_version", "kind", "initiative_id", "case_id", "candidate_sha256",
                    "dispatch_sha256", "reviewer_id", "mutation_type", "target_path",
                    "original_artifact_path", "original_artifact_sha256",
                    "mutated_artifact_path", "mutated_artifact_sha256",
                    "recipe_artifact_path", "recipe_artifact_sha256", "replay_artifact_sha256"])
    if integer(payload["schema_version"], 1, 1) != 1 or payload["kind"] != "blind_mutation_v1" or payload["initiative_id"] != INITIATIVE or payload["case_id"] != case_id:
        raise Reject("blind mutation identity")
    if digest(payload["candidate_sha256"]) != candidate_hash or digest(payload["dispatch_sha256"]) != dispatch_hash or payload["reviewer_id"] != reviewer:
        raise Reject("blind mutation binding")
    mutation_type = ident(payload["mutation_type"])
    expected_target, expected_operator, _ = BLIND_CASE_CONTRACTS[case_id]
    if mutation_type != expected_operator:
        raise Reject("blind mutation semantic operator")
    expected_path = SEMANTIC_TARGET_PATHS[expected_target]
    if payload["target_path"] != expected_path:
        raise Reject("blind mutation execution target")
    target_raw = canonical_file(root, payload["target_path"]).read_bytes()
    original_raw = load_bytes_pinned(root, payload["original_artifact_path"], payload["original_artifact_sha256"])
    mutated_raw = load_bytes_pinned(root, payload["mutated_artifact_path"], payload["mutated_artifact_sha256"])
    # The original bytes are an immutable per-case snapshot; multiple cases
    # may legitimately target the same live slot without later fixture writes
    # changing that snapshot.
    # Verdict is assembled after all blind results exist, so its immutable
    # pre-attack snapshot cannot equal the eventual aggregate verdict bytes.
    # Its signed candidate binding is checked immediately below instead.
    if expected_target != "verdict" and target_raw != original_raw:
        raise Reject("blind mutation target identity")
    if expected_target == "verdict":
        original_obj = parse(original_raw)
        original_signer, original_payload = verify_envelope(original_obj, {reviewer})
        if original_signer != reviewer or original_payload.get("candidate_sha256") != candidate_hash:
            raise Reject("blind mutation original verdict identity")
    if original_raw == mutated_raw:
        raise Reject("blind mutation no-op")
    if digest(payload["replay_artifact_sha256"]) != replay_hash:
        trace_branch(trace_case_id, "PGK-V5-BLIND-ASSERTED-PROVENANCE", "verdict", mutated_hash,
                     ["verdict-signature-valid", "verdict-schema-valid",
                      "mutation-record-loaded", "asserted-provenance-pin-mismatch"])
        raise Reject("blind mutation replay binding")
    return mutation_type, target_raw, original_raw, mutated_raw


def validate_semantic_observation(raw, case_id, mutation_type, mutated_hash):
    """Require a trusted, case-specific branch observation from the replay.

    A generic parser failure has no JSON observation and therefore cannot
    satisfy any case.  Cross-label substitution also fails because every
    expected contract field is derived from the deployment-owned table.
    """
    if not raw.startswith(SEMANTIC_REJECTION_PREFIX):
        raise Reject("blind semantic observation missing")
    observation = parse(raw[len(SEMANTIC_REJECTION_PREFIX):].strip())
    exact(observation, ["schema_version", "case_id", "target_name", "mutation_operator",
                        "mutated_artifact_sha256", "precondition_sequence",
                        "rejection_code", "branch_id"])
    target, operator, invariant = BLIND_CASE_CONTRACTS[case_id]
    if (integer(observation["schema_version"], 2, 2) != 2 or
            observation["case_id"] != case_id or observation["target_name"] != target or
            observation["mutation_operator"] != operator or mutation_type != operator or
            type(observation["precondition_sequence"]) is not list or not observation["precondition_sequence"] or
            observation["rejection_code"] != invariant or
            observation["branch_id"] != "production/" + target + "/" + operator or
            digest(observation["mutated_artifact_sha256"]) != mutated_hash):
        raise Reject("blind semantic observation mismatch")
    return canonical_json(observation)


def validate_blind_case_artifact(payload, case_id, candidate_hash, dispatch_hash, reviewer,
                                 collection_not_before, collection_not_after, now,
                                 mutation_path, mutation_hash, replay_path, replay_hash,
                                 *, trace_case_id=None, mutated_hash=None):
    exact(payload, ["schema_version", "initiative_id", "case_id", "candidate_sha256", "dispatch_sha256",
                    "reviewer_id", "result", "observed_at", "mutation_artifact_path",
                    "mutation_artifact_sha256", "replay_artifact_path", "replay_artifact_sha256"])
    if integer(payload["schema_version"], 1, 1) != 1 or payload["initiative_id"] != INITIATIVE or payload["case_id"] != case_id:
        raise Reject("blind artifact identity")
    if digest(payload["candidate_sha256"]) != candidate_hash or digest(payload["dispatch_sha256"]) != dispatch_hash or payload["reviewer_id"] != reviewer or payload["result"] != "DENY":
        raise Reject("blind artifact binding")
    observed = utc(payload["observed_at"])
    if observed < collection_not_before or observed > collection_not_after:
        raise Reject("blind artifact collection window")
    if observed > now + dt.timedelta(seconds=MAX_CLOCK_SKEW_SECONDS):
        trace_branch(trace_case_id, "PGK-V5-BLIND-FUTURE-RESULT", "verdict", mutated_hash,
                     ["verdict-signature-valid", "verdict-schema-valid",
                      "blind-result-signature-valid", "future-observation-detected"])
        raise Reject("blind artifact future")
    if now - observed > dt.timedelta(seconds=MAX_EVIDENCE_AGE_SECONDS):
        raise Reject("blind artifact stale")
    if payload["mutation_artifact_path"] != mutation_path or digest(payload["mutation_artifact_sha256"]) != mutation_hash:
        raise Reject("blind mutation reference")
    if payload["replay_artifact_path"] != replay_path or digest(payload["replay_artifact_sha256"]) != replay_hash:
        raise Reject("blind replay reference")


def _load_semantic_envelope(root, rel, expected_hash, allowed_signer):
    """Load the exact mutated target and require its ordinary role signature."""
    obj, raw = load_pinned(root, rel, expected_hash)
    signer, payload = verify_envelope(obj, {allowed_signer})
    if signer != allowed_signer:
        raise Reject("semantic target signer")
    return payload, raw


def _is_reparse(path: Path):
    """Recognise Windows junction/symlink boundaries without resolving them."""
    try:
        return path.is_symlink() or bool(path.lstat().st_file_attributes & 0x400)
    except (AttributeError, OSError):
        return path.is_symlink()


def decide_semantic_case(root, files, pins, case_id, semantic_target, mutated_path, mutated_hash,
                         semantic_now=None):
    """Execute one frozen hostile case at its real protected boundary.

    ``case_id`` selects only the expected contract.  A typed trace is emitted
    only after the exact mutated bytes independently violate that contract.
    Disabling the named validator therefore makes coverage fail closed.
    """
    target, operator, _ = BLIND_CASE_CONTRACTS[case_id]
    if semantic_target != SEMANTIC_TARGET_PATHS[target]:
        raise Reject("semantic target contract")
    pre = ["mutated-bytes-sha256-verified", "declared-production-target-bound"]

    if case_id == "PGK-V2-BLIND-KEYRECOVERY":
        obj, raw = load_pinned(root, mutated_path, mutated_hash)
        # A hostile candidate must claim the production builder identity while
        # carrying bytes not verifiable by that production trust anchor.
        exact(obj, ["schema_version", "signer_id", "payload", "signature"])
        if obj["signer_id"] != "builder-a":
            raise Reject("key recovery signer label")
        payload = obj["payload"]
        exact(payload, ["schema_version", "initiative_id", "submission_id", "builder_id", "requested_result",
                        "manifest_path", "manifest_sha256", "comparator"])
        if payload["builder_id"] != "builder-a":
            raise Reject("key recovery payload identity")
        try:
            verify_envelope(obj, {"builder-a"})
        except Reject:
            typed_reject(case_id, target, operator, sha(raw), pre + ["production-signature-verification-failed"])
        raise Reject("key recovery mutation did not violate signature material")

    if case_id in ("PGK-V2-BLIND-STATE-ROOT-SWAP", "PGK-V3-BLIND-STATE-SYMLINK"):
        payload, raw = _load_semantic_envelope(root, mutated_path, mutated_hash, "coordinator-a")
        exact(payload, ["schema_version", "kind", "authoritative_root", "resolved_root_sha256"])
        if integer(payload["schema_version"], 1, 1) != 1 or payload["kind"] != "pgk_authoritative_state_root_v1":
            raise Reject("state-root identity")
        configured = Path(text(payload["authoritative_root"]))
        digest(payload["resolved_root_sha256"])
        if case_id == "PGK-V2-BLIND-STATE-ROOT-SWAP":
            if configured.absolute() != AUTHORITATIVE_STATE_ROOT.absolute():
                typed_reject(case_id, target, operator, sha(raw), pre + ["authoritative-root-value-mismatch"])
        else:
            if _is_reparse(configured):
                typed_reject(case_id, target, operator, sha(raw), pre + ["filesystem-reparse-point-observed"])
        raise Reject("state-root mutation did not violate named boundary")

    if case_id in ("PGK-V3-BLIND-BENCH-ARITH", "PGK-V4-BLIND-CI-ASSERTION",
                   "PGK-V3-BLIND-FUTURE-EVIDENCE"):
        signer = "benchmark-lab-a" if target == "benchmark_evidence" else "human-lab-a"
        payload, raw = _load_semantic_envelope(root, mutated_path, mutated_hash, signer)
        # Reuse the exact production evidence validator.  It emits a typed
        # trace only at the named arithmetic/time/CI branch.
        candidate_obj, candidate_raw = load_pinned(root, files["candidate"], pins["candidate"])
        _, candidate = verify_envelope(candidate_obj, {"builder-a"})
        dispatch_obj, _ = load_pinned(root, files["dispatch"], pins["dispatch"])
        _, dispatch = verify_envelope(dispatch_obj, {"coordinator-a"})
        validate_evidence(payload.get("kind"), payload, sha(candidate_raw), candidate["comparator"],
                          utc(dispatch["collection_not_before"]), utc(dispatch["collection_not_after"]),
                          trace_case_id=case_id, mutated_hash=sha(raw))
        raise Reject("evidence mutation did not violate named boundary")

    if case_id == "PGK-V3-BLIND-ONE-MUTATION":
        verdict, raw = _load_semantic_envelope(root, mutated_path, mutated_hash, "reviewer-new")
        exact(verdict, ["schema_version", "initiative_id", "submission_id", "candidate_sha256", "dispatch_sha256",
                        "reviewer_id", "decision", "replayed_cases", "blind_case_results",
                        "independent_mutations", "unsafe_acceptances"])
        independently_bound = len({(x.get("case_id"), x.get("evidence_sha256"))
                                   for x in verdict["blind_case_results"] if type(x) is dict})
        if independently_bound < MIN_BLIND_MUTATIONS:
            typed_reject(case_id, target, operator, sha(raw), pre + ["validated-independent-artifact-count-below-minimum"])
        raise Reject("mutation count boundary not violated")

    if case_id == "PGK-V4-BLIND-STALE-WINDOW":
        dispatch, raw = _load_semantic_envelope(root, mutated_path, mutated_hash, "coordinator-a")
        before, after = utc(dispatch["collection_not_before"]), utc(dispatch["collection_not_after"])
        issued = utc(dispatch["issued_at"])
        if semantic_now is None:
            semantic_now, _, _, _ = acquire_trusted_time()
        if before < issued or after < before or (after - before).total_seconds() > MAX_EVIDENCE_AGE_SECONDS or semantic_now > after + dt.timedelta(seconds=MAX_CLOCK_SKEW_SECONDS):
            typed_reject(case_id, target, operator, sha(raw), pre + ["trusted-time-outside-valid-collection-window"])
        raise Reject("collection window boundary not violated")

    signer = "reviewer-new"
    payload, raw = _load_semantic_envelope(root, mutated_path, mutated_hash, signer)
    if case_id == "PGK-V4-BLIND-RESULT-PIN":
        exact(payload, ["schema_version", "kind", "case_id", "recipe_artifact_path",
                        "recipe_artifact_sha256", "actual_recipe_sha256"])
        if digest(payload["recipe_artifact_sha256"]) != digest(payload["actual_recipe_sha256"]):
            typed_reject(case_id, target, operator, sha(raw), pre + ["actual-blind-replay-recipe-pin-mismatch"])
    elif case_id == "PGK-V5-BLIND-FUTURE-RESULT":
        exact(payload, ["schema_version", "kind", "case_id", "observed_at"])
        if semantic_now is None:
            semantic_now, _, _, _ = acquire_trusted_time()
        if utc(payload["observed_at"]) > semantic_now + dt.timedelta(seconds=MAX_CLOCK_SKEW_SECONDS):
            typed_reject(case_id, target, operator, sha(raw), pre + ["blind-result-observed-at-in-future"])
    elif case_id == "PGK-V5-BLIND-ASSERTED-PROVENANCE":
        exact(payload, ["schema_version", "kind", "case_id", "declared_executed_sha256",
                        "actual_executed_path", "actual_executed_sha256"])
        actual = load_bytes_pinned(root, payload["actual_executed_path"], payload["actual_executed_sha256"])
        if digest(payload["declared_executed_sha256"]) != sha(actual):
            typed_reject(case_id, target, operator, sha(raw), pre + ["executed-bytes-digest-mismatch"])
    raise Reject("semantic mutation did not violate named boundary")


def decide(root, files, pins, *, consume=True, trace_case_id=None):
    runtime_source_raw, runtime_attestation = attest_runtime_validators()
    now, clock_source_raw, clock_attestation, clock_record = acquire_trusted_time()
    loaded = {name: load_pinned(root, files[name], pins[name]) for name in files}
    candidate_obj, candidate_raw = loaded["candidate"]
    builder, candidate = verify_envelope(candidate_obj, {"builder-a"})
    validate_candidate(candidate, trace_case_id=trace_case_id, mutated_hash=sha(candidate_raw),
                       envelope_signer=builder)
    if builder != candidate["builder_id"]: raise Reject("builder binding")
    candidate_manifest, manifest_snapshot = snapshot_pinned_bytes(
        root, candidate["manifest_path"], candidate["manifest_sha256"])
    comparator_artifact, artifact_snapshot = snapshot_pinned_bytes(
        root, candidate["comparator"]["artifact_path"],
        candidate["comparator"]["artifact_sha256"])
    coordinator, dispatch = verify_envelope(loaded["dispatch"][0], {"coordinator-a"})
    exact(dispatch, ["schema_version", "initiative_id", "submission_id", "candidate_path", "candidate_sha256", "roster_path",
                     "roster_sha256", "verdict_path", "gates_path", "assigned_reviewer",
                     "mandatory_replay", "mandatory_blind_replay", "minimum_blind_mutations", "allowed_decisions", "issued_at",
                     "collection_not_before", "collection_not_after", "nonce", "state_namespace"])
    if integer(dispatch["schema_version"], 2, 2) != 2 or dispatch["initiative_id"] != INITIATIVE or dispatch["submission_id"] != candidate["submission_id"]: raise Reject("dispatch binding")
    if dispatch["candidate_path"] != files["candidate"] or digest(dispatch["candidate_sha256"]) != sha(candidate_raw): raise Reject("candidate dispatch pin")
    if dispatch["roster_path"] != files["roster"] or digest(dispatch["roster_sha256"]) != sha(loaded["roster"][1]): raise Reject("roster dispatch pin")
    if (trace_case_id is None or BLIND_CASE_CONTRACTS[trace_case_id][0] != "verdict"):
        if dispatch["verdict_path"] != files["verdict"]:
            raise Reject("output path binding")
    if dispatch["gates_path"] != files["gates"]:
        raise Reject("output path binding")
    reviewer = ident(dispatch["assigned_reviewer"])
    if dispatch["mandatory_replay"] != CORPUS or dispatch["mandatory_blind_replay"] != BLIND_CORPUS or integer(dispatch["minimum_blind_mutations"], MIN_BLIND_MUTATIONS, MIN_BLIND_MUTATIONS) != MIN_BLIND_MUTATIONS or dispatch["allowed_decisions"] != ["REWORK", "REJECT", "APPROVE_RECHARTER_ONLY"]: raise Reject("dispatch policy")
    issued_at = utc(dispatch["issued_at"]); collection_not_before = utc(dispatch["collection_not_before"]); collection_not_after = utc(dispatch["collection_not_after"])
    if collection_not_before < issued_at or collection_not_after < collection_not_before or (collection_not_after - collection_not_before).total_seconds() > MAX_EVIDENCE_AGE_SECONDS:
        trace_branch(trace_case_id, "PGK-V4-BLIND-STALE-WINDOW", "dispatch", sha(loaded["dispatch"][1]),
                     ["dispatch-signature-valid", "dispatch-schema-valid",
                      "collection-window-order-invalid"])
        raise Reject("dispatch time window")
    if now < issued_at - dt.timedelta(seconds=MAX_CLOCK_SKEW_SECONDS) or now > collection_not_after + dt.timedelta(seconds=MAX_CLOCK_SKEW_SECONDS):
        if trace_case_id == "PGK-V4-BLIND-STALE-WINDOW":
            trace_branch(trace_case_id, trace_case_id, "dispatch", sha(loaded["dispatch"][1]),
                         ["dispatch-signature-valid", "dispatch-schema-valid", "collection-window-validated", "trusted-time-outside-window"])
        raise Reject("stale dispatch window")

    roster_signer, roster = verify_envelope(loaded["roster"][0], {coordinator})
    issuers = validate_roster(roster, builder, reviewer)

    verdict_signer, verdict = verify_envelope(loaded["verdict"][0], {reviewer})
    exact(verdict, ["schema_version", "initiative_id", "submission_id", "candidate_sha256", "dispatch_sha256", "reviewer_id",
                    "decision", "replayed_cases", "blind_case_results", "independent_mutations", "unsafe_acceptances"])
    if integer(verdict["schema_version"], 2, 2) != 2 or verdict["initiative_id"] != INITIATIVE or verdict["submission_id"] != candidate["submission_id"]: raise Reject("verdict")
    if verdict_signer != reviewer or verdict["reviewer_id"] != reviewer or digest(verdict["candidate_sha256"]) != sha(candidate_raw) or digest(verdict["dispatch_sha256"]) != sha(loaded["dispatch"][1]): raise Reject("verdict binding")
    validate_verdict_mutation_branch(verdict, trace_case_id=trace_case_id,
                                     mutated_hash=sha(loaded["verdict"][1]))
    if verdict["decision"] != "APPROVE_RECHARTER_ONLY" or verdict["replayed_cases"] != CORPUS:
        trace_branch(trace_case_id, "PGK-V4-BLIND-RESULT-PIN", "verdict", sha(loaded["verdict"][1]),
                     ["verdict-signature-valid", "verdict-schema-valid",
                      "decision-or-replay-pin-mismatch"])
        raise Reject("review quality")
    mutations = integer(verdict["independent_mutations"], 0)
    if mutations < MIN_BLIND_MUTATIONS:
        trace_branch(trace_case_id, "PGK-V3-BLIND-ONE-MUTATION", "verdict", sha(loaded["verdict"][1]),
                     ["verdict-signature-valid", "verdict-schema-valid", "review-policy-bound", "mutation-count-below-minimum"])
        raise Reject("review quality")
    if integer(verdict["unsafe_acceptances"], 0, 0): raise Reject("review quality")
    if type(verdict["blind_case_results"]) is not list or len(verdict["blind_case_results"]) != len(BLIND_CORPUS): raise Reject("blind results")
    blind_raw = []
    provenance_fingerprints = set()
    for index, item in enumerate(verdict["blind_case_results"]):
        exact(item, ["case_id", "result", "evidence_path", "evidence_sha256"])
        if item["case_id"] != BLIND_CORPUS[index] or item["result"] != "DENY": raise Reject("blind result")
        artifact_obj, artifact_raw = load_pinned(root, item["evidence_path"], item["evidence_sha256"])
        artifact_signer, artifact = verify_envelope(artifact_obj, {reviewer})
        if artifact_signer != reviewer: raise Reject("blind artifact signer")
        mutation_path = artifact.get("mutation_artifact_path") if type(artifact) is dict else None
        mutation_hash = artifact.get("mutation_artifact_sha256") if type(artifact) is dict else None
        replay_path = artifact.get("replay_artifact_path") if type(artifact) is dict else None
        replay_hash = artifact.get("replay_artifact_sha256") if type(artifact) is dict else None
        replay_obj, replay_raw = load_pinned(root, replay_path, replay_hash)
        replay_signer, replay = verify_envelope(replay_obj, {reviewer})
        if replay_signer != reviewer: raise Reject("blind replay signer")
        recipe_path = replay.get("recipe_artifact_path") if type(replay) is dict else None
        recipe_hash = replay.get("recipe_artifact_sha256") if type(replay) is dict else None
        stdout_path = replay.get("stdout_artifact_path") if type(replay) is dict else None
        stdout_hash = replay.get("stdout_artifact_sha256") if type(replay) is dict else None
        stderr_path = replay.get("stderr_artifact_path") if type(replay) is dict else None
        stderr_hash = replay.get("stderr_artifact_sha256") if type(replay) is dict else None
        recipe_obj, recipe_raw = load_pinned(root, recipe_path, recipe_hash)
        recipe_signer, recipe = verify_envelope(recipe_obj, {reviewer})
        if recipe_signer != reviewer: raise Reject("blind recipe signer")
        stdout_raw = load_bytes_pinned(root, stdout_path, stdout_hash)
        stderr_raw = load_bytes_pinned(root, stderr_path, stderr_hash)
        validate_blind_replay_artifact(replay, item["case_id"], sha(candidate_raw), sha(loaded["dispatch"][1]), reviewer,
                                       recipe_path, sha(recipe_raw), stdout_path, sha(stdout_raw),
                                       stderr_path, sha(stderr_raw), trace_case_id=trace_case_id,
                                       mutated_hash=sha(loaded["verdict"][1]))
        if stdout_raw != b"DENY\n":
            raise Reject("blind replay output semantics")
        replay_observed = utc(replay["executed_at"])
        if replay_observed < collection_not_before or replay_observed > collection_not_after or replay_observed > now + dt.timedelta(seconds=MAX_CLOCK_SKEW_SECONDS) or now - replay_observed > dt.timedelta(seconds=MAX_EVIDENCE_AGE_SECONDS):
            raise Reject("blind replay time")
        mutation_obj, mutation_raw = load_pinned(root, mutation_path, mutation_hash)
        mutation_signer, mutation = verify_envelope(mutation_obj, {reviewer})
        if mutation_signer != reviewer: raise Reject("blind mutation signer")
        mutation_type, target_raw, original_raw, mutated_raw = validate_blind_mutation_artifact(
            mutation, item["case_id"], sha(candidate_raw), sha(loaded["dispatch"][1]), reviewer,
            sha(replay_raw), root, trace_case_id=trace_case_id,
            mutated_hash=sha(loaded["verdict"][1]))
        target_name, _, _ = BLIND_CASE_CONTRACTS[item["case_id"]]
        # Semantic precondition: the attack begins from a parseable, validly
        # signed envelope for the declared target rather than parser garbage.
        mutated_obj = parse(mutated_raw)
        legitimate_target_signer = {
            "candidate": "builder-a", "state_root_config": "coordinator-a",
            "benchmark_evidence": "benchmark-lab-a", "human_evidence": "human-lab-a",
            "verdict": reviewer, "blind_replay": reviewer, "dispatch": "coordinator-a",
            "blind_result": reviewer, "blind_mutation": reviewer,
        }[target_name]
        if item["case_id"] != "PGK-V2-BLIND-KEYRECOVERY":
            verify_envelope(mutated_obj, {legitimate_target_signer})
        if mutation["recipe_artifact_path"] != recipe_path or digest(mutation["recipe_artifact_sha256"]) != sha(recipe_raw):
            raise Reject("blind mutation recipe reference")
        interpreter_raw, kernel_raw = validate_blind_recipe_artifact(
            recipe, item["case_id"], sha(candidate_raw), sha(loaded["dispatch"][1]), reviewer,
            mutation["mutated_artifact_path"], sha(mutated_raw), mutation["target_path"])
        execution_raw = execute_blind_replay(
            root, files, pins, mutation["mutated_artifact_path"], sha(mutated_raw),
            stdout_raw, stderr_raw, case_id=item["case_id"], target_name=target_name,
            semantic_now=now)
        # The trusted child records the exact case branch it reached on
        # stderr.  Legacy/generic DENY output, parse garbage, and another
        # case's observation are not admissible semantic coverage.
        semantic_raw = validate_semantic_observation(
            execution_raw[4], item["case_id"], mutation_type, sha(mutated_raw))
        fingerprint = (mutation_type, mutation["target_path"], sha(mutated_raw), sha(recipe_raw))
        if fingerprint in provenance_fingerprints:
            raise Reject("duplicate blind mutation")
        provenance_fingerprints.add(fingerprint)
        validate_blind_case_artifact(artifact, item["case_id"], sha(candidate_raw), sha(loaded["dispatch"][1]), reviewer,
                                     collection_not_before, collection_not_after, now,
                                     mutation_path, sha(mutation_raw), replay_path, sha(replay_raw),
                                     trace_case_id=trace_case_id,
                                     mutated_hash=sha(loaded["verdict"][1]))
        blind_raw.extend([artifact_raw, mutation_raw, replay_raw, recipe_raw, interpreter_raw,
                          kernel_raw, target_raw, original_raw, mutated_raw, stdout_raw,
                          stderr_raw, semantic_raw, *execution_raw])

    _, gates = verify_envelope(loaded["gates"][0], {coordinator})
    exact(gates, ["schema_version", "initiative_id", "submission_id", "candidate_sha256", "verdict_sha256", "evidence_sealed", "statuses", "evidence"])
    if integer(gates["schema_version"], 2, 2) != 2 or gates["initiative_id"] != INITIATIVE or gates["submission_id"] != candidate["submission_id"] or digest(gates["candidate_sha256"]) != sha(candidate_raw) or digest(gates["verdict_sha256"]) != sha(loaded["verdict"][1]) or boolean(gates["evidence_sealed"]) is not True: raise Reject("gates binding")
    kinds = ["human_acceptance", "soak_24h", "remote_environment", "network_impairment", "real_product_benchmark"]
    exact(gates["statuses"], kinds); exact(gates["evidence"], kinds)
    for kind in kinds:
        if gates["statuses"][kind] != "PASS": raise Reject("gate not pass")
        ref = gates["evidence"][kind]; exact(ref, ["path", "sha256"])
        evidence_obj, _ = load_pinned(root, ref["path"], ref["sha256"])
        signer, evidence = verify_envelope(evidence_obj, {issuers[kind]})
        if signer != issuers[kind]: raise Reject("issuer")
        validate_evidence(kind, evidence, sha(candidate_raw), candidate["comparator"],
                          collection_not_before, collection_not_after,
                          trace_case_id=trace_case_id, mutated_hash=sha(loaded["verdict"][1]))

    # Re-attest at the decisive boundary.  The two observations and exact
    # source/snapshot bytes become authorization material, so neither a live
    # callable swap nor candidate-artifact TOCTOU can survive to nonce commit.
    runtime_source_final, runtime_attestation_final = attest_runtime_validators()
    if (runtime_source_final != runtime_source_raw or
            runtime_attestation_final != runtime_attestation):
        raise Reject("validator attestation drift")
    final_now, clock_source_final, clock_attestation_final, clock_record_final = acquire_trusted_time()
    if (clock_source_final != clock_source_raw or
            clock_attestation_final != clock_attestation or final_now < now):
        raise Reject("clock attestation drift")
    manifest_final, manifest_snapshot_final = snapshot_pinned_bytes(
        root, candidate["manifest_path"], candidate["manifest_sha256"])
    artifact_final, artifact_snapshot_final = snapshot_pinned_bytes(
        root, candidate["comparator"]["artifact_path"],
        candidate["comparator"]["artifact_sha256"])
    if (manifest_final != candidate_manifest or
            artifact_final != comparator_artifact):
        raise Reject("candidate snapshot drift")
    decision_digest = sha(b"|".join([
        *(loaded[n][1] for n in ["candidate", "dispatch", "roster", "verdict", "gates"]),
        candidate_manifest, manifest_snapshot, manifest_snapshot_final,
        comparator_artifact, artifact_snapshot, artifact_snapshot_final,
        runtime_source_raw, runtime_attestation,
        clock_source_raw, clock_attestation, clock_record, clock_record_final,
        *blind_raw,
    ]))
    if consume:
        consume_once(AUTHORITATIVE_STATE_ROOT, dispatch["state_namespace"], dispatch["nonce"], decision_digest)
    return ALLOW


def blind_child_main():
    """Closed child entrypoint used only by execute_blind_replay()."""
    global KEYS
    try:
        request = parse(sys.stdin.buffer.read())
        exact(request, ["schema_version", "root", "files", "pins", "keys",
                        "case_id", "target_name", "mutated_artifact_path",
                        "mutated_artifact_sha256", "mutation_operator", "expected_invariant",
                        "authenticated_observed_at"])
        if integer(request["schema_version"], 1, 1) != 1:
            raise Reject("child request version")
        names = ["candidate", "dispatch", "roster", "verdict", "gates"]
        exact(request["files"], names); exact(request["pins"], names)
        # The child accepts a complete, closed test/deployment keyring.  It may
        # differ from this source file's bootstrap anchors (the builder suite
        # uses fresh public keys), but it cannot add roles or private material.
        exact(request["keys"], KEYS.keys())
        anchors = {ident(name): text(value) for name, value in request["keys"].items()}
        KEYS = anchors
        case_id = text(request["case_id"])
        if case_id not in BLIND_CASE_CONTRACTS:
            raise Reject("child semantic case")
        target_name, operator, invariant = BLIND_CASE_CONTRACTS[case_id]
        if (request["target_name"] != target_name or request["mutation_operator"] != operator or
                request["expected_invariant"] != invariant):
            raise Reject("child semantic contract")
        root = Path(text(request["root"]))
        mutated_path = text(request["mutated_artifact_path"])
        mutated_hash = digest(request["mutated_artifact_sha256"])
        # Pin before substitution, then map only the deployment-owned semantic
        # target.  This makes the trace depend on changed bytes, not case label.
        load_bytes_pinned(root, mutated_path, mutated_hash)
        request["files"] = dict(request["files"])
        request["pins"] = dict(request["pins"])
        semantic_target = SEMANTIC_TARGET_PATHS[target_name]
        if target_name in request["files"]:
            request["files"][target_name] = mutated_path
            request["pins"][target_name] = mutated_hash
        try:
            # The production parent supplies the observation it obtained from
            # the attested RFC3161 boundary.  It is not accepted from an
            # environment variable and cannot be reached by the public
            # decision API.  Sharing it bounds the child fanout to one global
            # decision window rather than one remote request per mutation.
            semantic_now = utc(text(request["authenticated_observed_at"]))
            decide_semantic_case(root, request["files"], request["pins"], case_id,
                                 semantic_target, mutated_path, mutated_hash,
                                 semantic_now=semantic_now)
        except TypedSemanticReject as exc:
            observation = canonical_json(exc.trace)
            sys.stdout.buffer.write(b"DENY\n")
            sys.stderr.buffer.write(SEMANTIC_REJECTION_PREFIX + observation + b"\n")
            return 2
        # A hostile input that unexpectedly ALLOWs is deliberately not rendered
        # as DENY, so the parent rejects the mismatch.
        sys.stdout.buffer.write((ALLOW + "\n").encode("ascii")); return 0
    except Exception:
        # Precondition/contract failures are intentionally generic and cannot
        # be accepted as semantic evidence by validate_semantic_observation().
        sys.stdout.buffer.write(b"DENY\n"); return 2


def main():
    if sys.argv[1:] == [BLIND_CHILD_SWITCH]:
        return blind_child_main()
    ap = argparse.ArgumentParser()
    ap.add_argument("--root", required=True)
    for name in ["candidate", "dispatch", "roster", "verdict", "gates"]:
        ap.add_argument("--" + name, required=True); ap.add_argument("--" + name + "-sha256", required=True)
    args = ap.parse_args()
    names = ["candidate", "dispatch", "roster", "verdict", "gates"]
    try:
        # The replay store is fail-closed and fixed relative to this deployed
        # executable.  A caller cannot reset nonce history by choosing another
        # directory.  Deployments must pre-create this directory with ACLs that
        # deny mutation by submitters and reviewers.
        result = decide(Path(args.root), {n: getattr(args, n) for n in names},
                        {n: getattr(args, n + "_sha256") for n in names})
        print(result); return 0
    except Exception:
        print(DENY); return 2


if __name__ == "__main__":
    sys.exit(main())
