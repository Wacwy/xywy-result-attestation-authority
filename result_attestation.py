#!/usr/bin/env python3
"""Verify externally issued, transparency-logged result attestations.

The runner's JSON and public SHA-256 fields are not authenticators.  This
module accepts a result only after (1) hashing every referenced result file,
(2) validating the closed result schema and bindings, and (3) asking a pinned
Cosign binary to verify a Sigstore bundle against one exact GitHub Actions
OIDC identity.  No insecure Cosign switches exist in this interface.

The policy digest is deliberately unprovisioned in the builder candidate.  A
fresh verifier generation must freeze an externally published policy digest;
passing a different policy on the command line cannot replace that trust root.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import subprocess
from pathlib import Path

from attestation_record import (BINDING_FIELDS, KIND as EXPECTED_KIND,
                                RESULT_FIELDS, load_and_validate)

HEX64 = re.compile(r"^[0-9a-f]{64}$")
GIT_COMMIT = re.compile(r"^(?:[0-9a-f]{40}|[0-9a-f]{64})$")
HTTPS_URL = re.compile(r"^https://[^\s]+$")
EXPECTED_PREDICATE_TYPE = "https://xywy.example/attestation/pgk-result/v1"
TRUSTED_RESULT_ATTESTATION_POLICY_SHA256 = (
    "UNPROVISIONED_EXTERNAL_RESULT_ATTESTATION_POLICY"
)

POLICY_FIELDS = {
    "schema_version", "initiative_id", "candidate_generation", "oidc_issuer",
    "certificate_identity", "github_workflow_repository",
    "github_workflow_name", "github_workflow_ref", "github_workflow_sha",
    "github_workflow_trigger", "rekor_url", "predicate_type",
    "cosign_sha256",
}


def sha256_bytes(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb", buffering=0) as stream:
        while chunk := stream.read(1024 * 1024):
            digest.update(chunk)
    return digest.hexdigest()


def canonical_bytes(value: object) -> bytes:
    return (json.dumps(value, ensure_ascii=True, sort_keys=True,
                       separators=(",", ":")) + "\n").encode("ascii")


def load_canonical_object(path: Path) -> tuple[dict, bytes]:
    raw = path.resolve(strict=True).read_bytes()
    try:
        value = json.loads(raw.decode("ascii"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ValueError(f"non-canonical JSON: {path.name}") from exc
    if not isinstance(value, dict) or raw != canonical_bytes(value):
        raise ValueError(f"non-canonical JSON: {path.name}")
    return value, raw


def _exact_evidence_child(evidence_dir: Path, relative: str) -> Path:
    if not isinstance(relative, str) or not relative or "\\" in relative:
        raise ValueError("invalid evidence-relative path")
    rel = Path(relative)
    if rel.is_absolute() or len(rel.parts) != 1 or rel.name != relative:
        raise ValueError("result artifact must be a direct evidence child")
    root = evidence_dir.resolve(strict=True)
    child = (root / rel).resolve(strict=True)
    if child.parent != root or not child.is_file() or child.is_symlink():
        raise ValueError("result artifact path alias")
    return child


def _require_external_artifact(candidate_root: Path, path: Path, label: str) -> Path:
    candidate = candidate_root.resolve(strict=True)
    resolved = path.resolve(strict=True)
    if resolved == candidate or candidate in resolved.parents:
        raise ValueError(f"{label} must be outside candidate")
    return resolved


def load_policy(path: Path, trusted_digest: str) -> dict:
    if not HEX64.fullmatch(trusted_digest):
        raise ValueError("external result-attestation policy is not provisioned")
    policy, raw = load_canonical_object(path)
    if sha256_bytes(raw) != trusted_digest:
        raise ValueError("result-attestation policy is not trusted")
    if set(policy) != POLICY_FIELDS:
        raise ValueError("result-attestation policy field set")
    if (policy["schema_version"] != 1
            or policy["initiative_id"] != "PGK-FAILCLOSED-001"
            or policy["candidate_generation"] != "v35"
            or policy["oidc_issuer"] != "https://token.actions.githubusercontent.com"
            or policy["predicate_type"] != EXPECTED_PREDICATE_TYPE):
        raise ValueError("result-attestation policy scope")
    for field in (
        "certificate_identity", "github_workflow_repository",
        "github_workflow_name", "github_workflow_ref", "github_workflow_sha",
        "github_workflow_trigger", "rekor_url",
    ):
        if not isinstance(policy[field], str) or not policy[field]:
            raise ValueError(f"empty result-attestation policy value: {field}")
    if not HTTPS_URL.fullmatch(policy["certificate_identity"]):
        raise ValueError("certificate identity must be one exact HTTPS URI")
    if not HTTPS_URL.fullmatch(policy["rekor_url"]):
        raise ValueError("Rekor URL must be HTTPS")
    if not GIT_COMMIT.fullmatch(policy["github_workflow_sha"]):
        raise ValueError("workflow SHA must be an exact commit")
    if not HEX64.fullmatch(policy["cosign_sha256"]):
        raise ValueError("Cosign digest")
    return policy


def validate_record_and_files(record_path: Path, evidence_dir: Path,
                              manifest_path: Path) -> dict:
    manifest, manifest_raw = load_canonical_object(manifest_path)
    if set(manifest) != {"schema_version", "candidate_generation", "files"} \
            or manifest["schema_version"] != 1 \
            or manifest["candidate_generation"] != "v35":
        raise ValueError("execution manifest scope")
    record, _ = load_and_validate(
        record_path, expected_manifest_files=manifest["files"])
    # The security identity is the canonical candidate SHA256SUMS byte digest,
    # externally pinned and authorized by custodians. execution-manifest.json
    # is a transport wrapper for the exact same file map and therefore must not
    # replace that identity with the digest of a different serialization.
    sums_raw = "".join(
        f"{digest}  {relative}\n"
        for relative, digest in sorted(manifest["files"].items())
    ).encode("ascii")
    if record["manifest_sha256"] != sha256_bytes(sums_raw):
        raise ValueError("canonical candidate manifest digest")
    if record["execution_manifest_sha256"] != sha256_bytes(manifest_raw):
        raise ValueError("execution manifest digest")
    result = record["result"]
    files = (
        ("builder-test-output.txt", "stdout_sha256", "stdout_bytes"),
        ("builder-test-stderr.txt", "stderr_sha256", "stderr_bytes"),
        (result.get("result_artifact_relative"), "result_artifact_sha256",
         "result_artifact_bytes"),
    )
    for relative, digest_field, size_field in files:
        path = _exact_evidence_child(evidence_dir, relative)
        size = result.get(size_field)
        if (not isinstance(size, int) or isinstance(size, bool) or size < 0
                or path.stat().st_size != size
                or sha256_file(path) != result.get(digest_field)):
            raise ValueError(f"evidence file mismatch: {relative}")
    return record


def verify_sigstore_bundle(*, record_path: Path, bundle_path: Path,
                           policy: dict, cosign_path: Path) -> dict:
    cosign = cosign_path.resolve(strict=True)
    if not cosign.is_file() or cosign.is_symlink():
        raise ValueError("Cosign executable path alias")
    if sha256_file(cosign) != policy["cosign_sha256"]:
        raise ValueError("Cosign executable is not policy-pinned")
    bundle = bundle_path.resolve(strict=True)
    if not bundle.is_file() or bundle.is_symlink():
        raise ValueError("Sigstore bundle path alias")
    command = [
        str(cosign), "verify-blob-attestation", "--new-bundle-format",
        "--bundle", str(bundle),
        "--certificate-identity", policy["certificate_identity"],
        "--certificate-oidc-issuer", policy["oidc_issuer"],
        "--certificate-github-workflow-repository",
        policy["github_workflow_repository"],
        "--certificate-github-workflow-name", policy["github_workflow_name"],
        "--certificate-github-workflow-ref", policy["github_workflow_ref"],
        "--certificate-github-workflow-sha", policy["github_workflow_sha"],
        "--certificate-github-workflow-trigger",
        policy["github_workflow_trigger"],
        "--rekor-url", policy["rekor_url"],
        "--type", policy["predicate_type"],
        str(record_path.resolve(strict=True)),
    ]
    environment = dict(os.environ)
    environment["COSIGN_EXPERIMENTAL"] = "0"
    completed = subprocess.run(
        command, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
        stderr=subprocess.PIPE, timeout=120, check=False, env=environment,
    )
    if completed.returncode != 0:
        detail = completed.stderr.decode("utf-8", errors="replace")[-1000:]
        raise ValueError(f"Sigstore result attestation rejected: {detail}")
    return {
        "verified": True,
        "record_sha256": sha256_file(record_path),
        "bundle_sha256": sha256_file(bundle),
        "policy_sha256": TRUSTED_RESULT_ATTESTATION_POLICY_SHA256,
        "certificate_identity": policy["certificate_identity"],
        "oidc_issuer": policy["oidc_issuer"],
        "rekor_url": policy["rekor_url"],
    }


def verify(*, record_path: Path, evidence_dir: Path, manifest_path: Path, bundle_path: Path,
           policy_path: Path, cosign_path: Path,
           trusted_policy_sha256: str = TRUSTED_RESULT_ATTESTATION_POLICY_SHA256) -> dict:
    candidate_root = Path(__file__).resolve().parent
    record = _require_external_artifact(candidate_root, record_path, "record")
    evidence = _require_external_artifact(candidate_root, evidence_dir,
                                          "evidence directory")
    manifest = _require_external_artifact(candidate_root, manifest_path,
                                          "execution manifest")
    bundle = _require_external_artifact(candidate_root, bundle_path,
                                        "Sigstore bundle")
    policy_path = _require_external_artifact(candidate_root, policy_path,
                                             "attestation policy")
    cosign_path = _require_external_artifact(candidate_root, cosign_path,
                                             "Cosign executable")
    policy = load_policy(policy_path, trusted_policy_sha256)
    validated = validate_record_and_files(record, evidence, manifest)
    outcome = verify_sigstore_bundle(record_path=record,
                                  bundle_path=bundle,
                                  policy=policy, cosign_path=cosign_path)
    outcome["authority_roster_sha256"] = validated["bindings"][
        "authority_roster_sha256"]
    outcome["verified_authorities"] = sorted(
        validated["threshold_authorization"]["verified_authorities"],
        key=lambda item: item["key_id"])
    return outcome


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--record", required=True, type=Path)
    parser.add_argument("--evidence-dir", required=True, type=Path)
    parser.add_argument("--manifest", required=True, type=Path)
    parser.add_argument("--bundle", required=True, type=Path)
    parser.add_argument("--policy", required=True, type=Path)
    parser.add_argument("--cosign", required=True, type=Path)
    args = parser.parse_args()
    result = verify(record_path=args.record, evidence_dir=args.evidence_dir,
                    manifest_path=args.manifest,
                    bundle_path=args.bundle, policy_path=args.policy,
                    cosign_path=args.cosign)
    print(json.dumps(result, sort_keys=True, separators=(",", ":")))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
