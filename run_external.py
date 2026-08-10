#!/usr/bin/env python3
"""Run PGK v35 only after an externally witnessed one-time authorization.

The source candidate is authentication input, never executable input.  Every
manifest-pinned byte is copied through an already-open source handle into a
new private directory, rehashed there, and the child interpreter is then
started only from that snapshot.  A concurrent source-tree replacement can
therefore neither choose the executed bytes nor be hidden by restoring them.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import shutil
import stat
import subprocess
import sys
import tempfile
from pathlib import Path

from authority_bundle import verify_threshold_authorization
from checkpoint_quorum import Service as CheckpointService
from checkpoint_quorum import commit as commit_checkpoint
from checkpoint_quorum import post_https as post_checkpoint_https
from checkpoint_quorum import read_current as read_checkpoint
from nonce_ledger import (build_request, consume_once_https,
                          verify_consumption_receipt)

AUTHORITY_ROOT = Path(__file__).resolve().parent
# In the protected workflow this names the digest-pinned candidate extracted
# from the immutable input archive.  The executing orchestration code and trust
# constants remain in AUTHORITY_ROOT; candidate bytes are only snapshot input.
ROOT = Path(os.environ.get("PGK_CANDIDATE_DIR", str(AUTHORITY_ROOT))).resolve()
MANIFEST = ROOT / "SHA256SUMS.txt"
SUITE_DEADLINE_SECONDS = 300
COPY_CHUNK_BYTES = 1024 * 1024
# Provisioned only by a fresh verifier generation after an external authority
# has published an immutable roster.  Deliberately fail-closed in the builder
# candidate: replacing this placeholder locally is not independent approval.
TRUSTED_AUTHORITY_ROSTER_SHA256 = "UNPROVISIONED_EXTERNAL_AUTHORITY_ROSTER"
# These constants must be provisioned only by a fresh, independently reviewed
# verifier generation.  The builder deliberately ships no usable trust root.
NONCE_LEDGER_URL = "UNPROVISIONED_EXTERNAL_NONCE_LEDGER_URL"
NONCE_LEDGER_TLS_LEAF_SHA256 = "UNPROVISIONED_EXTERNAL_NONCE_LEDGER_TLS_PIN"
TRUSTED_NONCE_LEDGER_SPKI_SHA256 = "UNPROVISIONED_EXTERNAL_NONCE_LEDGER_KEY"
TRUSTED_NONCE_WITNESS_SPKI_SHA256 = "UNPROVISIONED_EXTERNAL_WITNESS_KEY"
TRUSTED_NONCE_LEDGER_EPOCH = "UNPROVISIONED_EXTERNAL_LEDGER_EPOCH"
# Deployment-owned state which is administered independently of the candidate.
# It atomically moves from the current checkpoint to exactly one successor.
CHECKPOINT_SERVICE_A_URL = "UNPROVISIONED_EXTERNAL_CHECKPOINT_SERVICE_A_URL"
CHECKPOINT_SERVICE_B_URL = "UNPROVISIONED_EXTERNAL_CHECKPOINT_SERVICE_B_URL"
CHECKPOINT_SERVICE_A_TLS_LEAF_SHA256 = "UNPROVISIONED_CHECKPOINT_A_TLS_PIN"
CHECKPOINT_SERVICE_B_TLS_LEAF_SHA256 = "UNPROVISIONED_CHECKPOINT_B_TLS_PIN"
TRUSTED_CHECKPOINT_A_SPKI_SHA256 = "UNPROVISIONED_CHECKPOINT_A_SIGNING_KEY"
TRUSTED_CHECKPOINT_B_SPKI_SHA256 = "UNPROVISIONED_CHECKPOINT_B_SIGNING_KEY"
CHECKPOINT_SERVICE_A_CUSTODIAN_ID = "UNPROVISIONED_CHECKPOINT_A_CUSTODIAN"
CHECKPOINT_SERVICE_B_CUSTODIAN_ID = "UNPROVISIONED_CHECKPOINT_B_CUSTODIAN"

# Exact, generation-specific evidence discriminator.  Downstream consumers
# must compare this complete value, never a prefix or a prior-generation kind.
EXTERNAL_RUN_EVIDENCE_KIND = (
    "PGKv35AuthorityObservedExternalRun"
)


def sha(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb", buffering=0) as stream:
        while True:
            chunk = stream.read(COPY_CHUNK_BYTES)
            if not chunk:
                return digest.hexdigest()
            digest.update(chunk)


def sha_bytes(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def canonical_digest(value: object) -> str:
    raw = json.dumps(value, sort_keys=True, separators=(",", ":")).encode(
        "ascii") + b"\n"
    return sha_bytes(raw)


def load_external_pin(path: Path):
    """Parse the exact external manifest pin; authority verification follows."""
    pin = path.resolve(strict=True)
    if pin == ROOT or ROOT in pin.parents:
        raise ValueError("external pin must be outside candidate")
    pin_bytes = pin.read_bytes()
    if b"\r" in pin_bytes or not pin_bytes.endswith(b"\n"):
        raise ValueError("external pin must be canonical LF text")
    lines = pin_bytes.decode("ascii").splitlines()
    if len(lines) != 1:
        raise ValueError("external pin must contain exactly one record")
    digest, relative = lines[0].split("  ", 1)
    required = f"qa/orchestration/recovery/{ROOT.name}/SHA256SUMS.txt"
    if len(digest) != 64 or any(c not in "0123456789abcdef" for c in digest):
        raise ValueError("external pin digest")
    if relative != required:
        raise ValueError("external pin target")
    return pin, pin_bytes, digest, required


def require_external_authority_artifacts(paths: list[Path]) -> None:
    """Reject a deployment that tries to bootstrap authority inside candidate."""
    for supplied in paths:
        resolved = supplied.resolve(strict=True)
        if resolved == ROOT or ROOT in resolved.parents:
            raise ValueError("authority artifact must be outside candidate")


def load_manifest(external_digest: str):
    if sha(MANIFEST) != external_digest:
        raise ValueError("candidate manifest does not match external pin")
    expected = {}
    for line in MANIFEST.read_text("ascii").splitlines():
        digest, relative = line.split("  ", 1)
        if (relative in expected or len(digest) != 64
                or any(c not in "0123456789abcdef" for c in digest)):
            raise ValueError("invalid candidate manifest")
        relative_path = Path(relative)
        if (relative_path.is_absolute() or ".." in relative_path.parts
                or relative_path.as_posix() != relative):
            raise ValueError("manifest path escape")
        expected[relative] = digest
    actual = {}
    for path in ROOT.rglob("*"):
        if not path.is_file() or path == MANIFEST:
            continue
        resolved = path.resolve(strict=True)
        if resolved == ROOT or ROOT not in resolved.parents:
            raise ValueError("candidate path alias")
        relative = path.relative_to(ROOT).as_posix()
        actual[relative] = sha(path)
    if actual != expected:
        raise ValueError("candidate file-set or digest mismatch")
    return {"manifest_sha256": external_digest, "files": expected}


def copy_verified_snapshot(expected: dict[str, str], parent: Path) -> Path:
    """Copy pinned bytes without ever reopening a verified source by name.

    The digest is calculated over the exact bytes written to the snapshot.
    We also compare source fstat metadata before/after the copy.  The snapshot
    is private to this process and made read-only before execution.
    """
    snapshot = Path(tempfile.mkdtemp(prefix="pgk-v26-exec-", dir=str(parent))).resolve()
    try:
        for relative, expected_digest in sorted(expected.items()):
            source = ROOT / relative
            destination = snapshot / relative
            destination.parent.mkdir(parents=True, exist_ok=True)
            digest = hashlib.sha256()
            with source.open("rb", buffering=0) as source_stream:
                identity_before = os.fstat(source_stream.fileno())
                resolved_source = source.resolve(strict=True)
                if resolved_source == ROOT or ROOT not in resolved_source.parents:
                    raise ValueError(f"source path alias: {relative}")
                with destination.open("xb", buffering=0) as destination_stream:
                    while True:
                        chunk = source_stream.read(COPY_CHUNK_BYTES)
                        if not chunk:
                            break
                        digest.update(chunk)
                        destination_stream.write(chunk)
                    destination_stream.flush()
                    os.fsync(destination_stream.fileno())
                identity_after = os.fstat(source_stream.fileno())
            stable = (
                identity_before.st_dev == identity_after.st_dev
                and identity_before.st_ino == identity_after.st_ino
                and identity_before.st_size == identity_after.st_size
                and identity_before.st_mtime_ns == identity_after.st_mtime_ns
            )
            if not stable or digest.hexdigest() != expected_digest or sha(destination) != expected_digest:
                raise ValueError(f"source changed while snapshotting: {relative}")
            destination.chmod(stat.S_IREAD)
        # Re-verify the complete copied file set.  Manifest itself is supplied
        # by the external pin and is not needed by the executed suite.
        copied = {
            path.relative_to(snapshot).as_posix(): sha(path)
            for path in snapshot.rglob("*") if path.is_file()
        }
        if copied != expected:
            raise ValueError("execution snapshot mismatch")
        for directory in sorted(
                (p for p in snapshot.rglob("*") if p.is_dir()),
                key=lambda p: len(p.parts), reverse=True):
            directory.chmod(stat.S_IREAD | stat.S_IEXEC)
        return snapshot
    except Exception:
        shutil.rmtree(snapshot, ignore_errors=True)
        raise


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--evidence-dir")
    parser.add_argument("--external-pin", required=True)
    parser.add_argument("--authority-roster", required=True)
    parser.add_argument("--authorization", required=True)
    parser.add_argument("--authority-public-key-dir", required=True)
    parser.add_argument("--authority-signature-dir", required=True)
    parser.add_argument("--nonce-ledger-public-key", required=True)
    parser.add_argument("--nonce-witness-public-key", required=True)
    parser.add_argument("--checkpoint-a-public-key", required=True)
    parser.add_argument("--checkpoint-b-public-key", required=True)
    parser.add_argument("--execution-manifest", required=True)
    args = parser.parse_args()
    require_external_authority_artifacts([
        Path(args.authority_roster), Path(args.authorization),
        Path(args.authority_public_key_dir), Path(args.authority_signature_dir),
        Path(args.nonce_ledger_public_key), Path(args.nonce_witness_public_key),
        Path(args.checkpoint_a_public_key), Path(args.checkpoint_b_public_key),
    ])
    external_pin, external_pin_bytes, external_digest, pin_target = load_external_pin(
        Path(args.external_pin))
    authority = verify_threshold_authorization(
        roster_path=Path(args.authority_roster),
        authorization_path=Path(args.authorization),
        public_key_dir=Path(args.authority_public_key_dir),
        signature_dir=Path(args.authority_signature_dir),
        trusted_roster_sha256=TRUSTED_AUTHORITY_ROSTER_SHA256,
        expected_manifest_sha256=external_digest,
        expected_pin_sha256=hashlib.sha256(external_pin_bytes).hexdigest(),
        expected_pin_target=pin_target,
    )
    # Consume the release nonce before creating any execution snapshot or
    # starting promotion-capable code.  The fresh client challenge prevents a
    # captured success receipt from being replayed to satisfy a later run.
    consume_request, consume_request_raw = build_request(
        authorization_sha256=authority["authorization_sha256"],
        release_nonce=authority["release_nonce"],
        manifest_sha256=external_digest,
        authority_roster_sha256=authority["authority_roster_sha256"],
    )
    receipt_raw, ledger_signature, witness_signature = consume_once_https(
        url=NONCE_LEDGER_URL,
        tls_leaf_cert_sha256=NONCE_LEDGER_TLS_LEAF_SHA256,
        request_raw=consume_request_raw,
    )
    services = (
        CheckpointService("checkpoint-a", CHECKPOINT_SERVICE_A_CUSTODIAN_ID,
                          CHECKPOINT_SERVICE_A_URL,
                          CHECKPOINT_SERVICE_A_TLS_LEAF_SHA256,
                          Path(args.checkpoint_a_public_key),
                          TRUSTED_CHECKPOINT_A_SPKI_SHA256,
                          lambda raw: post_checkpoint_https(
                              CHECKPOINT_SERVICE_A_URL,
                              CHECKPOINT_SERVICE_A_TLS_LEAF_SHA256, raw)),
        CheckpointService("checkpoint-b", CHECKPOINT_SERVICE_B_CUSTODIAN_ID,
                          CHECKPOINT_SERVICE_B_URL,
                          CHECKPOINT_SERVICE_B_TLS_LEAF_SHA256,
                          Path(args.checkpoint_b_public_key),
                          TRUSTED_CHECKPOINT_B_SPKI_SHA256,
                          lambda raw: post_checkpoint_https(
                              CHECKPOINT_SERVICE_B_URL,
                              CHECKPOINT_SERVICE_B_TLS_LEAF_SHA256, raw)),
    )
    current_checkpoint = read_checkpoint(services, TRUSTED_NONCE_LEDGER_EPOCH)
    consumption_receipt = verify_consumption_receipt(
            request=consume_request,
            receipt_raw=receipt_raw,
            ledger_signature_b64=ledger_signature,
            witness_signature_b64=witness_signature,
            ledger_public_key_path=Path(args.nonce_ledger_public_key),
            witness_public_key_path=Path(args.nonce_witness_public_key),
            trusted_ledger_spki_sha256=TRUSTED_NONCE_LEDGER_SPKI_SHA256,
            trusted_witness_spki_sha256=TRUSTED_NONCE_WITNESS_SPKI_SHA256,
            trusted_ledger_epoch=TRUSTED_NONCE_LEDGER_EPOCH,
            trusted_prior_tree_size=current_checkpoint["tree_size"],
            trusted_prior_root_sha256=current_checkpoint["tree_root_sha256"],
        )
    # Independently pinned services compare-and-swap the same signed head.
    # Local rollback cannot reopen a sibling. A partial commit wedges closed.
    commit_checkpoint(services, current_checkpoint, receipt_raw,
                      consumption_receipt)
    if args.evidence_dir:
        evidence = Path(args.evidence_dir).resolve()
        if evidence == ROOT or ROOT in evidence.parents:
            raise SystemExit("evidence directory must be outside candidate")
        evidence.mkdir(parents=True, exist_ok=False)
    else:
        evidence = Path(tempfile.mkdtemp(prefix="pgk-v26-evidence-")).resolve()

    before = load_manifest(external_digest)
    execution_manifest_path = Path(args.execution_manifest).resolve(strict=True)
    execution_manifest_raw = execution_manifest_path.read_bytes()
    execution_manifest = json.loads(execution_manifest_raw.decode("ascii"))
    canonical_execution_manifest = (json.dumps(
        execution_manifest, ensure_ascii=True, sort_keys=True,
        separators=(",", ":")) + "\n").encode("ascii")
    if execution_manifest_raw != canonical_execution_manifest:
        raise ValueError("execution manifest canonical form")
    if (set(execution_manifest) != {"schema_version", "candidate_generation", "files"}
            or execution_manifest["schema_version"] != 1
            or execution_manifest["candidate_generation"] != "v35"
            or execution_manifest["files"] != before["files"]):
        raise ValueError("execution manifest candidate binding")
    execution_manifest_sha256 = hashlib.sha256(execution_manifest_raw).hexdigest()
    # Place the snapshot outside both candidate and evidence.  Evidence remains
    # writable while executed code and imports live only in the private copy.
    snapshot_parent = Path(tempfile.gettempdir()).resolve()
    snapshot = copy_verified_snapshot(before["files"], snapshot_parent)
    snapshot_digests = {
        relative: sha(snapshot / relative) for relative in before["files"]
    }
    try:
        env = dict(os.environ)
        env["PYTHONDONTWRITEBYTECODE"] = "1"
        workspace = Path(os.environ.get(
            "PGK_V21_WORKSPACE_ROOT", str(AUTHORITY_ROOT.parents[3]))).resolve()
        support = str(workspace / ".toolchains" / "rfc3161ng")
        env["PYTHONPATH"] = os.pathsep.join([support, str(snapshot)])
        # test_kernel resolves the workspace toolchain relative to HERE.  It
        # must execute from the snapshot nevertheless, so supply the original
        # authenticated workspace root as non-executable test data.
        env["PGK_V21_WORKSPACE_ROOT"] = str(workspace)
        result_path = evidence / "builder-test-results.json"
        completed = subprocess.run(
            [sys.executable, str(snapshot / "test_kernel.py"), "--json-out", str(result_path)],
            cwd=str(evidence), env=env, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            check=False, timeout=SUITE_DEADLINE_SECONDS,
        )
        (evidence / "builder-test-output.txt").write_bytes(completed.stdout)
        (evidence / "builder-test-stderr.txt").write_bytes(completed.stderr)
        snapshot_after = {
            relative: sha(snapshot / relative) for relative in before["files"]
        }
        after = load_manifest(external_digest)
        unchanged = before == after
        snapshot_unchanged = snapshot_digests == snapshot_after == before["files"]
        checkpoint_after = {
            "ledger_epoch": consumption_receipt["ledger_epoch"],
            "tree_size": consumption_receipt["tree_size"],
            "tree_root_sha256": consumption_receipt["tree_root_sha256"],
        }
        stdout_sha256 = sha(evidence / "builder-test-output.txt")
        stderr_sha256 = sha(evidence / "builder-test-stderr.txt")
        if result_path.is_file():
            result_artifact_sha256 = sha(result_path)
            result_artifact_bytes = result_path.stat().st_size
        else:
            result_artifact_sha256 = None
            result_artifact_bytes = None
        result = {
            "suite_exit_code": completed.returncode,
            "candidate_unchanged": unchanged,
            "execution_snapshot_unchanged": snapshot_unchanged,
            "executed_entrypoint_relative": "test_kernel.py",
            "executed_entrypoint_sha256": snapshot_digests["test_kernel.py"],
            "execution_snapshot_file_digests_sha256": canonical_digest(
                snapshot_digests),
            "stdout_sha256": stdout_sha256,
            "stdout_bytes": len(completed.stdout),
            "stderr_sha256": stderr_sha256,
            "stderr_bytes": len(completed.stderr),
            "result_artifact_relative": "builder-test-results.json",
            "result_artifact_sha256": result_artifact_sha256,
            "result_artifact_bytes": result_artifact_bytes,
        }
        result_sha256 = canonical_digest(result)
        bindings = {
            "candidate_generation": "v35",
            "candidate_manifest_sha256": external_digest,
            "execution_manifest_sha256": execution_manifest_sha256,
            "external_pin_sha256": sha(external_pin),
            "authority_roster_sha256": authority["authority_roster_sha256"],
            "authorization_sha256": authority["authorization_sha256"],
            "nonce_consumption_request_sha256": hashlib.sha256(
                consume_request_raw).hexdigest(),
            "nonce_consumption_receipt_sha256": hashlib.sha256(receipt_raw).hexdigest(),
            "checkpoint_before": current_checkpoint,
            "checkpoint_after": checkpoint_after,
            "checkpoint_service_bindings": [
                {
                    "service_id": service.service_id,
                    "custodian_id": service.custodian_id,
                    "origin": service.endpoint_origin,
                    "tls_leaf_sha256": service.tls_leaf_cert_sha256,
                    "signing_spki_sha256": service.public_key_spki_sha256,
                }
                for service in services
            ],
            "result_sha256": result_sha256,
        }
        # Emit only the closed, location-independent statement the external
        # signer is allowed to attest. Paths and file counts are not claims.
        record = {
            "schema_version": 1,
            "kind": EXTERNAL_RUN_EVIDENCE_KIND,
            "candidate_generation": "v35",
            "threshold_authorization": authority,
            "nonce_consumption_request_sha256": hashlib.sha256(consume_request_raw).hexdigest(),
            "nonce_consumption_receipt": consumption_receipt,
            "nonce_consumption_receipt_sha256": hashlib.sha256(receipt_raw).hexdigest(),
            "external_pin_manifest_sha256": external_digest,
            "manifest_sha256": before["manifest_sha256"],
            "execution_manifest_sha256": execution_manifest_sha256,
            "execution_snapshot_file_digests": snapshot_digests,
            "result": result,
            "result_sha256": result_sha256,
            "bindings": bindings,
            "bindings_sha256": canonical_digest(bindings),
        }
        record_raw = (json.dumps(record, ensure_ascii=True, sort_keys=True,
                                 separators=(",", ":")) + "\n")
        (evidence / "external-run.json").write_text(
            record_raw, "ascii", newline="\n")
        print(record_raw, end="")
        return 0 if completed.returncode == 0 and unchanged and snapshot_unchanged else 1
    finally:
        # Restore permissions before cleanup on Windows.
        for path in snapshot.rglob("*"):
            try:
                path.chmod(stat.S_IWRITE | stat.S_IREAD | (stat.S_IEXEC if path.is_dir() else 0))
            except OSError:
                pass
        snapshot.chmod(stat.S_IWRITE | stat.S_IREAD | stat.S_IEXEC)
        shutil.rmtree(snapshot, ignore_errors=False)


if __name__ == "__main__":
    raise SystemExit(main())
