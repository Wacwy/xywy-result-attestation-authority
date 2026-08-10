#!/usr/bin/env python3
from __future__ import annotations

import copy
import hashlib
import json
import os
import stat
import tempfile
import unittest
from pathlib import Path
from unittest import mock

import result_attestation as ra


def canonical(value: object) -> bytes:
    return ra.canonical_bytes(value)


class ResultAttestationTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name)
        self.evidence = self.root / "evidence"
        self.evidence.mkdir()
        self.files = {
            "builder-test-output.txt": b"pass\n",
            "builder-test-stderr.txt": b"",
            "builder-test-results.json": b'{"passed":true}\n',
        }
        for name, data in self.files.items():
            (self.evidence / name).write_bytes(data)
        from test_attestation_record import complete_record
        self.record = complete_record()
        self.record["result"]["stdout_sha256"] = hashlib.sha256(self.files["builder-test-output.txt"]).hexdigest()
        self.record["result"]["stdout_bytes"] = len(self.files["builder-test-output.txt"])
        self.record["result"]["stderr_sha256"] = hashlib.sha256(self.files["builder-test-stderr.txt"]).hexdigest()
        self.record["result"]["stderr_bytes"] = len(self.files["builder-test-stderr.txt"])
        self.record["result"]["result_artifact_sha256"] = hashlib.sha256(self.files["builder-test-results.json"]).hexdigest()
        self.record["result"]["result_artifact_bytes"] = len(self.files["builder-test-results.json"])
        self.record["result_sha256"] = hashlib.sha256(canonical(self.record["result"])).hexdigest()
        self.record["bindings"]["result_sha256"] = self.record["result_sha256"]
        self.record["bindings_sha256"] = hashlib.sha256(canonical(self.record["bindings"])).hexdigest()
        self.manifest_path = self.root / "execution-manifest.json"
        self.manifest_path.write_bytes(canonical({"schema_version": 1, "candidate_generation": "v35", "files": self.record["execution_snapshot_file_digests"]}))
        self.record["execution_manifest_sha256"] = hashlib.sha256(
            self.manifest_path.read_bytes()).hexdigest()
        self.record["bindings"]["execution_manifest_sha256"] = self.record[
            "execution_manifest_sha256"]
        sums_raw = "".join(
            f"{digest}  {relative}\n"
            for relative, digest in sorted(self.record["execution_snapshot_file_digests"].items())
        ).encode("ascii")
        self.record["manifest_sha256"] = hashlib.sha256(sums_raw).hexdigest()
        self.record["external_pin_manifest_sha256"] = self.record["manifest_sha256"]
        self.record["nonce_consumption_receipt"]["manifest_sha256"] = self.record["manifest_sha256"]
        request_fields = ("schema_version", "initiative_id", "candidate_generation",
                          "authorization_sha256", "release_nonce", "manifest_sha256",
                          "authority_roster_sha256", "client_challenge")
        request = {key: self.record["nonce_consumption_receipt"][key]
                   for key in request_fields}
        self.record["nonce_consumption_request_sha256"] = hashlib.sha256(
            canonical(request)).hexdigest()
        self.record["nonce_consumption_receipt_sha256"] = hashlib.sha256(
            canonical(self.record["nonce_consumption_receipt"])).hexdigest()
        self.record["bindings"]["candidate_manifest_sha256"] = self.record["manifest_sha256"]
        self.record["bindings"]["nonce_consumption_request_sha256"] = self.record["nonce_consumption_request_sha256"]
        self.record["bindings"]["nonce_consumption_receipt_sha256"] = self.record["nonce_consumption_receipt_sha256"]
        self.record["bindings_sha256"] = hashlib.sha256(canonical(self.record["bindings"])).hexdigest()
        self.record_path = self.root / "external-run.json"
        self.record_path.write_bytes(canonical(self.record))

    def tearDown(self):
        self.tmp.cleanup()

    def rewrite(self, record: dict):
        self.record_path.write_bytes(canonical(record))

    def test_valid_record_and_real_files_accept(self):
        validated = ra.validate_record_and_files(self.record_path, self.evidence, self.manifest_path)
        self.assertEqual(validated["result_sha256"], self.record["result_sha256"])

    def test_wrapper_digest_cannot_replace_canonical_sums_identity(self):
        forged = copy.deepcopy(self.record)
        forged["manifest_sha256"] = forged["execution_manifest_sha256"]
        forged["external_pin_manifest_sha256"] = forged["manifest_sha256"]
        forged["nonce_consumption_receipt"]["manifest_sha256"] = forged["manifest_sha256"]
        request_fields = ("schema_version", "initiative_id", "candidate_generation",
                          "authorization_sha256", "release_nonce", "manifest_sha256",
                          "authority_roster_sha256", "client_challenge")
        request = {key: forged["nonce_consumption_receipt"][key]
                   for key in request_fields}
        forged["nonce_consumption_request_sha256"] = hashlib.sha256(
            canonical(request)).hexdigest()
        forged["nonce_consumption_receipt_sha256"] = hashlib.sha256(
            canonical(forged["nonce_consumption_receipt"])).hexdigest()
        forged["bindings"]["candidate_manifest_sha256"] = forged["manifest_sha256"]
        forged["bindings"]["nonce_consumption_request_sha256"] = forged["nonce_consumption_request_sha256"]
        forged["bindings"]["nonce_consumption_receipt_sha256"] = forged["nonce_consumption_receipt_sha256"]
        forged["bindings_sha256"] = hashlib.sha256(canonical(forged["bindings"])).hexdigest()
        self.rewrite(forged)
        with self.assertRaisesRegex(ValueError, "canonical candidate manifest"):
            ra.validate_record_and_files(self.record_path, self.evidence,
                                         self.manifest_path)

    def test_execution_manifest_bytes_are_independently_bound(self):
        forged = copy.deepcopy(self.record)
        forged["execution_manifest_sha256"] = "a" * 64
        forged["bindings"]["execution_manifest_sha256"] = "a" * 64
        forged["bindings_sha256"] = hashlib.sha256(
            canonical(forged["bindings"])).hexdigest()
        self.rewrite(forged)
        with self.assertRaisesRegex(ValueError, "execution manifest digest"):
            ra.validate_record_and_files(self.record_path, self.evidence,
                                         self.manifest_path)

    def test_recomputed_success_cannot_hide_missing_or_changed_real_artifact(self):
        forged = copy.deepcopy(self.record)
        forged["result"]["result_artifact_sha256"] = "f" * 64
        forged["result_sha256"] = hashlib.sha256(
            canonical(forged["result"])).hexdigest()
        forged["bindings"]["result_sha256"] = forged["result_sha256"]
        forged["bindings_sha256"] = hashlib.sha256(
            canonical(forged["bindings"])).hexdigest()
        self.rewrite(forged)
        with self.assertRaisesRegex(ValueError, "evidence file mismatch"):
            ra.validate_record_and_files(self.record_path, self.evidence, self.manifest_path)

    def test_all_public_fields_recomputed_still_requires_sigstore(self):
        bundle = self.root / "bundle.json"
        bundle.write_text("{}", "ascii")
        policy_path = self.root / "policy.json"
        policy_path.write_text("{}", "ascii")
        cosign = self.root / "cosign.exe"
        cosign.write_bytes(b"not cosign")
        trusted = hashlib.sha256(policy_path.read_bytes()).hexdigest()
        with self.assertRaises(ValueError):
            ra.verify(record_path=self.record_path, evidence_dir=self.evidence,
                      manifest_path=self.manifest_path,
                      bundle_path=bundle, policy_path=policy_path,
                      cosign_path=cosign, trusted_policy_sha256=trusted)

    def test_unprovisioned_policy_fails_closed(self):
        policy = self.root / "policy.json"
        policy.write_bytes(canonical({}))
        with self.assertRaisesRegex(ValueError, "not provisioned"):
            ra.load_policy(policy, ra.TRUSTED_RESULT_ATTESTATION_POLICY_SHA256)

    def test_policy_requires_exact_commit_and_github_issuer(self):
        policy = self.complete_policy()
        policy["github_workflow_sha"] = "main"
        path = self.root / "policy.json"
        path.write_bytes(canonical(policy))
        digest = hashlib.sha256(path.read_bytes()).hexdigest()
        with self.assertRaisesRegex(ValueError, "workflow SHA"):
            ra.load_policy(path, digest)

    def test_policy_accepts_real_git_sha1_commit(self):
        policy = self.complete_policy()
        policy["github_workflow_sha"] = "9" * 40
        path = self.root / "policy.json"
        path.write_bytes(canonical(policy))
        digest = hashlib.sha256(path.read_bytes()).hexdigest()
        self.assertEqual(ra.load_policy(path, digest)["github_workflow_sha"],
                         "9" * 40)
        policy["github_workflow_sha"] = "9" * 64
        policy["oidc_issuer"] = "https://attacker.example"
        path.write_bytes(canonical(policy))
        digest = hashlib.sha256(path.read_bytes()).hexdigest()
        with self.assertRaisesRegex(ValueError, "policy scope"):
            ra.load_policy(path, digest)

    def test_sigstore_command_has_exact_claims_and_no_insecure_flags(self):
        policy = self.complete_policy()
        cosign = self.root / "cosign.exe"
        cosign.write_bytes(b"pinned-cosign")
        policy["cosign_sha256"] = hashlib.sha256(cosign.read_bytes()).hexdigest()
        bundle = self.root / "bundle.json"
        bundle.write_text("{}", "ascii")
        completed = mock.Mock(returncode=0, stdout=b"ok", stderr=b"")
        with mock.patch.object(ra.subprocess, "run", return_value=completed) as run:
            result = ra.verify_sigstore_bundle(
                record_path=self.record_path, bundle_path=bundle,
                policy=policy, cosign_path=cosign)
        command = run.call_args.args[0]
        self.assertTrue(result["verified"])
        self.assertIn("--new-bundle-format", command)
        self.assertIn("--certificate-identity", command)
        self.assertIn("--certificate-github-workflow-sha", command)
        self.assertNotIn("--insecure-ignore-tlog", command)
        self.assertNotIn("--insecure-ignore-sct", command)
        self.assertNotIn("--certificate-identity-regexp", command)

    def test_cosign_binary_replacement_rejected_before_execution(self):
        policy = self.complete_policy()
        cosign = self.root / "cosign.exe"
        cosign.write_bytes(b"changed")
        policy["cosign_sha256"] = "0" * 64
        bundle = self.root / "bundle.json"
        bundle.write_text("{}", "ascii")
        with mock.patch.object(ra.subprocess, "run") as run:
            with self.assertRaisesRegex(ValueError, "not policy-pinned"):
                ra.verify_sigstore_bundle(record_path=self.record_path,
                                           bundle_path=bundle, policy=policy,
                                           cosign_path=cosign)
        run.assert_not_called()

    @staticmethod
    def complete_policy():
        return {
            "schema_version": 1,
            "initiative_id": "PGK-FAILCLOSED-001",
            "candidate_generation": "v35",
            "oidc_issuer": "https://token.actions.githubusercontent.com",
            "certificate_identity":
                "https://github.com/example/xywy/.github/workflows/attest.yml@refs/heads/main",
            "github_workflow_repository": "example/xywy",
            "github_workflow_name": "attest",
            "github_workflow_ref": "refs/heads/main",
            "github_workflow_sha": "9" * 64,
            "github_workflow_trigger": "workflow_dispatch",
            "rekor_url": "https://rekor.sigstore.dev",
            "predicate_type": ra.EXPECTED_PREDICATE_TYPE,
            "cosign_sha256": "a" * 64,
        }


if __name__ == "__main__":
    unittest.main()
