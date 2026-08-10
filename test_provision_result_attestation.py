#!/usr/bin/env python3
from __future__ import annotations

import subprocess
import tempfile
import unittest
from pathlib import Path

import result_attestation as ra

HERE = Path(__file__).resolve().parent
COSIGN = HERE.parents[3] / ".tools" / "bin" / "cosign.exe"


class ProvisioningTests(unittest.TestCase):
    def test_generator_emits_verifier_canonical_policy(self):
        with tempfile.TemporaryDirectory() as tmp:
            output = Path(tmp) / "handoff"
            completed = subprocess.run([
                "powershell", "-NoProfile", "-File",
                str(HERE / "provision_result_attestation.ps1"),
                "-OwnerRepository", "example/xywy",
                "-WorkflowName", "attest",
                "-ProtectedRef", "refs/heads/main",
                "-WorkflowSha", "9" * 40,
                "-CertificateIdentity",
                "https://github.com/example/xywy/.github/workflows/attest.yml@refs/heads/main",
                "-CosignPath", str(COSIGN),
                "-OutputDirectory", str(output),
            ], stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=False)
            self.assertEqual(completed.returncode, 0,
                             completed.stderr.decode(errors="replace"))
            digest = (output / "TRUSTED_POLICY_SHA256.txt").read_text(
                "ascii").strip()
            policy = ra.load_policy(
                output / "result-attestation-policy.json", digest)
            self.assertEqual(policy["github_workflow_repository"],
                             "example/xywy")
            self.assertTrue((output / "handoff.json").is_file())

    def test_generator_rejects_identity_from_different_repository(self):
        with tempfile.TemporaryDirectory() as tmp:
            output = Path(tmp) / "handoff"
            completed = subprocess.run([
                "powershell", "-NoProfile", "-File",
                str(HERE / "provision_result_attestation.ps1"),
                "-OwnerRepository", "example/xywy", "-WorkflowName", "attest",
                "-ProtectedRef", "refs/heads/main", "-WorkflowSha", "9" * 40,
                "-CertificateIdentity",
                "https://github.com/attacker/xywy/.github/workflows/attest.yml@refs/heads/main",
                "-CosignPath", str(COSIGN), "-OutputDirectory", str(output),
            ], stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=False)
            self.assertNotEqual(completed.returncode, 0)
            self.assertFalse(output.exists())


if __name__ == "__main__":
    unittest.main()
