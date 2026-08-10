#!/usr/bin/env python3
from __future__ import annotations

import ast
import os
import tempfile
import unittest
from pathlib import Path
from unittest import mock

HERE = Path(__file__).resolve().parent


class GithubAuthorityTests(unittest.TestCase):
    def test_runner_delegates_only_to_reviewed_connector(self):
        source = (HERE / "github_authority" / "run_v35_authority.py").read_text("utf-8")
        self.assertNotIn("subprocess", source)
        self.assertNotIn("external-run.json", source)
        self.assertIn("construct_record", source)
        ast.parse(source)

    def test_connector_uses_closed_arguments_and_rejects_missing_bundle(self):
        from github_authority.construct_v35_record import construct_record
        with tempfile.TemporaryDirectory() as td:
            base = Path(td); root = base / "input"; root.mkdir()
            candidate = root / "candidate"; candidate.mkdir()
            with mock.patch.dict(os.environ, {"PGK_DEPLOYMENT_ROOT":
                                               str(base / "missing")}, clear=False):
                with self.assertRaises(FileNotFoundError):
                    construct_record(input_root=root, candidate_root=candidate,
                                     evidence_dir=root / "evidence")

    def test_connector_rejects_file_where_key_directory_required(self):
        from github_authority.construct_v35_record import construct_record, REQUIRED_DEPLOYMENT_FILES
        with tempfile.TemporaryDirectory() as td:
            base = Path(td); root = base / "input"; root.mkdir()
            candidate = root / "candidate"; candidate.mkdir()
            deployment = base / "deployment"; deployment.mkdir()
            for relative in REQUIRED_DEPLOYMENT_FILES.values():
                (deployment / relative).write_bytes(b"x")
            with mock.patch.dict(os.environ, {"PGK_DEPLOYMENT_ROOT":
                                               str(deployment)}, clear=False):
                with self.assertRaisesRegex(RuntimeError, "artifact type"):
                    construct_record(input_root=root, candidate_root=candidate,
                                     evidence_dir=root / "evidence")

    def test_connector_does_not_accept_caller_record_or_shell(self):
        source = (HERE / "github_authority" / "construct_v35_record.py").read_text("utf-8")
        self.assertNotIn("shell=True", source)
        self.assertNotIn("--record", source)
        self.assertNotIn("caller", source)
        self.assertNotIn('candidate_root / "run_external.py"', source)
        self.assertIn('authority_root / "run_external.py"', source)
        self.assertIn('"PGK_CANDIDATE_DIR": str(candidate_root)', source)
        self.assertIn('"--authority-roster"', source)
        self.assertIn('"--nonce-ledger-public-key"', source)
        self.assertIn('"--execution-manifest"', source)
        ast.parse(source)

    def test_workflow_executes_protected_not_fetched_authority_code(self):
        workflow = (HERE / "github-attest-result.template.yml").read_text("utf-8")
        self.assertIn("python3 github_authority/run_v35_authority.py", workflow)
        self.assertIn("python3 github_authority/validate_v35_record.py", workflow)
        self.assertNotIn("python3 candidate/github_authority/", workflow)
        self.assertIn('actual == expected', workflow)
        self.assertIn('input/execution-manifest.json', workflow)
        self.assertIn('!= "SHA256SUMS.txt"', workflow)
        validator = (HERE / "result_attestation.py").read_text("utf-8")
        record_schema = (HERE / "attestation_record.py").read_text("utf-8")
        runner = (HERE / "run_external.py").read_text("utf-8")
        for source in (validator, record_schema, runner):
            self.assertIn("execution_manifest_sha256", source)

    def test_connector_rejects_stdout_record_mismatch(self):
        from github_authority.construct_v35_record import construct_record, REQUIRED_DEPLOYMENT_FILES
        with tempfile.TemporaryDirectory() as td:
            base = Path(td); root = base / "input"; root.mkdir()
            candidate = root / "candidate"; candidate.mkdir()
            deployment = base / "deployment"; deployment.mkdir()
            for relative in REQUIRED_DEPLOYMENT_FILES.values():
                path = deployment / relative
                if path.suffix:
                    path.write_bytes(b"x")
                else:
                    path.mkdir()
            evidence = root / "evidence"; evidence.mkdir()
            (root / "execution-manifest.json").write_bytes(
                b'{"candidate_generation":"v35","files":{},"schema_version":1}\n')
            (evidence / "external-run.json").write_bytes(b'{}\n')
            completed = mock.Mock(returncode=0, stdout=b'{"forged":true}\n', stderr=b"")
            with mock.patch("github_authority.construct_v35_record.subprocess.run",
                            return_value=completed):
                with mock.patch.dict(os.environ, {"PGK_DEPLOYMENT_ROOT":
                                                   str(deployment)}, clear=False):
                    with self.assertRaisesRegex(RuntimeError, "mismatch"):
                        construct_record(input_root=root, candidate_root=candidate,
                                         evidence_dir=evidence)

    def test_workflow_signs_only_after_authority_validation(self):
        workflow = (HERE / "github-attest-result.template.yml").read_text("utf-8")
        build = workflow.index("run_v35_authority.py")
        validate = workflow.index("validate_v35_record.py")
        sign = workflow.index("cosign attest-blob")
        self.assertLess(build, validate); self.assertLess(validate, sign)
        self.assertNotIn("PGK_EXTERNAL_RUN_IMMUTABLE_URL", workflow)

    def test_workflow_requires_immutable_release_and_exact_asset_ids(self):
        workflow = (HERE / "github-attest-result.template.yml").read_text("utf-8")
        self.assertIn('test "$(jq -r .immutable <<<"$release_json")" = true', workflow)
        self.assertIn("PGK_V35_INPUT_ARCHIVE_ASSET_ID", workflow)
        self.assertIn("PGK_V35_DEPLOYMENT_ARCHIVE_ASSET_ID", workflow)
        self.assertIn("releases/assets/$INPUT_ASSET_ID", workflow)
        self.assertIn("releases/assets/$DEPLOYMENT_ASSET_ID", workflow)
        self.assertNotIn("INPUT_ARCHIVE_IMMUTABLE_URL", workflow)
        self.assertNotIn("DEPLOYMENT_ARCHIVE_IMMUTABLE_URL", workflow)


if __name__ == "__main__":
    unittest.main()
