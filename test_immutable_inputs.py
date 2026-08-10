#!/usr/bin/env python3
from __future__ import annotations

import json
import tarfile
import tempfile
import unittest
from pathlib import Path

from build_immutable_inputs import (build_candidate, build_deployment,
                                    canonical_json, sha256)


class ImmutableInputTests(unittest.TestCase):
    def candidate(self, root: Path) -> Path:
        candidate = root / "candidate"
        candidate.mkdir()
        (candidate / "a.txt").write_bytes(b"a\n")
        digest = sha256(candidate / "a.txt")
        (candidate / "SHA256SUMS.txt").write_bytes(
            f"{digest}  a.txt\n".encode("ascii"))
        return candidate

    def test_candidate_archive_is_reproducible_and_closed(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td); candidate = self.candidate(root)
            one = root / "one.tar"; two = root / "two.tar"
            first = build_candidate(candidate, one)
            second = build_candidate(candidate, two)
            self.assertEqual(one.read_bytes(), two.read_bytes())
            self.assertEqual(first, second)
            with tarfile.open(one, "r") as archive:
                names = sorted(item.name.rstrip("/") for item in archive)
                self.assertEqual(names, ["candidate", "candidate/SHA256SUMS.txt",
                                         "candidate/a.txt", "execution-manifest.json"])
                manifest = json.load(archive.extractfile("execution-manifest.json"))
                self.assertEqual(manifest["files"], {"a.txt": sha256(candidate / "a.txt")})

    def test_candidate_mutation_is_rejected(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td); candidate = self.candidate(root)
            (candidate / "a.txt").write_bytes(b"changed\n")
            with self.assertRaisesRegex(ValueError, "differs"):
                build_candidate(candidate, root / "bad.tar")

    def test_external_manifest_pin_is_required_when_supplied(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td); candidate = self.candidate(root)
            with self.assertRaisesRegex(ValueError, "externally reviewed"):
                build_candidate(candidate, root / "bad.tar", "0" * 64)

    def test_unmanifested_candidate_file_is_rejected(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td); candidate = self.candidate(root)
            (candidate / "extra.txt").write_bytes(b"extra\n")
            with self.assertRaisesRegex(ValueError, "file set"):
                build_candidate(candidate, root / "bad.tar")

    def test_deployment_requires_complete_external_bundle(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td); deployment = root / "deployment"; deployment.mkdir()
            with self.assertRaisesRegex(ValueError, "incomplete"):
                build_deployment(deployment, root / "bad.tar")

    def test_canonical_report_never_claims_pass(self):
        raw = canonical_json({"promotion_allowed": False, "official_pass": False})
        self.assertEqual(raw, b'{"official_pass":false,"promotion_allowed":false}\n')


if __name__ == "__main__":
    unittest.main()
