#!/usr/bin/env python3
from __future__ import annotations

import io
import tarfile
import tempfile
import unittest
from pathlib import Path

from safe_extract_tar import safe_extract


def archive(path: Path, *, name: str, kind: bytes = tarfile.REGTYPE,
            linkname: str = "", uid: int = 0) -> None:
    with tarfile.open(path, "w", format=tarfile.USTAR_FORMAT) as output:
        info = tarfile.TarInfo(name)
        info.type = kind; info.uid = uid; info.gid = 0; info.linkname = linkname
        raw = b"safe\n"
        if kind == tarfile.REGTYPE:
            info.size = len(raw); output.addfile(info, io.BytesIO(raw))
        else:
            output.addfile(info)


class SafeExtractTests(unittest.TestCase):
    def test_regular_file_accepts(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td); source = root / "input.tar"
            archive(source, name="a/b.txt")
            safe_extract(source, root / "out")
            self.assertEqual((root / "out/a/b.txt").read_bytes(), b"safe\n")

    def test_parent_escape_rejected_and_cleaned(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td); source = root / "input.tar"
            archive(source, name="../escape.txt")
            with self.assertRaisesRegex(ValueError, "unsafe"):
                safe_extract(source, root / "out")
            self.assertFalse((root / "escape.txt").exists())
            self.assertFalse((root / "out").exists())

    def test_symlink_and_hardlink_rejected(self):
        for kind in (tarfile.SYMTYPE, tarfile.LNKTYPE):
            with self.subTest(kind=kind), tempfile.TemporaryDirectory() as td:
                root = Path(td); source = root / "input.tar"
                archive(source, name="alias", kind=kind, linkname="../target")
                with self.assertRaisesRegex(ValueError, "unsafe"):
                    safe_extract(source, root / "out")

    def test_nonzero_owner_rejected(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td); source = root / "input.tar"
            archive(source, name="a.txt", uid=1000)
            with self.assertRaisesRegex(ValueError, "unsafe"):
                safe_extract(source, root / "out")


if __name__ == "__main__":
    unittest.main()
