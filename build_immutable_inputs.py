#!/usr/bin/env python3
"""Build deterministic, path-safe v35 workflow input archives.

This freezes transport bytes only; it neither creates custodian authority nor
claims release approval. Candidate manifests are verified before packaging.
"""
from __future__ import annotations

import argparse
import hashlib
import io
import json
import stat
import tarfile
from pathlib import Path, PurePosixPath

FIXED_MTIME = 0


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb", buffering=0) as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def canonical_json(value: object) -> bytes:
    return json.dumps(value, ensure_ascii=True, sort_keys=True,
                      separators=(",", ":")).encode("ascii") + b"\n"


def regular_files(root: Path, *, exclude: set[str] | None = None) -> dict[str, Path]:
    root = root.resolve(strict=True)
    excluded = exclude or set()
    result: dict[str, Path] = {}
    for path in sorted(root.rglob("*"), key=lambda item: item.as_posix()):
        relative = path.relative_to(root).as_posix()
        if relative in excluded:
            continue
        if path.is_symlink() or path.is_dir():
            if path.is_symlink():
                raise ValueError(f"symlink is forbidden: {relative}")
            continue
        if not path.is_file():
            raise ValueError(f"non-regular input is forbidden: {relative}")
        resolved = path.resolve(strict=True)
        if root not in resolved.parents:
            raise ValueError(f"path escapes root: {relative}")
        result[relative] = path
    return result


def parse_candidate_manifest(candidate: Path) -> dict[str, str]:
    manifest_path = candidate / "SHA256SUMS.txt"
    raw = manifest_path.read_bytes()
    if b"\r" in raw or not raw.endswith(b"\n"):
        raise ValueError("candidate manifest must be canonical LF text")
    expected: dict[str, str] = {}
    for line in raw.decode("ascii").splitlines():
        digest, relative = line.split("  ", 1)
        posix = PurePosixPath(relative)
        if (len(digest) != 64 or any(c not in "0123456789abcdef" for c in digest)
                or relative in expected or posix.is_absolute() or ".." in posix.parts
                or posix.as_posix() != relative or relative == "SHA256SUMS.txt"):
            raise ValueError("invalid candidate manifest entry")
        expected[relative] = digest
    actual_paths = regular_files(candidate, exclude={"SHA256SUMS.txt"})
    actual = {relative: sha256(path) for relative, path in actual_paths.items()}
    if actual != expected:
        raise ValueError("candidate file set or digest differs from SHA256SUMS.txt")
    return expected


def add_directory(archive: tarfile.TarFile, name: str) -> None:
    info = tarfile.TarInfo(name.rstrip("/") + "/")
    info.type = tarfile.DIRTYPE
    info.mode = 0o755
    info.uid = info.gid = 0
    info.uname = info.gname = ""
    info.mtime = FIXED_MTIME
    archive.addfile(info)


def add_bytes(archive: tarfile.TarFile, name: str, raw: bytes,
              mode: int = 0o644) -> None:
    info = tarfile.TarInfo(name)
    info.size = len(raw)
    info.mode = mode
    info.uid = info.gid = 0
    info.uname = info.gname = ""
    info.mtime = FIXED_MTIME
    archive.addfile(info, io.BytesIO(raw))


def add_tree(archive: tarfile.TarFile, prefix: str,
             files: dict[str, Path]) -> None:
    directories = set() if prefix == "." else {prefix}
    for relative in files:
        parent = PurePosixPath(prefix, relative).parent
        while parent.as_posix() not in (".", ""):
            directories.add(parent.as_posix())
            if parent.as_posix() == prefix or (prefix == "." and parent.as_posix() == "."):
                break
            parent = parent.parent
    for directory in sorted(directories):
        add_directory(archive, directory)
    for relative, path in sorted(files.items()):
        executable = bool(path.stat().st_mode & stat.S_IXUSR)
        name = relative if prefix == "." else PurePosixPath(prefix, relative).as_posix()
        add_bytes(archive, name,
                  path.read_bytes(), 0o755 if executable else 0o644)


def build_candidate(candidate: Path, output: Path,
                    expected_manifest_sha256: str | None = None) -> dict[str, object]:
    candidate = candidate.resolve(strict=True)
    manifest_digest = sha256(candidate / "SHA256SUMS.txt")
    if expected_manifest_sha256 is not None and manifest_digest != expected_manifest_sha256:
        raise ValueError("candidate manifest is not the externally reviewed digest")
    files = parse_candidate_manifest(candidate)
    execution_manifest = canonical_json({
        "candidate_generation": "v35", "files": files, "schema_version": 1,
    })
    output.parent.mkdir(parents=True, exist_ok=True)
    with tarfile.open(output, "w", format=tarfile.USTAR_FORMAT) as archive:
        add_tree(archive, "candidate", regular_files(candidate))
        add_bytes(archive, "execution-manifest.json", execution_manifest)
    return {"archive_sha256": sha256(output), "archive_bytes": output.stat().st_size,
            "candidate_manifest_sha256": manifest_digest,
            "execution_manifest_sha256": hashlib.sha256(execution_manifest).hexdigest(),
            "file_count": len(files)}


def build_deployment(deployment: Path, output: Path) -> dict[str, object]:
    files = regular_files(deployment)
    required = {
        "external-pin.txt", "authority-roster.json", "authorization.json",
        "nonce-ledger.spki.der", "nonce-witness.spki.der",
        "checkpoint-a.spki.der", "checkpoint-b.spki.der",
    }
    missing = sorted(required.difference(files))
    if (missing or not any(name.startswith("authority-public-keys/") for name in files)
            or not any(name.startswith("authority-signatures/") for name in files)):
        raise ValueError(f"deployment bundle is incomplete: {missing}")
    output.parent.mkdir(parents=True, exist_ok=True)
    with tarfile.open(output, "w", format=tarfile.USTAR_FORMAT) as archive:
        add_tree(archive, ".", files)
    return {"archive_sha256": sha256(output), "archive_bytes": output.stat().st_size,
            "file_count": len(files)}


def main() -> int:
    parser = argparse.ArgumentParser()
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("--candidate", type=Path)
    group.add_argument("--deployment", type=Path)
    parser.add_argument("--expected-manifest-sha256")
    parser.add_argument("--output", required=True, type=Path)
    parser.add_argument("--report", required=True, type=Path)
    args = parser.parse_args()
    report = (build_candidate(args.candidate, args.output,
                              args.expected_manifest_sha256) if args.candidate
              else build_deployment(args.deployment, args.output))
    report.update({"schema_version": 1,
                   "kind": "v35-candidate-input" if args.candidate else "v35-deployment-input",
                   "official_pass": False, "promotion_allowed": False})
    args.report.write_bytes(canonical_json(report))
    print(canonical_json(report).decode("ascii"), end="")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
