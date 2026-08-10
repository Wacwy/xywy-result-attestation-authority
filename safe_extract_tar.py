#!/usr/bin/env python3
"""Extract only canonical regular-file/directory USTAR archives, fail closed."""
from __future__ import annotations

import argparse
import os
import tarfile
from pathlib import Path, PurePosixPath


def safe_extract(archive_path: Path, destination: Path) -> None:
    destination = destination.resolve()
    if destination.exists():
        raise ValueError("destination already exists")
    destination.mkdir(parents=True, mode=0o700)
    try:
        with tarfile.open(archive_path.resolve(strict=True), "r:") as archive:
            seen: set[str] = set()
            members = archive.getmembers()
            if not members:
                raise ValueError("empty archive")
            for member in members:
                name = member.name.rstrip("/") if member.isdir() else member.name
                pure = PurePosixPath(name)
                if (not name or pure.is_absolute() or ".." in pure.parts
                        or pure.as_posix() != name or name in seen
                        or member.issym() or member.islnk()
                        or not (member.isdir() or member.isreg())
                        or member.uid != 0 or member.gid != 0):
                    raise ValueError(f"unsafe archive member: {member.name}")
                seen.add(name)
                target = destination.joinpath(*pure.parts)
                parent = target.parent.resolve()
                if parent != destination and destination not in parent.parents:
                    raise ValueError(f"archive path escape: {member.name}")
                if member.isdir():
                    target.mkdir(parents=True, exist_ok=False, mode=0o755)
                else:
                    target.parent.mkdir(parents=True, exist_ok=True, mode=0o755)
                    source = archive.extractfile(member)
                    if source is None:
                        raise ValueError("missing archive payload")
                    fd = os.open(target, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
                    try:
                        with os.fdopen(fd, "wb", closefd=True) as output:
                            for chunk in iter(lambda: source.read(1024 * 1024), b""):
                                output.write(chunk)
                            output.flush()
                            os.fsync(output.fileno())
                    except Exception:
                        try:
                            os.close(fd)
                        except OSError:
                            pass
                        raise
    except Exception:
        import shutil
        shutil.rmtree(destination, ignore_errors=True)
        raise


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--archive", required=True, type=Path)
    parser.add_argument("--destination", required=True, type=Path)
    args = parser.parse_args()
    safe_extract(args.archive, args.destination)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
