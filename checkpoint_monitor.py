#!/usr/bin/env python3
"""Deployment-owned monotonic checkpoint monitor for PGK v26.

The monitor is a verifier-side second line of defence.  A receipt is accepted
only when it is the unique successor of the exact checkpoint currently stored
outside the candidate.  State replacement is atomic and serialised across
processes; the candidate never accepts a caller-supplied state root.
"""
from __future__ import annotations

import ctypes
import json
import os
import time
from contextlib import contextmanager
from pathlib import Path


class MonitorReject(Exception):
    pass


def _canonical(value: dict) -> bytes:
    return (json.dumps(value, sort_keys=True, separators=(",", ":")) + "\n").encode("ascii")


def _checkpoint(size: int, root: str, epoch: str) -> dict:
    if (not isinstance(size, int) or isinstance(size, bool) or size < 1
            or not isinstance(root, str) or len(root) != 64
            or any(c not in "0123456789abcdef" for c in root)
            or not isinstance(epoch, str) or len(epoch) != 64
            or any(c not in "0123456789abcdef" for c in epoch)):
        raise MonitorReject("checkpoint format")
    return {"schema_version": 1, "ledger_epoch": epoch,
            "tree_size": size, "tree_root_sha256": root}


def _read(path: Path) -> dict:
    try:
        raw = path.read_bytes()
        value = json.loads(raw.decode("ascii"))
    except Exception as exc:
        raise MonitorReject("checkpoint state unavailable") from exc
    expected = _checkpoint(value.get("tree_size"), value.get("tree_root_sha256"),
                           value.get("ledger_epoch"))
    if value != expected or raw != _canonical(expected):
        raise MonitorReject("checkpoint state canonical form")
    return value


@contextmanager
def _exclusive_lock(lock_path: Path, timeout_seconds: float = 20.0):
    """Cross-process exclusive lock; fail closed when it cannot be acquired."""
    lock_path.parent.mkdir(parents=False, exist_ok=True)
    handle = None
    fd = None
    deadline = time.monotonic() + timeout_seconds
    if os.name == "nt":
        kernel32 = ctypes.windll.kernel32
        kernel32.CreateFileW.restype = ctypes.c_void_p
        while True:
            handle = kernel32.CreateFileW(str(lock_path), 0xC0000000, 0, None, 4,
                                          0x80, None)
            if handle != ctypes.c_void_p(-1).value:
                break
            if time.monotonic() >= deadline:
                raise MonitorReject("checkpoint lock unavailable")
            time.sleep(0.025)
        try:
            yield
        finally:
            kernel32.CloseHandle(handle)
        return
    import fcntl
    fd = os.open(lock_path, os.O_RDWR | os.O_CREAT, 0o600)
    try:
        while True:
            try:
                fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
                break
            except BlockingIOError:
                if time.monotonic() >= deadline:
                    raise MonitorReject("checkpoint lock unavailable")
                time.sleep(0.025)
        yield
    finally:
        fcntl.flock(fd, fcntl.LOCK_UN)
        os.close(fd)


def current(root: Path) -> dict:
    root = root.resolve(strict=True)
    if not root.is_dir() or root.is_symlink():
        raise MonitorReject("checkpoint root")
    return _read(root / "current.json")


def advance(root: Path, receipt: dict, verify_receipt) -> dict:
    """Verify against and atomically advance the single current checkpoint.

    ``verify_receipt`` receives the trusted size/root read under the deployment
    lock.  Only its successful, cryptographically verified receipt may become
    the next state.  Competing siblings therefore cannot both commit.
    """
    root = root.resolve(strict=True)
    if not root.is_dir() or root.is_symlink():
        raise MonitorReject("checkpoint root")
    state_path = root / "current.json"
    lock_path = root / "advance.lock"
    with _exclusive_lock(lock_path):
        before = _read(state_path)
        verified = verify_receipt(before["tree_size"], before["tree_root_sha256"])
        if verified is not receipt and verified != receipt:
            raise MonitorReject("verified receipt identity")
        if (verified.get("ledger_epoch") != before["ledger_epoch"]
                or verified.get("prior_tree_size") != before["tree_size"]
                or verified.get("prior_tree_root_sha256") != before["tree_root_sha256"]
                or not isinstance(verified.get("tree_size"), int)
                or verified["tree_size"] <= before["tree_size"]):
            raise MonitorReject("checkpoint is not unique monotonic successor")
        after = _checkpoint(verified["tree_size"], verified.get("tree_root_sha256"),
                            verified["ledger_epoch"])
        temporary = root / f".current.{os.getpid()}.{time.time_ns()}.tmp"
        try:
            with temporary.open("xb", buffering=0) as stream:
                stream.write(_canonical(after)); stream.flush(); os.fsync(stream.fileno())
            os.replace(temporary, state_path)
            # Flush the directory on platforms that support it. Windows
            # ReplaceFile/MoveFileEx durability is deployment-tested externally.
            if os.name != "nt":
                directory_fd = os.open(root, os.O_RDONLY)
                try: os.fsync(directory_fd)
                finally: os.close(directory_fd)
        finally:
            temporary.unlink(missing_ok=True)
        return after


def initialise_for_test(root: Path, *, tree_size: int, tree_root_sha256: str,
                        ledger_epoch: str) -> None:
    root.mkdir(parents=True, exist_ok=False)
    (root / "current.json").write_bytes(
        _canonical(_checkpoint(tree_size, tree_root_sha256, ledger_epoch)))
