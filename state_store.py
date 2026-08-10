#!/usr/bin/env python3
"""Deployment-owned, fail-closed nonce store helpers for PGK v8."""
from __future__ import annotations

import ctypes
import json
import os
import stat
import subprocess
from pathlib import Path

MARKER = ".pgk-authority-v8.json"
RISKY_SIDS = ("S-1-1-0", "S-1-5-11", "S-1-5-32-545")  # Everyone, Authenticated Users, Users
RISKY_RIGHTS = ("(F)", "(M)", "(W)", "(OI)(CI)(F)", "(OI)(CI)(M)", "(OI)(CI)(W)")


class StoreReject(Exception):
    pass


class StoreReplay(StoreReject):
    pass


def _reparse(path: Path) -> bool:
    if path.is_symlink() or stat.S_ISLNK(path.lstat().st_mode):
        return True
    if os.name == "nt":
        attrs = ctypes.windll.kernel32.GetFileAttributesW(str(path))
        if attrs == 0xFFFFFFFF:
            raise StoreReject("state attributes")
        return bool(attrs & 0x400)  # FILE_ATTRIBUTE_REPARSE_POINT
    return False


def _sddl(path: Path) -> str:
    # ``powershell -Command <script> <argument>`` does not populate ``$args``
    # the way a native executable invocation does; the old form parsed the
    # Unicode path as a trailing PowerShell expression and always failed.  Bind
    # the first argument explicitly in a script block instead.
    command = [
        "powershell", "-NoProfile", "-NonInteractive", "-Command",
        "& { param([string]$LiteralPath) (Get-Acl -LiteralPath $LiteralPath).Sddl }",
        str(path),
    ]
    proc = subprocess.run(command, text=True, capture_output=True, timeout=20)
    if proc.returncode or not proc.stdout.strip():
        raise StoreReject("state ACL unavailable")
    return proc.stdout.strip()


def verify(root: Path, expected: Path, *, enforce_acl: bool) -> None:
    if not root.is_absolute() or root.resolve() != expected.resolve() or not root.is_dir():
        raise StoreReject("authoritative state root")
    if _reparse(root):
        raise StoreReject("reparse state root")
    marker = root / MARKER
    if not marker.is_file() or _reparse(marker):
        raise StoreReject("authority marker")
    try:
        value = json.loads(marker.read_text("utf-8"))
    except Exception as exc:
        raise StoreReject(f"authority marker: {exc}")
    expected_marker = {"schema_version": 1, "authority": "PGK-V8", "absolute_root": expected.as_posix()}
    if value != expected_marker:
        raise StoreReject("authority marker binding")
    consumed = root / "consumed"
    if consumed.exists() and (not consumed.is_dir() or _reparse(consumed)):
        raise StoreReject("consumed reparse")
    if enforce_acl:
        sddl = _sddl(root)
        for sid in RISKY_SIDS:
            for right in RISKY_RIGHTS:
                if sid in sddl and right in sddl:
                    raise StoreReject("writable broad-principal ACL")


def consume_atomic(path: Path, raw: bytes) -> None:
    """CREATE_NEW plus write-through data durability; never overwrite."""
    if _reparse(path.parent):
        raise StoreReject("consumed reparse")
    if os.name != "nt":
        try:
            fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        except FileExistsError:
            raise StoreReplay("replay")
        with os.fdopen(fd, "wb") as file:
            file.write(raw); file.flush(); os.fsync(file.fileno())
        directory_fd = os.open(path.parent, os.O_RDONLY)
        try: os.fsync(directory_fd)
        finally: os.close(directory_fd)
        return
    kernel32 = ctypes.windll.kernel32
    kernel32.CreateFileW.restype = ctypes.c_void_p
    kernel32.CreateFileW.argtypes = [ctypes.c_wchar_p, ctypes.c_uint32, ctypes.c_uint32, ctypes.c_void_p,
                                     ctypes.c_uint32, ctypes.c_uint32, ctypes.c_void_p]
    handle = kernel32.CreateFileW(str(path), 0x40000000, 0, None, 1, 0x80000080, None)
    invalid = ctypes.c_void_p(-1).value
    if handle == invalid:
        error = kernel32.GetLastError()
        if error in (80, 183):
            raise StoreReplay("replay")
        raise StoreReject(f"create durable nonce: {error}")
    try:
        written = ctypes.c_ulong(0)
        buffer = ctypes.create_string_buffer(raw)
        if not kernel32.WriteFile(handle, buffer, len(raw), ctypes.byref(written), None) or written.value != len(raw):
            raise StoreReject("write durable nonce")
        if not kernel32.FlushFileBuffers(handle):
            raise StoreReject("flush durable nonce")
    finally:
        kernel32.CloseHandle(handle)


def write_test_marker(root: Path) -> None:
    root.mkdir(parents=True, exist_ok=True)
    value = {"schema_version": 1, "authority": "PGK-V8", "absolute_root": root.as_posix()}
    (root / MARKER).write_text(json.dumps(value, sort_keys=True, separators=(",", ":")) + "\n", "utf-8")
