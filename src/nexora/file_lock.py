"""Cross-process advisory locks for local append-only state files.

The persistent sidecar lock must not be deleted while clients may be running.
Locks coordinate cooperating processes; they are not a security boundary against
a privileged or non-cooperating process.
"""
from __future__ import annotations

import os
import stat
from collections.abc import Iterator
from contextlib import contextmanager
from pathlib import Path


@contextmanager
def exclusive_file_lock(path: Path) -> Iterator[None]:
    """Hold an exclusive POSIX or Windows lock on a regular sidecar file."""
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    try:
        existing = path.lstat()
    except FileNotFoundError:
        existing = None
    if existing is not None and (
        stat.S_ISLNK(existing.st_mode) or not stat.S_ISREG(existing.st_mode)
    ):
        raise OSError("Lock path must be a regular non-symlink file")

    flags = os.O_CREAT | os.O_RDWR
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    if hasattr(os, "O_BINARY"):
        flags |= os.O_BINARY
    descriptor = os.open(path, flags, 0o600)
    try:
        if not stat.S_ISREG(os.fstat(descriptor).st_mode):
            raise OSError("Lock path must be a regular file")
        if os.name == "nt":
            import msvcrt

            if os.fstat(descriptor).st_size == 0:
                os.write(descriptor, b"\0")
            os.lseek(descriptor, 0, os.SEEK_SET)
            msvcrt.locking(descriptor, msvcrt.LK_LOCK, 1)
            try:
                yield
            finally:
                os.lseek(descriptor, 0, os.SEEK_SET)
                msvcrt.locking(descriptor, msvcrt.LK_UNLCK, 1)
        else:
            import fcntl

            fcntl.flock(descriptor, fcntl.LOCK_EX)
            try:
                yield
            finally:
                fcntl.flock(descriptor, fcntl.LOCK_UN)
    finally:
        os.close(descriptor)
