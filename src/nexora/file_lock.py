"""Cross-process advisory locks and safe regular-file opening.

The persistent sidecar lock must not be deleted while clients may be running.
Locks coordinate cooperating processes; they are not a security boundary against
a privileged or non-cooperating process.
"""
from __future__ import annotations

import errno
import os
import stat
from collections.abc import Iterator
from contextlib import contextmanager
from pathlib import Path


class UnsafeFilePathError(OSError):
    """Raised when a state-file path is a symlink or is not a regular file."""


def open_regular_file(path: Path, flags: int, mode: int = 0o600) -> int:
    """Open a regular file without following symlinks where the OS supports it.

    The path is checked both before and after opening. The returned descriptor
    refers to the inode that was checked; callers should perform related reads
    and writes through that same descriptor rather than reopening the path.
    """
    path = Path(path)
    try:
        before = path.lstat()
    except FileNotFoundError:
        before = None
    if before is not None and (
        stat.S_ISLNK(before.st_mode) or not stat.S_ISREG(before.st_mode)
    ):
        raise UnsafeFilePathError(
            "File path must be a regular non-symlink file"
        )

    open_flags = flags
    if hasattr(os, "O_NOFOLLOW"):
        open_flags |= os.O_NOFOLLOW
    if hasattr(os, "O_BINARY"):
        open_flags |= os.O_BINARY
    try:
        descriptor = os.open(path, open_flags, mode)
    except OSError as exc:
        if exc.errno == errno.ELOOP:
            raise UnsafeFilePathError(
                "File path must be a regular non-symlink file"
            ) from exc
        raise

    try:
        opened = os.fstat(descriptor)
        if not stat.S_ISREG(opened.st_mode):
            raise UnsafeFilePathError(
                "File path must be a regular non-symlink file"
            )
        try:
            current = path.lstat()
        except OSError as exc:
            raise UnsafeFilePathError("File path changed during open") from exc
        if stat.S_ISLNK(current.st_mode) or not stat.S_ISREG(current.st_mode):
            raise UnsafeFilePathError(
                "File path must be a regular non-symlink file"
            )
        if before is not None and (
            before.st_dev != opened.st_dev
            or (before.st_ino and opened.st_ino and before.st_ino != opened.st_ino)
        ):
            raise UnsafeFilePathError("File path changed before open")
        if (
            current.st_dev != opened.st_dev
            or (current.st_ino and opened.st_ino and current.st_ino != opened.st_ino)
        ):
            raise UnsafeFilePathError("File path changed during open")
        return descriptor
    except Exception:
        os.close(descriptor)
        raise


@contextmanager
def exclusive_file_lock(path: Path) -> Iterator[None]:
    """Hold an exclusive POSIX or Windows lock on a regular sidecar file."""
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    descriptor = open_regular_file(path, os.O_CREAT | os.O_RDWR, 0o600)
    try:
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
