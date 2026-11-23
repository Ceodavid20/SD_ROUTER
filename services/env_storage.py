"""Serialize private environment-file updates across local threads and processes."""

from __future__ import annotations

from collections.abc import Callable, Mapping
from contextlib import contextmanager
from io import StringIO
import os
from pathlib import Path
import stat
import tempfile
import threading

from dotenv import dotenv_values, set_key


_LOCKS: dict[str, threading.Lock] = {}
_LOCKS_GUARD = threading.Lock()


def _reject_symlink(path: Path, label: str) -> None:
    if path.is_symlink():
        raise ValueError(f"The {label} must not be a symbolic link.")


@contextmanager
def _locked_environment(path: Path):
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    _reject_symlink(path, "environment file")
    # Resolve directory aliases, but never resolve away an environment symlink.
    path = path.parent.resolve() / path.name
    lock_path = path.with_name(path.name + ".lock")
    with _LOCKS_GUARD:
        thread_lock = _LOCKS.setdefault(str(path), threading.Lock())
    with thread_lock:
        _reject_symlink(path, "environment file")
        _reject_symlink(lock_path, "environment lock file")
        descriptor = os.open(
            lock_path, os.O_RDWR | os.O_CREAT | getattr(os, "O_NOFOLLOW", 0), 0o600,
        )
        try:
            if not stat.S_ISREG(os.fstat(descriptor).st_mode):
                raise ValueError("The environment lock must be a regular file.")
            if hasattr(os, "fchmod"):
                os.fchmod(descriptor, 0o600)
            else:
                os.chmod(lock_path, 0o600)
            if os.name == "nt":
                import msvcrt

                if os.fstat(descriptor).st_size == 0:
                    os.write(descriptor, b"\0")
                os.lseek(descriptor, 0, os.SEEK_SET)
                msvcrt.locking(descriptor, msvcrt.LK_LOCK, 1)
            else:
                import fcntl

                fcntl.flock(descriptor, fcntl.LOCK_EX)
            try:
                _reject_symlink(path, "environment file")
                yield path
            finally:
                if os.name == "nt":
                    os.lseek(descriptor, 0, os.SEEK_SET)
                    msvcrt.locking(descriptor, msvcrt.LK_UNLCK, 1)
                else:
                    fcntl.flock(descriptor, fcntl.LOCK_UN)
        finally:
            os.close(descriptor)
        # Keep the sidecar: unlinking it would allow another process to lock a
        # different inode while an existing waiter still holds the old lock.


def update_private_environment(
    env_path: str | Path,
    updates: Callable[[Mapping[str, str | None]], Mapping[str, str]],
) -> None:
    """Read, update and replace one .env snapshot while holding its stable lock.

    The callback can validate existing values before returning changes. Existing
    comments and unrelated settings are retained; no secret values are logged.
    All writers of this file must use this helper on a local filesystem.
    """
    with _locked_environment(Path(env_path).expanduser().absolute()) as path:
        try:
            descriptor = os.open(
                path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_NONBLOCK", 0),
            )
        except FileNotFoundError:
            existing = ""
        else:
            with os.fdopen(descriptor, "r", encoding="utf-8") as stream:
                if not stat.S_ISREG(os.fstat(stream.fileno()).st_mode):
                    raise ValueError("The environment file must be a regular file.")
                existing = stream.read()
        values = dotenv_values(stream=StringIO(existing), interpolate=False)
        changes = updates(values)
        descriptor, temporary = tempfile.mkstemp(prefix=".env.update.", dir=path.parent)
        try:
            with os.fdopen(descriptor, "w", encoding="utf-8") as stream:
                stream.write(existing)
                if existing and not existing.endswith("\n"):
                    stream.write("\n")
            for name, value in changes.items():
                set_key(temporary, name, value)
            os.chmod(temporary, 0o600)
            with open(temporary, "rb") as stream:
                os.fsync(stream.fileno())
            _reject_symlink(path, "environment file")
            os.replace(temporary, path)
            if os.name != "nt":
                directory = os.open(path.parent, os.O_RDONLY)
                try:
                    os.fsync(directory)
                finally:
                    os.close(directory)
        finally:
            if os.path.exists(temporary):
                os.unlink(temporary)
