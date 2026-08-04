from __future__ import annotations

import os
from pathlib import Path


class SingleInstanceLock:
    """Portable non-blocking process lock for QuietWard's own lock file."""

    def __init__(self, path: Path) -> None:
        self.path = path
        self.descriptor: int | None = None

    def acquire(self) -> None:
        self.path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        descriptor = os.open(self.path, os.O_RDWR | os.O_CREAT, 0o600)
        try:
            if os.name == "nt":
                import msvcrt

                os.lseek(descriptor, 0, os.SEEK_SET)
                if os.fstat(descriptor).st_size == 0:
                    os.write(descriptor, b"0")
                    os.fsync(descriptor)
                os.lseek(descriptor, 0, os.SEEK_SET)
                try:
                    msvcrt.locking(descriptor, msvcrt.LK_NBLCK, 1)
                except OSError as exc:
                    raise RuntimeError(
                        "another QuietWard service instance is active"
                    ) from exc
            else:
                import fcntl

                try:
                    fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
                except BlockingIOError as exc:
                    raise RuntimeError(
                        "another QuietWard service instance is active"
                    ) from exc
            os.ftruncate(descriptor, 0)
            os.lseek(descriptor, 0, os.SEEK_SET)
            os.write(descriptor, str(os.getpid()).encode("ascii"))
            os.fsync(descriptor)
            self.descriptor = descriptor
        except Exception:
            os.close(descriptor)
            raise

    def release(self) -> None:
        descriptor = self.descriptor
        if descriptor is None:
            return
        try:
            if os.name == "nt":
                import msvcrt

                os.lseek(descriptor, 0, os.SEEK_SET)
                msvcrt.locking(descriptor, msvcrt.LK_UNLCK, 1)
            else:
                import fcntl

                fcntl.flock(descriptor, fcntl.LOCK_UN)
        finally:
            os.close(descriptor)
            self.descriptor = None

    def __enter__(self) -> "SingleInstanceLock":
        self.acquire()
        return self

    def __exit__(self, *_: object) -> None:
        self.release()
