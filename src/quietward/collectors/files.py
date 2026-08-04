from __future__ import annotations

import hashlib
import os
import stat
from pathlib import Path

from .models import FileRecord
from .privacy import redact_error


DEFAULT_SENSITIVE_FILES = (
    Path("/etc/passwd"),
    Path("/etc/group"),
    Path("/etc/sudoers"),
    Path("/etc/ssh/sshd_config"),
    Path("/etc/docker/daemon.json"),
)


def observe_file(path: Path, max_hash_bytes: int = 4 * 1024 * 1024) -> FileRecord:
    if not path.is_absolute():
        raise ValueError(f"monitored path must be absolute: {path}")
    try:
        info = path.lstat()
    except FileNotFoundError:
        return FileRecord(str(path), False, "missing", None, None, None, None)
    except OSError as exc:
        return FileRecord(str(path), False, "error", None, None, None, None, redact_error(str(exc)))

    if stat.S_ISLNK(info.st_mode):
        return FileRecord(str(path), True, "symlink", stat.S_IMODE(info.st_mode), info.st_size, info.st_mtime_ns, None)
    if not stat.S_ISREG(info.st_mode):
        kind = "directory" if stat.S_ISDIR(info.st_mode) else "other"
        return FileRecord(str(path), True, kind, stat.S_IMODE(info.st_mode), info.st_size, info.st_mtime_ns, None)

    digest: str | None = None
    error: str | None = None
    if info.st_size <= max_hash_bytes:
        try:
            flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
            fd = os.open(path, flags)
            try:
                hasher = hashlib.sha256()
                while chunk := os.read(fd, 128 * 1024):
                    hasher.update(chunk)
                digest = hasher.hexdigest()
            finally:
                os.close(fd)
        except OSError as exc:
            error = redact_error(str(exc))
    return FileRecord(
        path=str(path),
        exists=True,
        file_type="regular",
        mode=stat.S_IMODE(info.st_mode),
        size=info.st_size,
        mtime_ns=info.st_mtime_ns,
        sha256=digest,
        error=error,
    )
