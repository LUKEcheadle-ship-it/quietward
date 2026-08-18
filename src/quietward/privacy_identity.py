from __future__ import annotations

import hashlib
import hmac
import os
import re
import stat
from pathlib import Path


_DOMAIN = re.compile(r"^[a-z0-9][a-z0-9._-]{0,63}$")
PRIVACY_IDENTITY_NAMESPACES = {
    "quietward-v1": b"quietward-auth-username-v1\0",
    "forge-sentinel-v1": b"forge-sentinel-auth-username-v1\0",
}


class PrivacyIdentity:
    DOMAIN = b"quietward-auth-username-v1\0"
    SCOPED_PREFIX = b"quietward-privacy-identity-v1\0"

    def __init__(self, key: bytes, domain: bytes | None = None) -> None:
        self._key = key
        self._domain = domain or self.DOMAIN

    @classmethod
    def load(
        cls,
        path: Path,
        *,
        namespace: str = "quietward-v1",
    ) -> "PrivacyIdentity":
        try:
            domain = PRIVACY_IDENTITY_NAMESPACES[namespace]
        except KeyError as exc:
            raise ValueError("unsupported privacy identity namespace") from exc
        if not path.is_absolute():
            raise ValueError("privacy identity key path must be absolute")
        flags = (
            os.O_RDONLY
            | getattr(os, "O_BINARY", 0)
            | getattr(os, "O_CLOEXEC", 0)
            | getattr(os, "O_NOFOLLOW", 0)
        )
        try:
            descriptor = os.open(path, flags)
        except OSError as exc:
            raise ValueError("privacy identity key is unavailable") from exc
        try:
            info = os.fstat(descriptor)
            if not stat.S_ISREG(info.st_mode):
                raise ValueError("privacy identity key must be a regular file")
            if os.name != "nt" and stat.S_IMODE(info.st_mode) != 0o600:
                raise ValueError("privacy identity key must be mode 0600")
            if info.st_size < 32 or info.st_size > 4096:
                raise ValueError(
                    "privacy identity key must contain between 32 and 4096 bytes"
                )
            chunks: list[bytes] = []
            remaining = 4097
            while remaining:
                chunk = os.read(descriptor, remaining)
                if not chunk:
                    break
                chunks.append(chunk)
                remaining -= len(chunk)
            key = b"".join(chunks)
        finally:
            os.close(descriptor)
        if len(key) < 32 or len(key) > 4096:
            raise ValueError(
                "privacy identity key must contain between 32 and 4096 bytes"
            )
        return cls(key, domain)

    def identify(self, username: str) -> str:
        return hmac.new(
            self._key,
            self._domain + username.encode("utf-8", errors="replace"),
            hashlib.sha256,
        ).hexdigest()[:32]

    def identify_scoped(self, value: str, domain: str) -> str:
        normalized_domain = domain.strip().lower()
        if not _DOMAIN.fullmatch(normalized_domain):
            raise ValueError("privacy identity domain is invalid")
        message = (
            self.SCOPED_PREFIX
            + normalized_domain.encode("ascii")
            + b"\0"
            + value.encode("utf-8", errors="replace")
        )
        return hmac.new(self._key, message, hashlib.sha256).hexdigest()[:32]
