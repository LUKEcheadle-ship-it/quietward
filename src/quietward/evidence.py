from __future__ import annotations

import hashlib
import hmac
import os
import stat
from dataclasses import dataclass
from pathlib import Path


EVIDENCE_KEY_ID_NAMESPACES = {
    "quietward-v1": b"quietward-evidence-key-id-v1\0",
    "forge-sentinel-v1": b"forge-sentinel-evidence-key-id-v1\0",
}


@dataclass(frozen=True, slots=True)
class EvidenceSigner:
    """Loads a private local key and signs retained evidence-chain hashes."""

    key_id: str
    key: bytes
    algorithm: str = "hmac-sha256-v1"

    @classmethod
    def load(
        cls,
        path: Path,
        *,
        key_id_namespace: str = "quietward-v1",
    ) -> "EvidenceSigner":
        try:
            key_id_domain = EVIDENCE_KEY_ID_NAMESPACES[key_id_namespace]
        except KeyError as exc:
            raise ValueError("unsupported evidence signing key namespace") from exc
        path = path.expanduser()
        if not path.is_absolute():
            raise ValueError("evidence signing key path must be absolute")
        flags = (
            os.O_RDONLY
            | getattr(os, "O_BINARY", 0)
            | getattr(os, "O_CLOEXEC", 0)
            | getattr(os, "O_NOFOLLOW", 0)
        )
        try:
            descriptor = os.open(path, flags)
        except OSError as exc:
            raise ValueError(f"cannot open evidence signing key: {exc}") from exc
        try:
            info = os.fstat(descriptor)
            if not stat.S_ISREG(info.st_mode):
                raise ValueError(
                    "evidence signing key must be a regular non-symlink file"
                )
            if os.name != "nt" and info.st_mode & 0o077:
                raise ValueError(
                    "evidence signing key must not be group/world accessible"
                )
            if info.st_size < 32 or info.st_size > 4096:
                raise ValueError(
                    "evidence signing key must contain between 32 and 4096 bytes"
                )
            chunks: list[bytes] = []
            remaining = 4097
            while remaining:
                chunk = os.read(descriptor, min(remaining, 64 * 1024))
                if not chunk:
                    break
                chunks.append(chunk)
                remaining -= len(chunk)
            key = b"".join(chunks)
        finally:
            os.close(descriptor)
        if len(key) < 32 or len(key) > 4096:
            raise ValueError(
                "evidence signing key must contain between 32 and 4096 bytes"
            )
        key_id = hashlib.sha256(key_id_domain + key).hexdigest()[:20]
        return cls(key_id=key_id, key=key)

    def sign(self, cycle_id: int, chain_hash: str) -> str:
        message = (
            f"{self.algorithm}|{self.key_id}|{cycle_id}|{chain_hash}"
        ).encode("ascii")
        return hmac.new(self.key, message, hashlib.sha256).hexdigest()

    def verify(self, cycle_id: int, chain_hash: str, signature: str) -> bool:
        return hmac.compare_digest(
            self.sign(cycle_id, chain_hash),
            signature,
        )
