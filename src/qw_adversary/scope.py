from __future__ import annotations

import ipaddress
from dataclasses import dataclass
from urllib.parse import urlsplit


class UnsafeTargetError(ValueError):
    pass


@dataclass(frozen=True, slots=True)
class TargetScope:
    base_url: str
    host: str
    port: int | None


def validate_target(base_url: str) -> TargetScope:
    """Fail closed unless the target is an explicit loopback HTTP endpoint."""
    parsed = urlsplit(base_url)
    if parsed.scheme not in {"http", "https"}:
        raise UnsafeTargetError("target must use http or https")
    if parsed.username is not None or parsed.password is not None:
        raise UnsafeTargetError("credentials in target URLs are prohibited")
    if parsed.query or parsed.fragment:
        raise UnsafeTargetError("base target must not contain query or fragment")
    if not parsed.hostname:
        raise UnsafeTargetError("target hostname is required")

    host = parsed.hostname.rstrip(".").lower()
    is_loopback = host == "localhost"
    if not is_loopback:
        try:
            is_loopback = ipaddress.ip_address(host).is_loopback
        except ValueError:
            is_loopback = False
    if not is_loopback:
        raise UnsafeTargetError("v0.1 permits loopback targets only")

    return TargetScope(base_url=base_url.rstrip("/"), host=host, port=parsed.port)
