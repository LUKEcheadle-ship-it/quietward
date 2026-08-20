from __future__ import annotations

import hashlib
import hmac


def derive_hmac_key(secret: str) -> bytes:
    return hashlib.sha256(("quietward-response-v1:" + secret).encode("utf-8")).digest()


def canonical_target(path: str, query: str = "") -> str:
    return path if not query else f"{path}?{query}"


def canonical_request(*, method: str, target: str, timestamp: str, nonce: str, body: bytes) -> bytes:
    body_hash = hashlib.sha256(body).hexdigest()
    return "\n".join([method.upper(), target, timestamp, nonce, body_hash]).encode("utf-8")


def sign_request(
    secret: str,
    *,
    method: str,
    target: str,
    timestamp: str,
    nonce: str,
    body: bytes,
) -> str:
    return hmac.new(
        derive_hmac_key(secret),
        canonical_request(
            method=method,
            target=target,
            timestamp=timestamp,
            nonce=nonce,
            body=body,
        ),
        hashlib.sha256,
    ).hexdigest()
