import hashlib

from qw_adversary.signing import canonical_request, canonical_target, sign_request


def test_canonical_target_preserves_query_order() -> None:
    assert canonical_target("/api/v1/x", "b=2&a=1") == "/api/v1/x?b=2&a=1"


def test_body_change_changes_signature() -> None:
    common = dict(method="POST", target="/api/v1/events", timestamp="1770000000", nonce="0123456789abcdef")
    a = sign_request("secret", body=b'{"a":1}', **common)
    b = sign_request("secret", body=b'{"a":2}', **common)
    assert a != b


def test_target_change_changes_signature() -> None:
    common = dict(method="GET", timestamp="1770000000", nonce="0123456789abcdef", body=b"")
    a = sign_request("secret", target="/api/v1/a?x=1", **common)
    b = sign_request("secret", target="/api/v1/a?x=2", **common)
    assert a != b


def test_canonical_request_binds_method_target_timestamp_nonce_and_body_hash() -> None:
    body = b"abc"
    actual = canonical_request(method="post", target="/x?q=1", timestamp="10", nonce="n" * 16, body=body)
    expected = "\n".join(["POST", "/x?q=1", "10", "n" * 16, hashlib.sha256(body).hexdigest()]).encode()
    assert actual == expected
