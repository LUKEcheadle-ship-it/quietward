import pytest

from qw_adversary.scope import UnsafeTargetError, validate_target


@pytest.mark.parametrize("url", [
    "http://127.0.0.1:8002",
    "http://localhost:8002",
    "http://[::1]:8002",
    "https://127.0.0.1:8443",
])
def test_loopback_targets_allowed(url: str) -> None:
    assert validate_target(url).base_url == url


@pytest.mark.parametrize("url", [
    "http://192.168.1.20:8002",
    "http://10.0.0.5:8002",
    "https://example.com",
    "ftp://127.0.0.1",
    "http://user:pass@127.0.0.1:8002",
    "http://127.0.0.1:8002?x=1",
])
def test_non_loopback_or_ambiguous_targets_rejected(url: str) -> None:
    with pytest.raises(UnsafeTargetError):
        validate_target(url)
