from __future__ import annotations

import json
from datetime import datetime, timezone

from quietward.collectors.parsers import parse_auth_journal, parse_connections_output
from quietward.collectors.windows_parsers import (
    parse_windows_auth_events,
    parse_windows_connections,
)
from quietward.privacy_identity import PrivacyIdentity


RAW_IP = "203.0.113.42"


def test_linux_network_pseudonym_changes_between_installation_keys() -> None:
    first = PrivacyIdentity(b"a" * 32)
    second = PrivacyIdentity(b"b" * 32)
    text = f'tcp ESTAB 0 0 192.168.1.10:5000 {RAW_IP}:443 users:(("app",pid=2,fd=3))'

    one = parse_connections_output(text, first)[0]
    two = parse_connections_output(text, second)[0]

    assert one.remote_address_hash != two.remote_address_hash
    assert RAW_IP not in json.dumps(one.to_dict())
    assert RAW_IP not in json.dumps(two.to_dict())


def test_linux_auth_source_pseudonym_is_keyed() -> None:
    first = PrivacyIdentity(b"a" * 32)
    second = PrivacyIdentity(b"b" * 32)
    text = json.dumps(
        {
            "MESSAGE": f"Failed password for invalid user admin from {RAW_IP}",
            "__REALTIME_TIMESTAMP": "1785430800000000",
        }
    )

    one = parse_auth_journal(text, privacy_identity=first)[0]
    two = parse_auth_journal(text, privacy_identity=second)[0]

    assert one["source_address_hash"] != two["source_address_hash"]
    assert RAW_IP not in json.dumps(one, default=str)


def test_windows_network_and_auth_source_pseudonyms_are_keyed() -> None:
    first = PrivacyIdentity(b"a" * 32)
    second = PrivacyIdentity(b"b" * 32)
    connections = json.dumps(
        [
            {
                "Protocol": "tcp",
                "RemoteAddress": RAW_IP,
                "RemotePort": 443,
                "ProcessName": "browser",
            }
        ]
    )
    auth = json.dumps(
        [
            {
                "TimeCreated": "2026-08-23T20:00:00Z",
                "User": "Administrator",
                "SourceAddress": RAW_IP,
            }
        ]
    )

    first_connection = parse_windows_connections(connections, first)[0]
    second_connection = parse_windows_connections(connections, second)[0]
    assert first_connection.remote_address_hash != second_connection.remote_address_hash

    first_event = parse_windows_auth_events(
        auth,
        host_id="host-a",
        privacy_identity=first,
        fallback_time=datetime.now(timezone.utc),
    )[0]
    second_event = parse_windows_auth_events(
        auth,
        host_id="host-a",
        privacy_identity=second,
        fallback_time=datetime.now(timezone.utc),
    )[0]
    assert (
        first_event.attributes["source_address_hash"]
        != second_event.attributes["source_address_hash"]
    )
    assert RAW_IP not in json.dumps(first_event.to_dict())
