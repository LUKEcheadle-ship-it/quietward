from __future__ import annotations

import json
from datetime import datetime, timezone

from quietward.collectors.windows_parsers import (
    parse_windows_auth_events,
    parse_windows_connections,
    parse_windows_persistence,
    parse_windows_processes,
)
from quietward.privacy_identity import PrivacyIdentity


IDENTITY = PrivacyIdentity(b"w" * 32)
NOW = datetime(2026, 8, 23, 20, 0, tzinfo=timezone.utc)


def test_windows_process_regex_markers_execute_without_name_error() -> None:
    rows = [
        {
            "ProcessId": 100,
            "ParentProcessId": 1,
            "Name": "vssadmin.exe",
            "ExecutablePath": r"C:\Windows\System32\vssadmin.exe",
            "CommandLine": "vssadmin.exe delete shadows /all /quiet",
            "UserName": r"NT AUTHORITY\SYSTEM",
        },
        {
            "ProcessId": 101,
            "ParentProcessId": 1,
            "Name": "wevtutil.exe",
            "ExecutablePath": r"C:\Windows\System32\wevtutil.exe",
            "CommandLine": "wevtutil.exe cl Security",
            "UserName": r"NT AUTHORITY\SYSTEM",
        },
    ]
    parsed = parse_windows_processes(json.dumps(rows), IDENTITY)
    assert "ransomware_recovery_inhibition" in parsed[0].suspicious_markers
    assert "event_log_clearing" in parsed[1].suspicious_markers


def test_windows_connection_parser_accepts_collector_contract_and_keys_address() -> None:
    raw = "203.0.113.10"
    parsed = parse_windows_connections(
        json.dumps(
            {
                "Protocol": "tcp",
                "RemoteAddress": raw,
                "RemotePort": 443,
                "ProcessName": "browser",
            }
        ),
        IDENTITY,
        10,
    )
    assert len(parsed) == 1
    assert parsed[0].remote_address_hash == IDENTITY.identify_scoped(
        raw,
        "windows-outbound-address-v1",
    )
    assert raw not in json.dumps(parsed[0].to_dict())


def test_windows_auth_parser_keys_source_and_account() -> None:
    raw_ip = "198.51.100.25"
    events = parse_windows_auth_events(
        json.dumps(
            {
                "TimeCreated": NOW.isoformat(),
                "User": "Administrator",
                "SourceAddress": raw_ip,
            }
        ),
        host_id="host-a",
        privacy_identity=IDENTITY,
        fallback_time=NOW,
    )
    assert len(events) == 1
    event = events[0]
    assert event.attributes["source_address_hash"] == IDENTITY.identify_scoped(
        raw_ip,
        "windows-auth-source-v1",
    )
    assert event.attributes["address_identity"] == "installation_keyed_hmac_sha256"
    assert raw_ip not in json.dumps(event.to_dict())
    assert "Administrator" not in json.dumps(event.to_dict())


def test_windows_persistence_parser_matches_powershell_wire_fields_without_raw_values() -> None:
    secret_command = r"powershell.exe -enc SECRET-CONTENT"
    records = parse_windows_persistence(
        json.dumps(
            [
                {
                    "Category": "registry_run",
                    "Name": r"HKCU:\Software\Microsoft\Windows\CurrentVersion\Run\Updater",
                    "Command": secret_command,
                    "State": "enabled",
                    "Account": r"HOST\Alice",
                }
            ]
        ),
        IDENTITY,
        10,
    )
    assert len(records) == 1
    record = records[0]
    serialized = json.dumps(record.to_dict())
    assert "SECRET-CONTENT" not in serialized
    assert "HOST\\Alice" not in serialized
    assert "Updater" not in record.subject
    assert record.metadata["raw_name_persisted"] is False
    assert record.metadata["raw_command_persisted"] is False
    assert record.metadata["raw_account_persisted"] is False
    assert record.metadata["command_hash"] == record.metadata["command_identity_hash"]
    assert "unexpected_interpreter" in record.risk_markers
