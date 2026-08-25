from __future__ import annotations

import json
import os
import tempfile
import unittest
from datetime import datetime, timezone
from pathlib import Path
from unittest.mock import patch

from quietward.collectors import CollectionBatch, CollectorSnapshot
from quietward.config import load_config
from quietward.console import main as console_main
from quietward.contracts import EventKind, SecurityEvent
from quietward.exports import (
    build_redacted_incident_export,
    write_private_incident_export,
)
from quietward.pipeline import SentinelPipeline
from quietward.storage import SentinelStore


class IncidentExportTests(unittest.TestCase):
    def _stored_finding(
        self,
        root: Path,
    ) -> tuple[Path, str, str]:
        config_path = root / "config.json"
        config_path.write_text(
            json.dumps(
                {
                    "state_dir": str(root / "state"),
                    "dashboard": {"enabled": False},
                    "collector": {
                        "include_auth_journal": False,
                        "include_docker": False,
                    },
                }
            ),
            encoding="utf-8",
        )
        config = load_config(config_path)
        observed = datetime.now(timezone.utc)
        secret_subject = "/home/luke/private/evidence.bin"
        event = SecurityEvent(
            event_id="event-export",
            observed_at=observed,
            host_id="host-test",
            source="clamav",
            kind=EventKind.MALWARE_SIGNATURE,
            subject=secret_subject,
            attributes={
                "signature": "Example.Test.Signature",
                "user": "luke",
                "process_name": "private-process",
                "target": secret_subject,
                "description": "/home/luke/private/free-text detail",
                "raw_remote_address_persisted": False,
            },
        )
        report = SentinelPipeline().analyze([event])
        finding_id = report.findings[0].finding_id
        with SentinelStore(config.storage) as store:
            store.persist_cycle(
                CollectionBatch(
                    CollectorSnapshot(observed_at=observed, host_id="host-test"),
                    (event,),
                ),
                report,
                started_at=observed,
                completed_at=observed,
            )
            store.set_finding_state(
                finding_id,
                "acknowledged",
                note="Luke's private analyst note",
            )
        return config_path, finding_id, secret_subject

    def _redacted_value(
        self,
        config_path: Path,
        finding_id: str,
    ) -> dict[str, object]:
        config = load_config(config_path)
        with SentinelStore(config.storage) as store:
            bundle = store.incident_bundle(finding_id)
        bundle["proposals"][0]["reason"] = (
            "/home/luke/private/proposal reason"
        )
        return build_redacted_incident_export(bundle)

    def test_redacted_export_excludes_subjects_hosts_notes_and_free_text(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            config_path, finding_id, secret_subject = self._stored_finding(root)
            value = self._redacted_value(config_path, finding_id)
            serialized = json.dumps(value)
            self.assertEqual(value["export_version"], "quietward-redacted-incident-v2")
            self.assertIn("QuietWard incident", value["finding"]["title"])
            self.assertNotIn(secret_subject, serialized)
            self.assertNotIn('"host_id": "host-test"', serialized)
            self.assertNotIn("private analyst note", serialized)
            self.assertNotIn("private-process", serialized)
            self.assertNotIn('"user": "luke"', serialized)
            self.assertNotIn("free-text detail", serialized)
            self.assertNotIn("proposal reason", serialized)
            self.assertTrue(value["privacy"]["subjects_redacted"])
            self.assertTrue(value["privacy"]["host_ids_redacted"])
            self.assertTrue(value["privacy"]["arbitrary_strings_hashed"])
            self.assertFalse(value["review"]["analyst_note_included"])
            self.assertFalse(value["proposals"][0]["reason_included"])
            self.assertIn(
                "value_hash",
                value["events"][0]["attributes"]["description"],
            )
            self.assertEqual(value["privacy"]["actions_executed"], 0)

    def test_console_writes_private_export_and_refuses_overwrite(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            config_path, finding_id, secret_subject = self._stored_finding(root)
            output = root / "incident.json"
            result = console_main(
                [
                    "export",
                    finding_id,
                    str(output),
                    "--config",
                    str(config_path),
                    "--pretty",
                ]
            )
            self.assertEqual(result, 0)
            if os.name != "nt":
                self.assertEqual(output.stat().st_mode & 0o777, 0o600)
            loaded = json.loads(output.read_text(encoding="utf-8"))
            self.assertEqual(loaded["export_version"], "quietward-redacted-incident-v2")
            self.assertNotIn(secret_subject, output.read_text(encoding="utf-8"))
            with self.assertRaises(FileExistsError):
                console_main(
                    [
                        "export",
                        finding_id,
                        str(output),
                        "--config",
                        str(config_path),
                    ]
                )

    def test_short_low_level_writes_are_completed(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            config_path, finding_id, _ = self._stored_finding(root)
            value = self._redacted_value(config_path, finding_id)
            output = root / "incident.json"
            real_write = os.write

            def short_write(descriptor: int, data: object) -> int:
                return real_write(descriptor, bytes(data[:3]))

            with patch(
                "quietward.exports.os.write",
                side_effect=short_write,
            ):
                write_private_incident_export(output, value)
            loaded = json.loads(output.read_text(encoding="utf-8"))
            self.assertEqual(
                loaded["export_version"],
                "quietward-redacted-incident-v2",
            )

    def test_export_rejects_dangling_symlink(self) -> None:
        value = {
            "finding": {"finding_id": "f", "subject_hash": "hash"},
            "review": {},
            "events": [],
            "proposals": [],
            "evidence_chain": {},
            "privacy": {},
        }
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            output = root / "incident.json"
            try:
                output.symlink_to(root / "missing")
            except OSError:
                self.skipTest("symlink privilege unavailable")
            with self.assertRaisesRegex(ValueError, "symlink"):
                write_private_incident_export(output, value)


if __name__ == "__main__":
    unittest.main()
