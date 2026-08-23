from __future__ import annotations

import os
from pathlib import Path

import pytest

from quietward.collectors import command
from quietward.scanners import execution


def test_posix_collector_resolver_rejects_binary_outside_trusted_system_paths(tmp_path: Path, monkeypatch) -> None:
    if os.name == "nt":
        pytest.skip("POSIX resolver test")
    fake = tmp_path / "ps"
    fake.write_text("not a real binary", encoding="utf-8")
    fake.chmod(0o755)
    monkeypatch.setattr(command.shutil, "which", lambda name, path=None: str(fake))
    assert command._trusted_posix_executable("ps") is None


def test_posix_scanner_resolver_rejects_binary_outside_trusted_system_paths(tmp_path: Path, monkeypatch) -> None:
    if os.name == "nt":
        pytest.skip("POSIX resolver test")
    fake = tmp_path / "trivy"
    fake.write_text("not a real binary", encoding="utf-8")
    fake.chmod(0o755)
    monkeypatch.setattr(execution.shutil, "which", lambda name, path=None: str(fake))
    assert execution._trusted_default_resolver("trivy") is None


def test_service_pins_trusted_posix_path() -> None:
    root = Path(__file__).resolve().parents[1]
    unit = (root / "deploy" / "quietward.service").read_text(encoding="utf-8")
    assert "Environment=PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin" in unit


def test_default_collector_runner_executes_absolute_resolved_binary() -> None:
    source = Path(command.__file__).read_text(encoding="utf-8")
    assert "command = (resolved, *normalized[1:])" in source
    assert '"PATH": _TRUSTED_POSIX_PATH' in source
