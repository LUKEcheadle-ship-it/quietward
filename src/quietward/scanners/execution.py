from __future__ import annotations

import os
import shutil
import stat
import subprocess
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Callable, Sequence

from ..config import ScannerJobSettings
from ..contracts import SecurityEvent
from .clamav import parse_clamav_output
from .debsecan import parse_debsecan_simple
from .trivy import parse_trivy_json
from .yara import parse_yara_output


_ALLOWED_BINARIES = {"clamscan", "yara", "trivy", "debsecan"}
_ALLOWED_SCANNERS = {"clamav", "yara", "trivy", "debsecan"}
_TRUSTED_POSIX_PATH = "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"


def _bounded_error(value: str, limit: int = 500) -> str:
    return " ".join(value.replace("\x00", "").split())[:limit]


def _trusted_default_resolver(name: str) -> str | None:
    if os.name == "nt":
        resolved = shutil.which(name)
        if not resolved:
            return None
        try:
            path = Path(resolved).resolve(strict=True)
        except OSError:
            return None
        trusted_roots = [
            Path(os.environ.get("ProgramFiles") or r"C:\Program Files"),
            Path(os.environ.get("ProgramFiles(x86)") or r"C:\Program Files (x86)"),
            Path(os.environ.get("SystemRoot") or os.environ.get("WINDIR") or r"C:\Windows"),
        ]
        normalized = str(path).casefold()
        if not any(
            normalized == str(root).casefold()
            or normalized.startswith(str(root).rstrip("\\/").casefold() + os.sep.casefold())
            for root in trusted_roots
        ):
            return None
        return str(path)

    resolved = shutil.which(name, path=_TRUSTED_POSIX_PATH)
    if not resolved:
        return None
    try:
        path = Path(resolved).resolve(strict=True)
        info = path.stat()
    except OSError:
        return None
    if not stat.S_ISREG(info.st_mode) or info.st_uid != 0 or stat.S_IMODE(info.st_mode) & 0o022:
        return None
    trusted_roots = tuple(Path(item).resolve() for item in _TRUSTED_POSIX_PATH.split(os.pathsep))
    if not any(path.parent == root or root in path.parents for root in trusted_roots):
        return None
    return str(path)


@dataclass(frozen=True, slots=True)
class ScannerExecutionResult:
    scanner: str
    target: str | None
    started_at: datetime
    completed_at: datetime
    status: str
    returncode: int | None
    events: tuple[SecurityEvent, ...]
    error: str | None = None
    timed_out: bool = False
    output_truncated: bool = False
    command_binary: str | None = None

    def to_dict(self) -> dict[str, object]:
        return {
            "scanner": self.scanner,
            "target": self.target,
            "started_at": self.started_at.astimezone(timezone.utc).isoformat().replace("+00:00", "Z"),
            "completed_at": self.completed_at.astimezone(timezone.utc).isoformat().replace("+00:00", "Z"),
            "status": self.status,
            "returncode": self.returncode,
            "events_count": len(self.events),
            "error": self.error,
            "timed_out": self.timed_out,
            "output_truncated": self.output_truncated,
            "command_binary": self.command_binary,
            "shell_used": False,
            "sudo_used": False,
            "network_updates_allowed": False,
            "actions_executed": 0,
        }


class ScannerExecutor:
    """Runs bounded, explicitly configured local scans without updates, shell, sudo, or containment."""

    def __init__(
        self,
        host_id: str,
        *,
        executable_resolver: Callable[[str], str | None] | None = None,
        run_process: Callable[..., subprocess.CompletedProcess[bytes]] = subprocess.run,
    ) -> None:
        if not host_id.strip():
            raise ValueError("host_id must not be empty")
        self.host_id = host_id
        self.executable_resolver = executable_resolver or _trusted_default_resolver
        self.run_process = run_process

    def build_commands(self, job: ScannerJobSettings) -> list[tuple[tuple[str, ...], str | None]]:
        if not job.enabled:
            return []
        if job.scanner not in _ALLOWED_SCANNERS:
            raise ValueError(f"unsupported scanner: {job.scanner}")
        if job.scanner == "debsecan":
            if job.data_source is None:
                raise ValueError("debsecan requires an explicit local data_source")
            source = self._validate_path(job.data_source, "data_source")
            argv = ["debsecan", "--format", "simple", "--source", Path(source).as_uri()]
            if job.suite:
                argv.extend(["--suite", job.suite])
            return [(tuple(argv), None)]
        if not job.targets:
            raise ValueError(f"{job.scanner} requires at least one target")
        commands: list[tuple[tuple[str, ...], str | None]] = []
        for target in job.targets:
            normalized_target = self._validate_path(target, "target")
            if job.scanner == "clamav":
                database = (("--database=" + self._validate_path(job.data_source, "data_source")),) if job.data_source else ()
                argv = ("clamscan", "--recursive", "--infected", "--no-summary", "--cross-fs=no", "--max-filesize=100M", "--max-scansize=250M", *database, normalized_target)
            elif job.scanner == "yara":
                if job.rules_path is None:
                    raise ValueError("yara requires rules_path")
                rules = self._validate_path(job.rules_path, "rules_path")
                argv = ("yara", "--recursive", "--no-follow-symlinks", "--timeout", str(max(1, int(job.timeout_seconds))), "--skip-larger", str(100 * 1024 * 1024), rules, normalized_target)
            else:
                cache = (("--cache-dir", self._validate_path(job.data_source, "data_source")),) if job.data_source else ()
                cache_args = tuple(item for pair in cache for item in pair)
                argv = ("trivy", *cache_args, "filesystem", "--quiet", "--format", "json", "--offline-scan", "--skip-db-update", "--skip-java-db-update", "--skip-check-update", "--skip-vex-repo-update", "--scanners", "vuln,misconfig,secret", "--timeout", f"{max(1, int(job.timeout_seconds))}s", normalized_target)
            commands.append((argv, normalized_target))
        return commands

    def run(self, job: ScannerJobSettings) -> list[ScannerExecutionResult]:
        return [self._run_one(job, argv, target) for argv, target in self.build_commands(job)]

    def _run_one(self, job: ScannerJobSettings, argv: Sequence[str], target: str | None) -> ScannerExecutionResult:
        started = datetime.now(timezone.utc)
        binary = str(argv[0])
        if binary not in _ALLOWED_BINARIES:
            raise ValueError("scanner binary is not allowed")
        resolved = self.executable_resolver(binary)
        if not resolved:
            return ScannerExecutionResult(job.scanner, target, started, datetime.now(timezone.utc), "unavailable", 127, (), f"trusted {binary} is not installed")
        command = (resolved, *tuple(str(item) for item in argv[1:]))
        if any(os.path.basename(item).casefold() in {"sudo", "su", "sh", "bash", "freshclam"} for item in command):
            raise ValueError("shell, privilege escalation, and updater commands are forbidden")
        env = {
            "PATH": _TRUSTED_POSIX_PATH if os.name != "nt" else str(Path(resolved).parent),
            "HOME": os.environ.get("HOME", "/nonexistent"),
            "LANG": "C.UTF-8",
            "LC_ALL": "C.UTF-8",
            "NO_PROXY": "*",
            "no_proxy": "*",
        }
        try:
            process = self.run_process(command, shell=False, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=job.timeout_seconds, check=False, env=env)
            raw_stdout = bytes(process.stdout or b"")
            raw_stderr = bytes(process.stderr or b"")
            truncated = len(raw_stdout) > job.max_output_bytes or len(raw_stderr) > job.max_output_bytes
            stdout = raw_stdout[:job.max_output_bytes].decode("utf-8", errors="replace")
            stderr = raw_stderr[:job.max_output_bytes].decode("utf-8", errors="replace")
            events = tuple(self._parse(job, stdout, target, started, int(process.returncode)))
            acceptable = self._acceptable_returncode(job.scanner, int(process.returncode))
            return ScannerExecutionResult(job.scanner, target, started, datetime.now(timezone.utc), "ok" if acceptable else "error", int(process.returncode), events, error=None if acceptable else _bounded_error(stderr or f"scanner exited {process.returncode}"), output_truncated=truncated, command_binary=resolved)
        except subprocess.TimeoutExpired as exc:
            return ScannerExecutionResult(job.scanner, target, started, datetime.now(timezone.utc), "timeout", 124, (), error=_bounded_error(str(exc)), timed_out=True, command_binary=resolved)
        except OSError as exc:
            return ScannerExecutionResult(job.scanner, target, started, datetime.now(timezone.utc), "error", None, (), error=_bounded_error(str(exc)), command_binary=resolved)

    def _parse(self, job: ScannerJobSettings, stdout: str, target: str | None, observed_at: datetime, returncode: int) -> list[SecurityEvent]:
        if job.scanner == "clamav":
            return parse_clamav_output(stdout, self.host_id, observed_at=observed_at, scanner_exit_code=returncode)
        if job.scanner == "yara":
            assert target is not None
            return parse_yara_output(stdout, self.host_id, target, observed_at=observed_at)
        if job.scanner == "trivy":
            return parse_trivy_json(stdout or "{}", self.host_id, observed_at=observed_at)
        return parse_debsecan_simple(stdout, self.host_id, observed_at=observed_at, suite=job.suite)

    @staticmethod
    def _acceptable_returncode(scanner: str, returncode: int) -> bool:
        return returncode in {0, 1} if scanner == "clamav" else returncode == 0

    @staticmethod
    def _validate_path(path: Path, label: str) -> str:
        if not path.is_absolute():
            raise ValueError(f"{label} must be absolute")
        text = str(path)
        if "\x00" in text or text in {"", "/proc", "/sys", "/dev"}:
            raise ValueError(f"unsafe {label}")
        return text
