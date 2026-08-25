from __future__ import annotations

import os
import subprocess
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Callable, Sequence

from ..config import ScannerJobSettings
from ..contracts import SecurityEvent
from ..windows_trust import (
    WindowsTrustedPaths,
    is_regular_non_reparse_file,
    load_windows_trusted_paths,
    trusted_executable,
    trusted_windows_environment,
)
from .clamav import parse_clamav_output
from .debsecan import parse_debsecan_simple
from .trivy import parse_trivy_json
from .yara import parse_yara_output

_ALLOWED_BINARIES = {"clamscan", "yara", "trivy", "debsecan"}
_ALLOWED_SCANNERS = {"clamav", "yara", "trivy", "debsecan"}
_POSIX_EXECUTABLE_ROOTS = (
    Path("/usr/local/sbin"), Path("/usr/local/bin"), Path("/usr/sbin"),
    Path("/usr/bin"), Path("/sbin"), Path("/bin"),
)


def _bounded_error(value: str, limit: int = 500) -> str:
    return " ".join(value.replace("\x00", "").split())[:limit]


def _regular_non_link_executable(path: Path) -> bool:
    return is_regular_non_reparse_file(path, executable=True)


def _windows_scanner_candidates(binary: str, paths: WindowsTrustedPaths | None = None) -> tuple[Path, ...]:
    trusted = paths if paths is not None else load_windows_trusted_paths()
    if trusted is None:
        return ()
    roots = tuple(root for root in (trusted.program_files, trusted.program_files_x86) if root is not None)
    mapping = {
        "clamscan": tuple(root / "ClamAV" / "clamscan.exe" for root in roots),
        "yara": tuple(candidate for root in roots for candidate in (root / "YARA" / "yara64.exe", root / "YARA" / "yara.exe")),
        "trivy": tuple(root / "Trivy" / "trivy.exe" for root in roots),
        "debsecan": (),
    }
    return mapping.get(binary.casefold(), ())


def resolve_trusted_scanner(binary: str) -> str | None:
    name = os.path.basename(binary).casefold()
    if name not in _ALLOWED_BINARIES or name != binary.casefold():
        return None
    if os.name == "nt":
        paths = load_windows_trusted_paths()
        if paths is None:
            return None
        return trusted_executable(_windows_scanner_candidates(name, paths), paths.executable_roots)
    for candidate in tuple(root / name for root in _POSIX_EXECUTABLE_ROOTS):
        if _regular_non_link_executable(candidate):
            return str(candidate.resolve(strict=True))
    return None


def _trusted_environment(executable: Path) -> dict[str, str]:
    if os.name == "nt":
        paths = load_windows_trusted_paths()
        if paths is None:
            raise ValueError("trusted Windows directories are unavailable")
        return trusted_windows_environment(executable, paths, deny_network_updates=True)
    return {"PATH": os.pathsep.join(str(root) for root in _POSIX_EXECUTABLE_ROOTS), "HOME": os.environ.get("HOME", "/nonexistent"), "LANG": "C.UTF-8", "LC_ALL": "C.UTF-8", "NO_PROXY": "*", "no_proxy": "*"}


def _injected_environment(executable: Path) -> dict[str, str]:
    if os.name != "nt":
        return {"PATH": str(executable.parent), "HOME": os.environ.get("HOME", "/nonexistent"), "LANG": "C.UTF-8", "LC_ALL": "C.UTF-8", "NO_PROXY": "*", "no_proxy": "*"}
    env: dict[str, str] = {"PATH": str(executable.parent), "PATHEXT": ".COM;.EXE;.BAT;.CMD", "NO_PROXY": "*", "no_proxy": "*"}
    for key in ("SYSTEMROOT","WINDIR","TEMP","TMP","LOCALAPPDATA","APPDATA","PROGRAMDATA","USERPROFILE","HOMEDRIVE","HOMEPATH"):
        value = os.environ.get(key) or os.environ.get(key.title())
        if value:
            env[key] = value
    return env


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
    """Runs bounded local scans without updates, shell, sudo, or containment."""

    def __init__(
        self,
        host_id: str,
        *,
        executable_resolver: Callable[[str], str | None] = resolve_trusted_scanner,
        run_process: Callable[..., subprocess.CompletedProcess[bytes]] = subprocess.run,
    ) -> None:
        if not host_id.strip():
            raise ValueError("host_id must not be empty")
        self.host_id = host_id
        self.executable_resolver = executable_resolver
        self._production_resolver = executable_resolver is resolve_trusted_scanner
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
                database = (("--database=" + self._validate_path(job.data_source, "data_source"),) if job.data_source else ())
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
            return ScannerExecutionResult(job.scanner, target, started, datetime.now(timezone.utc), "unavailable", 127, (), f"trusted {binary} executable is not installed")
        resolved_path = Path(resolved)
        if not resolved_path.is_absolute() or not _regular_non_link_executable(resolved_path):
            raise ValueError("scanner executable must be a trusted regular absolute file")
        command = (str(resolved_path), *tuple(str(item) for item in argv[1:]))
        if any(os.path.basename(item).casefold() in {"sudo", "su", "sh", "bash", "freshclam"} for item in command):
            raise ValueError("shell, privilege escalation, and updater commands are forbidden")
        env = _trusted_environment(resolved_path) if self._production_resolver else _injected_environment(resolved_path)
        try:
            process = self.run_process(command, shell=False, cwd=str(resolved_path.parent), stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=job.timeout_seconds, check=False, env=env)
            raw_stdout = bytes(process.stdout or b"")
            raw_stderr = bytes(process.stderr or b"")
            truncated = len(raw_stdout) > job.max_output_bytes or len(raw_stderr) > job.max_output_bytes
            stdout = raw_stdout[: job.max_output_bytes].decode("utf-8", errors="replace")
            stderr = raw_stderr[: job.max_output_bytes].decode("utf-8", errors="replace")
            returncode = int(process.returncode)
            if truncated:
                return ScannerExecutionResult(job.scanner, target, started, datetime.now(timezone.utc), "error", returncode, (), error="scanner output exceeded the configured safety limit", output_truncated=True, command_binary=str(resolved_path))
            if not self._acceptable_returncode(job.scanner, returncode):
                return ScannerExecutionResult(job.scanner, target, started, datetime.now(timezone.utc), "error", returncode, (), error=_bounded_error(stderr or f"scanner exited {returncode}"), command_binary=str(resolved_path))
            try:
                events = tuple(self._parse(job, stdout, target, started, returncode))
            except (ValueError, TypeError, KeyError, IndexError):
                return ScannerExecutionResult(job.scanner, target, started, datetime.now(timezone.utc), "error", returncode, (), error="scanner returned invalid or incomplete output", command_binary=str(resolved_path))
            return ScannerExecutionResult(job.scanner, target, started, datetime.now(timezone.utc), "ok", returncode, events, command_binary=str(resolved_path))
        except subprocess.TimeoutExpired as exc:
            return ScannerExecutionResult(job.scanner, target, started, datetime.now(timezone.utc), "timeout", 124, (), error=_bounded_error(str(exc)), timed_out=True, command_binary=str(resolved_path))
        except OSError as exc:
            return ScannerExecutionResult(job.scanner, target, started, datetime.now(timezone.utc), "error", None, (), error=_bounded_error(str(exc)), command_binary=str(resolved_path))

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
