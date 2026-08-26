from __future__ import annotations

import os
import re
import subprocess
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Callable, Protocol, Sequence

from ..windows_trust import (
    WindowsTrustedPaths,
    is_regular_non_reparse_file,
    load_windows_trusted_paths,
    trusted_executable,
    trusted_windows_environment,
)

PS_COMMAND = ("ps", "--no-headers", "-eo", "pid=,ppid=,user=,comm=,args=")
SS_COMMAND = ("ss", "-H", "-lntup")
CONNECTIONS_COMMAND = ("ss", "-H", "-ntup", "state", "established")
JOURNAL_AUTH_COMMAND = (
    "journalctl",
    "--no-pager",
    "--output=json",
    "--since=-15min",
    "-u",
    "ssh.service",
    "-u",
    "sshd.service",
)
DOCKER_PS_COMMAND = ("docker", "ps", "--no-trunc", "--format", "{{json .}}")
DOCKER_INSPECT_PREFIX = (
    "docker",
    "inspect",
    "--type",
    "container",
    "--format",
    "{{json .}}",
)
ALLOWED_COMMANDS = {
    PS_COMMAND,
    SS_COMMAND,
    CONNECTIONS_COMMAND,
    JOURNAL_AUTH_COMMAND,
    DOCKER_PS_COMMAND,
}
_ALLOWED_EXECUTABLES = {"ps", "ss", "journalctl", "docker", "powershell.exe"}
_CONTAINER_ID = re.compile(r"^[a-fA-F0-9]{12,64}$")
_MAX_DOCKER_BATCH = 50
_POSIX_EXECUTABLE_ROOTS = (
    Path("/usr/local/sbin"),
    Path("/usr/local/bin"),
    Path("/usr/sbin"),
    Path("/usr/bin"),
    Path("/sbin"),
    Path("/bin"),
)
_TRUSTED_POSIX_PATH = os.pathsep.join(
    str(root) for root in _POSIX_EXECUTABLE_ROOTS
)


@dataclass(frozen=True, slots=True)
class CommandResult:
    argv: tuple[str, ...]
    returncode: int
    stdout: str
    stderr: str
    timed_out: bool = False
    duration_ms: float = 0.0


class CommandRunner(Protocol):
    def run(self, argv: Sequence[str]) -> CommandResult: ...


def _regular_non_link_executable(path: Path) -> bool:
    return is_regular_non_reparse_file(path, executable=True)


def _windows_candidates(
    binary: str,
    paths: WindowsTrustedPaths | None = None,
) -> tuple[Path, ...]:
    trusted = paths if paths is not None else load_windows_trusted_paths()
    if trusted is None:
        return ()
    mapping = {
        "powershell.exe": (
            trusted.system / "WindowsPowerShell" / "v1.0" / "powershell.exe",
        ),
        "docker": tuple(
            root / "Docker" / "Docker" / "resources" / "bin" / "docker.exe"
            for root in trusted.executable_roots
            if root in {trusted.program_files, trusted.program_files_x86}
        ),
    }
    return mapping.get(binary.casefold(), ())


def resolve_trusted_executable(binary: str) -> str | None:
    name = os.path.basename(binary).casefold()
    if name not in _ALLOWED_EXECUTABLES or name != binary.casefold():
        return None
    if os.name == "nt":
        paths = load_windows_trusted_paths()
        if paths is None:
            return None
        return trusted_executable(
            _windows_candidates(name, paths),
            paths.executable_roots,
        )
    candidates = tuple(root / name for root in _POSIX_EXECUTABLE_ROOTS)
    for candidate in candidates:
        if _regular_non_link_executable(candidate):
            return str(candidate.resolve(strict=True))
    return None


def _trusted_environment(executable: Path) -> dict[str, str]:
    if os.name == "nt":
        paths = load_windows_trusted_paths()
        if paths is None:
            raise ValueError("trusted Windows directories are unavailable")
        return trusted_windows_environment(executable, paths)
    return {
        "PATH": _TRUSTED_POSIX_PATH,
        "LANG": "C.UTF-8",
        "LC_ALL": "C.UTF-8",
    }


def _injected_environment(executable: Path) -> dict[str, str]:
    """Minimal environment for explicitly injected test/embedding resolvers."""

    if os.name != "nt":
        return {
            "PATH": str(executable.parent),
            "LANG": "C.UTF-8",
            "LC_ALL": "C.UTF-8",
        }

    env: dict[str, str] = {
        "PATH": str(executable.parent),
        "PATHEXT": ".COM;.EXE;.BAT;.CMD",
    }
    for key in (
        "SYSTEMROOT",
        "WINDIR",
        "TEMP",
        "TMP",
        "LOCALAPPDATA",
        "APPDATA",
        "PROGRAMDATA",
        "USERPROFILE",
        "HOMEDRIVE",
        "HOMEPATH",
    ):
        value = os.environ.get(key) or os.environ.get(key.title())
        if value:
            env[key] = value
    return env


class ReadOnlyCommandRunner:
    def __init__(
        self,
        timeout_seconds: float = 5.0,
        max_output_bytes: int = 2_000_000,
        *,
        additional_commands: Sequence[Sequence[str]] = (),
        executable_resolver: Callable[[str], str | None] = resolve_trusted_executable,
    ) -> None:
        if timeout_seconds <= 0 or max_output_bytes <= 0:
            raise ValueError("runner limits must be positive")
        self.timeout_seconds = timeout_seconds
        self.max_output_bytes = max_output_bytes
        self.additional_commands = frozenset(
            tuple(str(part) for part in command) for command in additional_commands
        )
        self.executable_resolver = executable_resolver
        self._production_resolver = executable_resolver is resolve_trusted_executable
        self.commands_executed = 0
        self.command_duration_ms = 0.0

    @staticmethod
    def validate(
        argv: Sequence[str],
        additional_commands: Sequence[Sequence[str]] = (),
    ) -> tuple[str, ...]:
        normalized = tuple(str(item) for item in argv)
        if not normalized:
            raise ValueError("empty commands are forbidden")
        executable = os.path.basename(normalized[0]).casefold()
        if executable in {
            "sudo",
            "su",
            "sh",
            "bash",
            "cmd",
            "cmd.exe",
            "wscript",
            "wscript.exe",
            "cscript",
            "cscript.exe",
        }:
            raise ValueError("shell and privilege-escalation commands are forbidden")
        if executable not in _ALLOWED_EXECUTABLES or normalized[0].casefold() != executable:
            raise ValueError("command executable is not in the read-only allowlist")
        docker_args = normalized[len(DOCKER_INSPECT_PREFIX) :]
        dynamic = (
            normalized[: len(DOCKER_INSPECT_PREFIX)] == DOCKER_INSPECT_PREFIX
            and 1 <= len(docker_args) <= _MAX_DOCKER_BATCH
            and all(_CONTAINER_ID.fullmatch(value) for value in docker_args)
        )
        additional = {tuple(str(part) for part in command) for command in additional_commands}
        if normalized not in ALLOWED_COMMANDS and normalized not in additional and not dynamic:
            raise ValueError(f"command is not in the read-only allowlist: {normalized!r}")
        return normalized

    def _record(self, result: CommandResult) -> CommandResult:
        self.commands_executed += 1
        self.command_duration_ms += max(0.0, float(result.duration_ms))
        return result

    def performance_snapshot(self) -> dict[str, object]:
        return {
            "commands_executed": self.commands_executed,
            "command_duration_ms": round(self.command_duration_ms, 3),
            "mean_command_ms": round(self.command_duration_ms / self.commands_executed, 3) if self.commands_executed else 0.0,
            "shell_used": False,
            "actions_executed": 0,
        }

    def run(self, argv: Sequence[str]) -> CommandResult:
        normalized = self.validate(argv, self.additional_commands)
        started = time.perf_counter()
        resolved = self.executable_resolver(normalized[0])
        if not resolved:
            return self._record(
                CommandResult(normalized, 127, "", f"trusted command unavailable: {normalized[0]}", duration_ms=(time.perf_counter() - started) * 1000.0)
            )
        executable = Path(resolved)
        if not executable.is_absolute() or not _regular_non_link_executable(executable):
            raise ValueError("command executable must be a trusted regular absolute file")
        command = (resolved, *normalized[1:])
        env = _trusted_environment(executable) if self._production_resolver else _injected_environment(executable)
        try:
            completed = subprocess.run(
                command,
                shell=False,
                cwd=str(executable.parent),
                stdin=subprocess.DEVNULL,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=False,
                timeout=self.timeout_seconds,
                check=False,
                env=env,
            )
        except FileNotFoundError:
            return self._record(
                CommandResult(normalized, 127, "", f"trusted command unavailable: {normalized[0]}", duration_ms=(time.perf_counter() - started) * 1000.0)
            )
        except subprocess.TimeoutExpired as exc:
            return self._record(
                CommandResult(
                    normalized,
                    124,
                    self._decode(exc.stdout or b""),
                    self._decode(exc.stderr or b"") or "command timed out",
                    True,
                    (time.perf_counter() - started) * 1000.0,
                )
            )
        return self._record(
            CommandResult(
                normalized,
                completed.returncode,
                self._decode(completed.stdout),
                self._decode(completed.stderr),
                duration_ms=(time.perf_counter() - started) * 1000.0,
            )
        )

    def _decode(self, value: bytes) -> str:
        bounded = value[: self.max_output_bytes]
        text = bounded.decode("utf-8", errors="replace")
        return text + ("\n[output truncated]" if len(value) > self.max_output_bytes else "")
