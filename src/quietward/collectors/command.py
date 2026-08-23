from __future__ import annotations

import os
import re
import shutil
import stat
import subprocess
from dataclasses import dataclass
from pathlib import Path
from typing import Protocol, Sequence

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
_CONTAINER_ID = re.compile(r"^[a-fA-F0-9]{12,64}$")
_TRUSTED_POSIX_PATH = "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"


@dataclass(frozen=True, slots=True)
class CommandResult:
    argv: tuple[str, ...]
    returncode: int
    stdout: str
    stderr: str
    timed_out: bool = False


class CommandRunner(Protocol):
    def run(self, argv: Sequence[str]) -> CommandResult: ...


def _trusted_posix_executable(name: str) -> str | None:
    resolved = shutil.which(name, path=_TRUSTED_POSIX_PATH)
    if not resolved:
        return None
    try:
        path = Path(resolved).resolve(strict=True)
        info = path.stat()
    except OSError:
        return None
    if not path.is_absolute() or not stat.S_ISREG(info.st_mode):
        return None
    if info.st_uid != 0 or stat.S_IMODE(info.st_mode) & 0o022:
        return None
    trusted_roots = tuple(Path(item).resolve() for item in _TRUSTED_POSIX_PATH.split(os.pathsep))
    if not any(path.parent == root or root in path.parents for root in trusted_roots):
        return None
    return str(path)


def _trusted_windows_executable(name: str) -> str | None:
    lowered = name.casefold()
    system_root = Path(os.environ.get("SystemRoot") or os.environ.get("WINDIR") or r"C:\Windows")
    if lowered in {"powershell", "powershell.exe"}:
        candidate = system_root / "System32" / "WindowsPowerShell" / "v1.0" / "powershell.exe"
        return str(candidate) if candidate.is_file() else None
    if lowered in {"docker", "docker.exe"}:
        program_files = Path(os.environ.get("ProgramFiles") or r"C:\Program Files")
        candidates = (
            program_files / "Docker" / "Docker" / "resources" / "bin" / "docker.exe",
            program_files / "Docker" / "Docker" / "resources" / "docker.exe",
        )
        for candidate in candidates:
            if candidate.is_file():
                return str(candidate)
        return None
    return None


def _trusted_executable(name: str) -> str | None:
    return _trusted_windows_executable(name) if os.name == "nt" else _trusted_posix_executable(name)


class ReadOnlyCommandRunner:
    def __init__(
        self,
        timeout_seconds: float = 5.0,
        max_output_bytes: int = 2_000_000,
        *,
        additional_commands: Sequence[Sequence[str]] = (),
    ) -> None:
        if timeout_seconds <= 0 or max_output_bytes <= 0:
            raise ValueError("runner limits must be positive")
        self.timeout_seconds = timeout_seconds
        self.max_output_bytes = max_output_bytes
        self.additional_commands = frozenset(
            tuple(str(part) for part in command) for command in additional_commands
        )

    @staticmethod
    def validate(
        argv: Sequence[str],
        additional_commands: Sequence[Sequence[str]] = (),
    ) -> tuple[str, ...]:
        normalized = tuple(str(item) for item in argv)
        if normalized:
            executable = os.path.basename(normalized[0]).lower()
            if executable in {"sudo", "su", "sh", "bash", "cmd", "cmd.exe", "wscript", "wscript.exe", "cscript", "cscript.exe"}:
                raise ValueError("shell and privilege-escalation commands are forbidden")
        dynamic = (
            len(normalized) == len(DOCKER_INSPECT_PREFIX) + 1
            and normalized[: len(DOCKER_INSPECT_PREFIX)] == DOCKER_INSPECT_PREFIX
            and bool(_CONTAINER_ID.fullmatch(normalized[-1]))
        )
        additional = {
            tuple(str(part) for part in command) for command in additional_commands
        }
        if normalized not in ALLOWED_COMMANDS and normalized not in additional and not dynamic:
            raise ValueError(
                f"command is not in the read-only allowlist: {normalized!r}"
            )
        if not normalized:
            raise ValueError("empty commands are forbidden")
        executable = os.path.basename(normalized[0]).lower()
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
        return normalized

    def run(self, argv: Sequence[str]) -> CommandResult:
        normalized = self.validate(argv, self.additional_commands)
        resolved = _trusted_executable(normalized[0])
        if resolved is None:
            return CommandResult(
                normalized,
                127,
                "",
                f"trusted command unavailable: {normalized[0]}",
            )
        command = (resolved, *normalized[1:])
        if os.name == "nt":
            allowed_environment = {
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
                "PSMODULEPATH",
            }
            env = {
                key: value
                for key, value in os.environ.items()
                if key.upper() in allowed_environment
            }
            env["PATH"] = str(Path(resolved).parent)
        else:
            env = {
                "PATH": _TRUSTED_POSIX_PATH,
                "LANG": "C.UTF-8",
                "LC_ALL": "C.UTF-8",
            }
        try:
            completed = subprocess.run(
                command,
                shell=False,
                stdin=subprocess.DEVNULL,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=False,
                timeout=self.timeout_seconds,
                check=False,
                env=env,
            )
        except FileNotFoundError:
            return CommandResult(
                normalized,
                127,
                "",
                f"trusted command unavailable: {normalized[0]}",
            )
        except subprocess.TimeoutExpired as exc:
            return CommandResult(
                normalized,
                124,
                self._decode(exc.stdout or b""),
                self._decode(exc.stderr or b"") or "command timed out",
                True,
            )
        return CommandResult(
            normalized,
            completed.returncode,
            self._decode(completed.stdout),
            self._decode(completed.stderr),
        )

    def _decode(self, value: bytes) -> str:
        bounded = value[: self.max_output_bytes]
        text = bounded.decode("utf-8", errors="replace")
        return text + (
            "\n[output truncated]" if len(value) > self.max_output_bytes else ""
        )
