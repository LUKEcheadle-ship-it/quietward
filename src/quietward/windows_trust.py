from __future__ import annotations

import ctypes
import os
import stat
from dataclasses import dataclass
from pathlib import Path
from typing import Callable, Iterable

FILE_ATTRIBUTE_REPARSE_POINT = 0x400
CSIDL_APPDATA = 0x001A
CSIDL_LOCAL_APPDATA = 0x001C
CSIDL_COMMON_APPDATA = 0x0023
CSIDL_PROGRAM_FILES = 0x0026
CSIDL_PROFILE = 0x0028
CSIDL_PROGRAM_FILES_X86 = 0x002A
SHGFP_TYPE_CURRENT = 0

DirectoryProvider = Callable[[], Path | None]
KnownFolderProvider = Callable[[int], Path | None]


@dataclass(frozen=True, slots=True)
class WindowsTrustedPaths:
    windows: Path
    system: Path
    program_files: Path
    program_files_x86: Path | None
    local_app_data: Path
    app_data: Path
    program_data: Path
    user_profile: Path
    temp: Path

    @property
    def executable_roots(self) -> tuple[Path, ...]:
        roots = [self.system, self.program_files]
        if self.program_files_x86 is not None:
            roots.append(self.program_files_x86)
        return tuple(dict.fromkeys(roots))


def _win32_buffer_call(function_name: str) -> Path | None:
    if os.name != "nt":
        return None
    function = getattr(ctypes.windll.kernel32, function_name, None)
    if function is None:
        return None
    size = 32768
    buffer = ctypes.create_unicode_buffer(size)
    length = int(function(buffer, size))
    if length <= 0 or length >= size:
        return None
    value = buffer.value.strip()
    return Path(value) if value else None


def _windows_directory() -> Path | None:
    return _win32_buffer_call("GetWindowsDirectoryW")


def _system_directory() -> Path | None:
    return _win32_buffer_call("GetSystemDirectoryW")


def _temporary_directory() -> Path | None:
    if os.name != "nt":
        return None
    size = 32768
    buffer = ctypes.create_unicode_buffer(size)
    length = int(ctypes.windll.kernel32.GetTempPathW(size, buffer))
    if length <= 0 or length >= size:
        return None
    value = buffer.value.rstrip("\\/")
    return Path(value) if value else None


def _known_folder(csidl: int) -> Path | None:
    if os.name != "nt":
        return None
    buffer = ctypes.create_unicode_buffer(32768)
    result = int(
        ctypes.windll.shell32.SHGetFolderPathW(
            None,
            int(csidl),
            None,
            SHGFP_TYPE_CURRENT,
            buffer,
        )
    )
    if result != 0:
        return None
    value = buffer.value.strip()
    return Path(value) if value else None


def _normalized_path(value: Path) -> str:
    return os.path.normcase(os.path.normpath(str(value)))


def _same_path(left: Path, right: Path) -> bool:
    return _normalized_path(left) == _normalized_path(right)


def _absolute_directory(path: Path | None) -> Path | None:
    if path is None or not path.is_absolute():
        return None
    try:
        details = path.lstat()
    except OSError:
        return None
    attributes = int(getattr(details, "st_file_attributes", 0))
    if not stat.S_ISDIR(details.st_mode) or attributes & FILE_ATTRIBUTE_REPARSE_POINT:
        return None
    try:
        resolved = path.resolve(strict=True)
        resolved_details = resolved.lstat()
    except OSError:
        return None
    resolved_attributes = int(getattr(resolved_details, "st_file_attributes", 0))
    if (
        not resolved.is_absolute()
        or not stat.S_ISDIR(resolved_details.st_mode)
        or resolved_attributes & FILE_ATTRIBUTE_REPARSE_POINT
    ):
        return None
    return resolved


def load_windows_trusted_paths(
    *,
    windows_provider: DirectoryProvider = _windows_directory,
    system_provider: DirectoryProvider = _system_directory,
    temp_provider: DirectoryProvider = _temporary_directory,
    known_folder_provider: KnownFolderProvider = _known_folder,
) -> WindowsTrustedPaths | None:
    if os.name != "nt" and (
        windows_provider is _windows_directory
        or system_provider is _system_directory
        or temp_provider is _temporary_directory
        or known_folder_provider is _known_folder
    ):
        return None

    windows = _absolute_directory(windows_provider())
    system = _absolute_directory(system_provider())
    program_files = _absolute_directory(known_folder_provider(CSIDL_PROGRAM_FILES))
    program_files_x86 = _absolute_directory(known_folder_provider(CSIDL_PROGRAM_FILES_X86))
    local_app_data = _absolute_directory(known_folder_provider(CSIDL_LOCAL_APPDATA))
    app_data = _absolute_directory(known_folder_provider(CSIDL_APPDATA))
    program_data = _absolute_directory(known_folder_provider(CSIDL_COMMON_APPDATA))
    user_profile = _absolute_directory(known_folder_provider(CSIDL_PROFILE))
    temp = _absolute_directory(temp_provider())

    required = (
        windows,
        system,
        program_files,
        local_app_data,
        app_data,
        program_data,
        user_profile,
        temp,
    )
    if any(value is None for value in required):
        return None
    assert windows is not None
    assert system is not None
    assert program_files is not None
    assert local_app_data is not None
    assert app_data is not None
    assert program_data is not None
    assert user_profile is not None
    assert temp is not None
    return WindowsTrustedPaths(
        windows=windows,
        system=system,
        program_files=program_files,
        program_files_x86=program_files_x86,
        local_app_data=local_app_data,
        app_data=app_data,
        program_data=program_data,
        user_profile=user_profile,
        temp=temp,
    )


def is_regular_non_reparse_file(path: Path, *, executable: bool = False) -> bool:
    if not path.is_absolute():
        return False
    try:
        before = path.lstat()
    except OSError:
        return False
    attributes = int(getattr(before, "st_file_attributes", 0))
    if (
        stat.S_ISLNK(before.st_mode)
        or not stat.S_ISREG(before.st_mode)
        or attributes & FILE_ATTRIBUTE_REPARSE_POINT
    ):
        return False
    if executable:
        if os.name == "nt":
            if path.suffix.casefold() not in {".exe", ".com", ".bat", ".cmd"}:
                return False
        elif not os.access(path, os.X_OK):
            return False
    try:
        resolved = path.resolve(strict=True)
        after = resolved.lstat()
    except OSError:
        return False
    after_attributes = int(getattr(after, "st_file_attributes", 0))
    if (
        not _same_path(resolved, path)
        or stat.S_ISLNK(after.st_mode)
        or not stat.S_ISREG(after.st_mode)
        or after_attributes & FILE_ATTRIBUTE_REPARSE_POINT
    ):
        return False
    if before.st_ino and after.st_ino:
        return (before.st_dev, before.st_ino) == (after.st_dev, after.st_ino)
    return (
        before.st_dev,
        before.st_size,
        before.st_mtime_ns,
        before.st_ctime_ns,
    ) == (
        after.st_dev,
        after.st_size,
        after.st_mtime_ns,
        after.st_ctime_ns,
    )


def _inside(candidate: Path, root: Path) -> bool:
    candidate_value = _normalized_path(candidate)
    root_value = _normalized_path(root)
    try:
        common = os.path.commonpath((candidate_value, root_value))
    except ValueError:
        return False
    return common == root_value


def trusted_executable(
    candidates: Iterable[Path],
    approved_roots: Iterable[Path],
) -> str | None:
    roots = tuple(dict.fromkeys(approved_roots))
    if not roots:
        return None
    validated_roots: list[Path] = []
    for root in roots:
        validated = _absolute_directory(root)
        if validated is None or not _same_path(validated, root):
            return None
        validated_roots.append(validated)
    for candidate in candidates:
        if not candidate.is_absolute():
            continue
        if not is_regular_non_reparse_file(candidate, executable=True):
            continue
        try:
            normalized = candidate.resolve(strict=True)
        except OSError:
            continue
        if not any(_inside(normalized, root) for root in validated_roots):
            continue
        return str(normalized)
    return None


def trusted_windows_environment(
    executable: Path,
    paths: WindowsTrustedPaths,
    *,
    deny_network_updates: bool = False,
) -> dict[str, str]:
    roots = paths.executable_roots
    if not any(_inside(executable, root) for root in roots):
        raise ValueError("executable is outside trusted Windows roots")
    path_value = os.pathsep.join(
        dict.fromkeys(
            str(item)
            for item in (
                executable.parent,
                paths.system,
                paths.system / "WindowsPowerShell" / "v1.0",
                paths.windows,
            )
            if item.is_absolute()
        )
    )
    env = {
        "PATH": path_value,
        "PATHEXT": ".COM;.EXE;.BAT;.CMD",
        "SYSTEMROOT": str(paths.windows),
        "WINDIR": str(paths.windows),
        "TEMP": str(paths.temp),
        "TMP": str(paths.temp),
        "LOCALAPPDATA": str(paths.local_app_data),
        "APPDATA": str(paths.app_data),
        "PROGRAMDATA": str(paths.program_data),
        "USERPROFILE": str(paths.user_profile),
        "HOMEDRIVE": paths.user_profile.drive,
        "HOMEPATH": str(paths.user_profile)[len(paths.user_profile.drive) :],
    }
    if deny_network_updates:
        env["NO_PROXY"] = "*"
        env["no_proxy"] = "*"
    return {key: value for key, value in env.items() if value}
