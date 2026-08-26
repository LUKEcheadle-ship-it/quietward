from __future__ import annotations

import os
import stat
import subprocess
import sys
from pathlib import Path, PurePosixPath
from typing import Iterable

ROOT = Path(__file__).resolve().parents[1]
SRC = ROOT / "src"
if str(SRC) not in sys.path:
    sys.path.insert(0, str(SRC))

from quietward.windows_trust import (  # noqa: E402
    WindowsTrustedPaths,
    load_windows_trusted_paths,
    trusted_executable,
    trusted_windows_environment,
)

FILE_ATTRIBUTE_REPARSE_POINT = 0x400
READ_CHUNK_BYTES = 1024 * 1024
_POSIX_GIT_CANDIDATES = (
    Path("/usr/bin/git"), Path("/usr/local/bin/git"), Path("/bin/git"),
)
_RELEASE_TREE_MARKERS = (
    Path("pyproject.toml"),
    Path("src/quietward"),
    Path("scripts/build_release_bundle.py"),
)


def _is_excluded(relative: Path, excluded_parts: set[str]) -> bool:
    return any(part in excluded_parts for part in relative.parts)


def is_link_like(path: Path) -> bool:
    try:
        details = path.lstat()
    except OSError:
        return True
    if stat.S_ISLNK(details.st_mode):
        return True
    return bool(int(getattr(details, "st_file_attributes", 0)) & FILE_ATTRIBUTE_REPARSE_POINT)


def _same_file(left: os.stat_result, right: os.stat_result) -> bool:
    if left.st_ino and right.st_ino:
        return (left.st_dev, left.st_ino) == (right.st_dev, right.st_ino)
    return (left.st_dev,left.st_size,left.st_mtime_ns,left.st_ctime_ns) == (right.st_dev,right.st_size,right.st_mtime_ns,right.st_ctime_ns)


def _regular_non_link_file(path: Path, *, executable: bool = False) -> bool:
    try:
        details = path.lstat()
    except OSError:
        return False
    attributes = int(getattr(details, "st_file_attributes", 0))
    if stat.S_ISLNK(details.st_mode) or not stat.S_ISREG(details.st_mode) or attributes & FILE_ATTRIBUTE_REPARSE_POINT:
        return False
    return not executable or os.access(path, os.X_OK)


def read_regular_bytes(path: Path, *, max_bytes: int | None = None) -> bytes:
    try:
        before = path.lstat()
    except OSError as exc:
        raise ValueError(f"cannot inspect release file {path}: {exc}") from exc
    attributes = int(getattr(before, "st_file_attributes", 0))
    if stat.S_ISLNK(before.st_mode) or attributes & FILE_ATTRIBUTE_REPARSE_POINT:
        raise ValueError(f"link-like release file is forbidden: {path}")
    if not stat.S_ISREG(before.st_mode):
        raise ValueError(f"non-regular release file is forbidden: {path}")
    if int(getattr(before, "st_nlink", 1)) != 1:
        raise ValueError(f"hard-linked release file is forbidden: {path}")
    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_BINARY", 0) | getattr(os, "O_NOFOLLOW", 0)
    try:
        descriptor = os.open(path, flags)
    except OSError as exc:
        raise ValueError(f"cannot open release file safely {path}: {exc}") from exc
    try:
        opened = os.fstat(descriptor)
        opened_attributes = int(getattr(opened, "st_file_attributes", 0))
        if not stat.S_ISREG(opened.st_mode) or opened_attributes & FILE_ATTRIBUTE_REPARSE_POINT or not _same_file(before, opened):
            raise ValueError(f"release file changed during validation: {path}")
        if int(getattr(opened, "st_nlink", 1)) != 1:
            raise ValueError(f"hard-linked release file is forbidden: {path}")
        chunks: list[bytes] = []
        total = 0
        while True:
            chunk = os.read(descriptor, READ_CHUNK_BYTES)
            if not chunk:
                break
            chunks.append(chunk)
            total += len(chunk)
            if max_bytes is not None and total > max_bytes:
                raise ValueError(f"release file exceeds {max_bytes} bytes: {path}")
    finally:
        os.close(descriptor)
    try:
        after = path.lstat()
    except OSError as exc:
        raise ValueError(f"release file disappeared during validation: {path}: {exc}") from exc
    if not _same_file(before, after) or is_link_like(path):
        raise ValueError(f"release file changed during validation: {path}")
    return b"".join(chunks)


def walk_regular_files(root: Path, excluded_parts: set[str]) -> tuple[list[Path], list[str]]:
    root = root.resolve()
    files: list[Path] = []
    blockers: list[str] = []
    pending = [root]
    while pending:
        directory = pending.pop()
        try:
            entries: Iterable[os.DirEntry[str]] = os.scandir(directory)
            with entries as values:  # type: ignore[attr-defined]
                ordered = sorted(values, key=lambda item: item.name.casefold())
        except OSError as exc:
            blockers.append(f"cannot inspect release path {directory}: {exc}")
            continue
        for entry in ordered:
            path = Path(entry.path)
            try:
                relative = path.relative_to(root)
            except ValueError:
                blockers.append(f"release path escaped checkout: {path}")
                continue
            if _is_excluded(relative, excluded_parts):
                continue
            if is_link_like(path):
                blockers.append(f"link-like release path is forbidden: {relative.as_posix()}")
                continue
            try:
                if entry.is_dir(follow_symlinks=False):
                    pending.append(path)
                elif entry.is_file(follow_symlinks=False):
                    details = path.lstat()
                    if int(getattr(details, "st_nlink", 1)) != 1:
                        blockers.append(f"hard-linked release path is forbidden: {relative.as_posix()}")
                    else:
                        files.append(relative)
                else:
                    blockers.append(f"non-regular release path is forbidden: {relative.as_posix()}")
            except OSError as exc:
                blockers.append(f"cannot classify release path {relative.as_posix()}: {exc}")
    return sorted(files, key=lambda item: item.as_posix()), blockers


def _decode_git_paths(payload: bytes) -> list[Path]:
    values: list[Path] = []
    for raw in payload.split(b"\0"):
        if not raw:
            continue
        text = os.fsdecode(raw).replace("\\", "/")
        pure = PurePosixPath(text)
        if pure.is_absolute() or ".." in pure.parts or not pure.parts:
            raise ValueError(f"unsafe path returned by git: {text}")
        values.append(Path(*pure.parts))
    return values


def _windows_git_candidates(paths: WindowsTrustedPaths | None = None) -> tuple[Path, ...]:
    trusted = paths if paths is not None else load_windows_trusted_paths()
    if trusted is None:
        return ()
    roots = tuple(root for root in (trusted.program_files, trusted.program_files_x86) if root is not None)
    return tuple(candidate for root in roots for candidate in (root / "Git" / "cmd" / "git.exe", root / "Git" / "bin" / "git.exe"))


def resolve_trusted_git() -> Path | None:
    if os.name == "nt":
        paths = load_windows_trusted_paths()
        if paths is None:
            return None
        resolved = trusted_executable(_windows_git_candidates(paths), paths.executable_roots)
        # Path() consults os.name at call time. Tests deliberately emulate the
        # Windows branch on POSIX, so retain the native concrete path class that
        # was selected when this module loaded.
        return type(ROOT)(resolved) if resolved is not None else None
    for candidate in _POSIX_GIT_CANDIDATES:
        if _regular_non_link_file(candidate, executable=True):
            return candidate.resolve(strict=True)
    return None


def _git_environment(git: Path) -> dict[str, str]:
    if os.name == "nt":
        paths = load_windows_trusted_paths()
        if paths is None:
            raise ValueError("trusted Windows directories are unavailable")
        env = trusted_windows_environment(git, paths, deny_network_updates=True)
        env.update({"HOME": str(paths.user_profile), "COMSPEC": str(paths.system / "cmd.exe")})
    else:
        env = {"PATH": str(git.parent), "HOME": "/nonexistent"}
    env.update({
        "GIT_CONFIG_NOSYSTEM": "1",
        "GIT_CONFIG_GLOBAL": os.devnull,
        "GIT_TERMINAL_PROMPT": "0",
        "GIT_OPTIONAL_LOCKS": "0",
        "LC_ALL": "C",
        "LANG": "C",
    })
    return {key: value for key, value in env.items() if value}


def _run_git(root: Path, git: Path, arguments: list[str]) -> subprocess.CompletedProcess[bytes]:
    return subprocess.run(
        [str(git), "-c", "core.fsmonitor=false", "-c", "core.untrackedCache=false", "-C", str(root), *arguments],
        check=False, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
        stdin=subprocess.DEVNULL, shell=False, env=_git_environment(git),
    )


def _looks_like_complete_release_tree(root: Path) -> bool:
    return all((root / marker).exists() for marker in _RELEASE_TREE_MARKERS)


def release_regular_files(root: Path, excluded_parts: set[str]) -> tuple[list[Path], list[str]]:
    root = root.resolve()
    scanned, blockers = walk_regular_files(root, excluded_parts)
    git_marker = root / ".git"
    if not git_marker.exists():
        if _looks_like_complete_release_tree(root):
            blockers.append("complete release root must be a committed Git worktree")
            return [], blockers
        return scanned, blockers
    if is_link_like(git_marker):
        blockers.append("release checkout .git marker may not be a link or reparse point")
        return [], blockers
    git = resolve_trusted_git()
    if git is None:
        blockers.append("Git from a trusted system installation is required to build or audit a release checkout")
        return [], blockers
    worktree = _run_git(root, git, ["rev-parse", "--is-inside-work-tree"])
    if worktree.returncode != 0 or worktree.stdout.strip() != b"true":
        blockers.append("release root is not a valid Git worktree")
        return [], blockers
    head = _run_git(root, git, ["rev-parse", "--verify", "HEAD^{commit}"])
    if head.returncode != 0:
        blockers.append("release checkout does not have a valid committed HEAD")
        return [], blockers
    dirty = _run_git(root, git, ["diff", "--quiet", "--no-ext-diff", "--no-textconv", "HEAD", "--"])
    if dirty.returncode == 1:
        blockers.append("release checkout contains modified or staged tracked files")
    elif dirty.returncode != 0:
        detail = dirty.stderr.decode("utf-8", errors="replace").strip()
        blockers.append(f"cannot verify clean release checkout: {detail or dirty.returncode}")
    tracked_result = _run_git(root, git, ["ls-files", "-z", "--cached"])
    if tracked_result.returncode != 0:
        detail = tracked_result.stderr.decode("utf-8", errors="replace").strip()
        blockers.append(f"cannot enumerate tracked release files: {detail or tracked_result.returncode}")
        return [], blockers
    try:
        tracked = {path for path in _decode_git_paths(tracked_result.stdout) if not _is_excluded(path, excluded_parts)}
    except ValueError as exc:
        blockers.append(str(exc))
        return [], blockers
    scanned_set = set(scanned)
    for path in sorted(scanned_set - tracked, key=lambda item: item.as_posix()):
        blockers.append(f"untracked or ignored release path is forbidden: {path.as_posix()}")
    for path in sorted(tracked - scanned_set, key=lambda item: item.as_posix()):
        blockers.append(f"tracked release path is missing or not a regular file: {path.as_posix()}")
    return sorted(tracked & scanned_set, key=lambda item: item.as_posix()), blockers
