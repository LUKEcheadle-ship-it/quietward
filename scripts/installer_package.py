#!/usr/bin/env python3
"""Isolated installer helpers; never start services or alter configuration/state.

Directory replacement uses same-volume renames and rollback on caught failures.
It is not a crash-atomic exchange: an interrupted transaction leaves a lock and
possibly .quietward-package-backup for explicit inspection/recovery. A subsequent
install refuses to overwrite either artifact.
"""
from __future__ import annotations

import argparse
import os
from pathlib import Path
import shutil
import stat
import subprocess
import tempfile
from typing import Callable


def reject_links(path: Path) -> None:
    """Reject symlinks and Windows reparse points, including ancestor junctions."""
    for item in (path, *path.parents):
        info = item.lstat()
        if stat.S_ISLNK(info.st_mode) or getattr(info, 'st_file_attributes', 0) & 0x400:
            raise ValueError('Installer paths must not traverse links or reparse points')


def validate_process(venv: Path, process: Path) -> None:
    if not venv.is_absolute() or not process.is_absolute():
        raise ValueError('Process and virtual environment paths must be absolute')
    reject_links(venv / 'Scripts')
    reject_links(process)
    expected = (venv / 'Scripts').resolve(strict=True)
    actual = process.resolve(strict=True)
    if actual.parent != expected or actual.name.casefold() != 'python.exe' or not actual.is_file():
        raise ValueError('Process must be the installed virtual environment python.exe')


def replace_package(source: Path, destination: Path, validate: Callable[[Path], None]) -> None:
    source = source.absolute()
    destination = destination.absolute()
    reject_links(source)
    reject_links(destination.parent)
    source = source.resolve(strict=True)
    destination = destination.parent.resolve(strict=True) / destination.name
    if destination.name != 'quietward' or not source.is_dir():
        raise ValueError('Expected a QuietWard source directory and package destination')
    if source == destination or source.is_relative_to(destination) or destination.is_relative_to(source):
        raise ValueError('Source and destination must not overlap')
    for item in source.rglob('*'):
        reject_links(item)
        if not item.is_file() and not item.is_dir():
            raise ValueError('Source contains a non-regular entry')
    if os.path.lexists(destination):
        reject_links(destination)
        if not destination.is_dir():
            raise ValueError('Installed package must be a directory')
    backup = destination.with_name('.quietward-package-backup')
    lock = destination.with_name('.quietward-package-lock')
    if os.path.lexists(backup):
        raise ValueError('Preserved package backup requires inspection before retry')
    lock.mkdir()  # Exclusive; never remove another transaction's lock.
    work: Path | None = None
    moved_old = False
    promoted = False
    restored = False
    try:
        work = Path(tempfile.mkdtemp(prefix='.quietward-package-stage-', dir=destination.parent))
        staged = work / 'quietward'
        shutil.copytree(source, staged, ignore=shutil.ignore_patterns('__pycache__', '*.pyc'))
        if destination.exists():
            destination.rename(backup)
            moved_old = True
        staged.rename(destination)
        promoted = True
        validate(destination)
    except BaseException:
        # Rename failed candidates out of the way; do not recursively remove the
        # live path. If restoration fails, preserve backup, staging and lock.
        if promoted:
            destination.rename(work / 'failed-package')
        if moved_old:
            backup.rename(destination)
        restored = True
        raise
    else:
        if moved_old:
            shutil.rmtree(backup)
        restored = True
    finally:
        if restored or not moved_old and not promoted:
            if work is not None:
                shutil.rmtree(work)
            lock.rmdir()


def validate_installed(python: Path, destination: Path) -> None:
    code = (
        'import pathlib,runpy,sys,quietward; '
        'assert pathlib.Path(quietward.__file__).resolve().parent == pathlib.Path(sys.argv[1]).resolve(); '
        'sys.argv=["quietward","--help"]; runpy.run_module("quietward",run_name="__main__")'
    )
    subprocess.run([str(python), '-I', '-c', code, str(destination)],
                   cwd=destination.parent, check=True, timeout=30)


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest='command', required=True)
    process = commands.add_parser('validate-process')
    process.add_argument('--venv', type=Path, required=True)
    process.add_argument('--process', type=Path, required=True)
    package = commands.add_parser('replace-package')
    package.add_argument('--source', type=Path, required=True)
    package.add_argument('--destination', type=Path, required=True)
    package.add_argument('--python', type=Path, required=True)
    args = parser.parse_args()
    if args.command == 'validate-process':
        validate_process(args.venv, args.process)
    else:
        replace_package(args.source, args.destination, lambda path: validate_installed(args.python, path))


if __name__ == '__main__':
    main()
