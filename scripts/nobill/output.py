"""Where the reports go, and how they are written.

Every destination is checked before anything is written: its directory and, when
something already exists at the path, what that entry resolves to (through
symlinks) must lie outside the scanned project. Each file is then written to a
fresh temporary file in the same directory and moved over the destination with
an atomic replace, which swaps the directory entry and never writes through an
existing symlink or hard link at the destination. No two outputs, and no output
and an input, may name the same file: names are compared case-folded and
Unicode-normalised (case-insensitive file systems), entries that already exist
are compared by identity, and identity is checked again at write time.
"""

from __future__ import annotations

import itertools
import os
import tempfile
import unicodedata
from pathlib import Path


class OutputError(Exception):
    pass


def inside(child: Path, parent: Path) -> bool:
    try:
        child.relative_to(parent)
        return True
    except ValueError:
        return False


def destination(path: Path) -> Path:
    """The absolute destination with its directory resolved but the final name kept:
    resolving the name itself would follow a symlink that is about to be replaced."""
    path = Path(path).expanduser()
    return path.parent.resolve() / path.name


def _same_entry(a: Path, b: Path) -> bool:
    """Do two paths reach the same directory entry or inode (without following a final symlink)?"""
    try:
        return os.path.samestat(os.lstat(a), os.lstat(b))
    except OSError:
        return False


def _check_distinct(paths: list[Path]) -> None:
    seen: dict[str, Path] = {}
    for p in paths:
        key = unicodedata.normalize("NFC", str(p)).casefold()
        if key in seen:
            raise OutputError(f"{p} and {seen[key]} would be the same file (names differ only in case); "
                              "choose another --out")
        seen[key] = p
    for a, b in itertools.combinations(paths, 2):
        if _same_entry(a, b):
            raise OutputError(f"{a} and {b} are the same file; choose another --out")


def check_destinations(dests: list[Path], project: Path | None, inputs: list[Path] = ()) -> list[Path]:
    """Validate every destination before any is written; return them as written."""
    out = []
    for d in dests:
        d = destination(d)
        if project is not None and inside(d.parent, project):
            raise OutputError(f"{d} is inside the scanned project; choose an output outside it")
        if os.path.lexists(d):
            if d.is_dir() and not d.is_symlink():
                raise OutputError(f"{d} is a directory")
            real = Path(os.path.realpath(d))
            if project is not None and inside(real, project):
                raise OutputError(f"{d} links into the scanned project ({real}); remove it or choose another output")
        out.append(d)
    _check_distinct(out + [Path(i) for i in inputs])
    return out


def write_all(items: list[tuple[Path, str]]) -> None:
    """Write each (destination, text), refusing one that turns out to be a file already written."""
    written: list[Path] = []
    for dest, text in items:
        for w in written:
            if _same_entry(w, dest):
                raise OutputError(f"{dest} and {w} are the same file; stopped before overwriting it")
        write_atomic(dest, text)
        written.append(dest)


def _umask() -> int:
    old = os.umask(0)
    os.umask(old)
    return old


def write_atomic(dest: Path, text: str) -> None:
    """Write text to dest through a new temporary file and an atomic replace."""
    fd, tmp = tempfile.mkstemp(dir=dest.parent, prefix=f".{dest.name}.", suffix=".tmp")
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as fh:
            fh.write(text)
        os.chmod(tmp, 0o666 & ~_umask())  # the mode a plain write would give, not mkstemp's 0600
        os.replace(tmp, dest)
    except BaseException:
        try:
            os.unlink(tmp)
        except OSError:
            pass
        raise
