"""Owner-only files and directories for stored findings, state and audit.

Files are 0600 and directories 0700 whatever the umask: `mkdir`'s mode and
`os.open`'s mode are masked by it, so each is set again explicitly.
"""

from __future__ import annotations

import contextlib
import logging
import os
import stat
import tempfile
from pathlib import Path

FILE_MODE = 0o600
DIR_MODE = 0o700

log = logging.getLogger("forgd_verdict.fsmode")
# The warnings `_warn_once` has logged in this process.
_warned: set[str] = set()


def _warn_once(message: str, exc: OSError) -> None:
    """Log `message` the first time this process sees it, and not again."""
    if message in _warned:
        return
    _warned.add(message)
    log.warning(message, extra={"fields": {"error": type(exc).__name__}})


def private_dir(path: str | os.PathLike[str]) -> Path:
    """`path` as a directory, creating each missing component 0700.

    A directory that already exists keeps its mode.
    """
    path = Path(path)
    missing: list[Path] = []
    current = path
    while not current.exists():
        missing.append(current)
        if current.parent == current:
            break
        current = current.parent
    for directory in reversed(missing):
        try:
            directory.mkdir(mode=DIR_MODE)
        except FileExistsError:
            continue
        try:
            os.chmod(directory, DIR_MODE)
        except OSError as exc:
            _warn_once("a store directory could not be made owner-only", exc)
    if not path.is_dir():
        raise NotADirectoryError(str(path))
    return path


def write_private(path: str | os.PathLike[str], data: bytes) -> None:
    """Replace `path` with `data`, atomically, as a 0600 file.

    The bytes go to a uniquely named temporary file in the same directory,
    which is flushed to disk and renamed over `path`. Two writers of one
    path each rename a whole file, so the last rename wins and neither
    leaves a torn one.
    """
    path = Path(path)
    private_dir(path.parent)
    fd, tmp = tempfile.mkstemp(dir=path.parent, prefix=f".{path.name}.", suffix=".tmp")
    try:
        _owner_only(fd)
        with os.fdopen(fd, "wb") as fh:
            fh.write(data)
            fh.flush()
            os.fsync(fh.fileno())
        os.replace(tmp, path)
    except BaseException:
        with contextlib.suppress(FileNotFoundError):
            os.unlink(tmp)
        raise


def create_private(path: str | os.PathLike[str], data: bytes) -> None:
    """Write `data` to `path` as a new 0600 file. FileExistsError if
    `path` exists. Readers never see it partly written: the bytes are
    written and synced under a temporary name, then hard-linked to
    `path`, which fails if `path` exists."""
    path = Path(path)
    private_dir(path.parent)
    fd, tmp = tempfile.mkstemp(dir=path.parent, prefix=f".{path.name}.", suffix=".tmp")
    try:
        _owner_only(fd)
        with os.fdopen(fd, "wb") as fh:
            fh.write(data)
            fh.flush()
            os.fsync(fh.fileno())
        os.link(tmp, path)
    finally:
        with contextlib.suppress(FileNotFoundError):
            os.unlink(tmp)


def open_private(path: str | os.PathLike[str], flags: int) -> int:
    """`os.open(path, flags | O_CREAT, 0600)`, with a new file's mode set
    again in case the umask masked it, and its directory made 0700."""
    path = Path(path)
    private_dir(path.parent)
    fd = os.open(path, flags | os.O_CREAT, FILE_MODE)
    _owner_only(fd)
    return fd


def _owner_only(fd: int) -> None:
    """Make the open file 0600 if it is not. A filesystem that refuses the
    change is logged, once per process, and the write goes ahead."""
    try:
        if stat.S_IMODE(os.fstat(fd).st_mode) != FILE_MODE:
            os.fchmod(fd, FILE_MODE)
    except OSError as exc:
        _warn_once("a stored file could not be made owner-only", exc)


def tighten_tree(root: str | os.PathLike[str], children: tuple[str, ...]) -> int:
    """Make `root` 0700, and every directory under each of `children` 0700
    and every regular file there 0600. Returns how many entries could not
    be changed. Nothing else under `root` is touched.

    Symlinks are not followed: a child that is a link is skipped, the walk
    does not descend through one, and each entry is opened with O_NOFOLLOW
    and changed through its file descriptor, so a link swapped in after
    the walk saw the entry fails to open instead of being followed.
    Anything that is neither a directory nor a regular file is left alone.
    """
    failed = _tighten(os.fspath(root), DIR_MODE)
    for child in children:
        top = os.path.join(root, child)
        if not os.path.isdir(top) or os.path.islink(top):
            continue
        for dirpath, _dirnames, filenames in os.walk(top, followlinks=False):
            failed += _tighten(dirpath, DIR_MODE)
            for name in filenames:
                failed += _tighten(os.path.join(dirpath, name), FILE_MODE)
    if failed:
        log.warning("store entries could not be made owner-only",
                    extra={"fields": {"count": failed}})
    return failed


def _tighten(path: str, mode: int) -> int:
    try:
        st = os.lstat(path)
    except FileNotFoundError:
        return 0
    want_dir = mode == DIR_MODE
    if stat.S_ISLNK(st.st_mode) or not (
            stat.S_ISDIR(st.st_mode) if want_dir else stat.S_ISREG(st.st_mode)):
        return 0
    if stat.S_IMODE(st.st_mode) == mode:
        return 0
    flags = os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK
    if want_dir:
        flags |= os.O_DIRECTORY
    try:
        fd = os.open(path, flags)
    except FileNotFoundError:
        return 0
    except OSError:
        return 1
    try:
        st = os.fstat(fd)
        if (stat.S_ISDIR(st.st_mode) if want_dir else stat.S_ISREG(st.st_mode)):
            os.fchmod(fd, mode)
        return 0
    except OSError:
        return 1
    finally:
        os.close(fd)
