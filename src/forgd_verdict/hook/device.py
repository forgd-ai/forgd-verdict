"""A salt that belongs to one laptop.

The deployment's hash salt covers the three server-side writers and deliberately exempts the hook:
a deployment secret copied to every developer machine leaks with the first
lost one. Without a salt of its own the hook would hash with an empty one
-- EMPTY IS THE WORST AVAILABLE SALT -- and spool and ship those hashes
unchanged into the shared store, so a findings export containing adapter-2
rows could be swept back to the matched secret by brute force. An SSN is
about a billion guesses; a card number fewer.

A per-device random salt keeps both properties:

  * the deployment secret never reaches a laptop;
  * adapter 2's hashes stay in their own namespace, apart from the server's;
  * but they are not a bare SHA-256, so an export cannot be swept
    back to the value;
  * a lost laptop leaks one laptop's salt, for its own findings only.

The cost is that two laptops finding the same key produce different
hashes, so distinct-value counts drift. That is ALREADY true between
laptop and server, and it is why records carry a namespace marker: a
reader can then say "these are not comparable with those" instead of
silently unioning them.
"""

from __future__ import annotations

import contextlib
import hashlib
import os
import secrets
import stat
from pathlib import Path

from ..fsmode import private_dir

# 32 bytes. The salt only has to be unguessable, and a longer one buys
# nothing against a brute force over a value space of a billion.
_SALT_BYTES = 32
_FILENAME = "device-salt"


def device_salt_path(root: str | os.PathLike[str] | None = None) -> Path:
    """Where the salt lives: beside the spool, not in the repository.

    Same reasoning as the spool root -- a file inside the project directory
    lands in whatever repository the developer happened to be in, and gets
    committed.
    """
    if root is not None:
        return Path(root).expanduser() / _FILENAME
    from ..store.spool import default_spool_root

    return Path(default_spool_root()).expanduser().parent / _FILENAME


def _read_salt(path: Path) -> str | None:
    """The stored salt, or None when the file is missing, empty or malformed.

    Reads at most 2 KiB from a regular file, opened without blocking or
    following a symlink. The state directory can be chosen from the
    environment, so the file is not trusted to be a salt: a FIFO there
    would block the hook until Claude Code killed it.
    """
    flags = os.O_RDONLY | getattr(os, "O_NONBLOCK", 0) | getattr(os, "O_NOFOLLOW", 0)
    fd = os.open(path, flags)
    try:
        if not stat.S_ISREG(os.fstat(fd).st_mode):
            return None
        raw = os.read(fd, 2048)
    finally:
        os.close(fd)
    try:
        text = raw.decode("ascii").strip()
    except UnicodeDecodeError:
        return None
    if len(text) == 2 * _SALT_BYTES and all(c in "0123456789abcdef" for c in text):
        return text
    return None


def device_salt(root: str | os.PathLike[str] | None = None) -> str:
    """This device's salt; a process-lifetime one on any failure."""
    try:
        return _device_salt(root)
    except Exception:  # noqa: BLE001 - see _device_salt: never raises
        return secrets.token_hex(_SALT_BYTES)


def _device_salt(root: str | os.PathLike[str] | None = None) -> str:
    """This device's salt, generated on first use.

    Never raises. A hook that cannot persist a salt must still run and must
    still refuse to hash unsalted, so an unwritable state directory falls
    back to a PROCESS-lifetime salt: the hashes are then uncomparable even
    with this device's earlier ones, which is worse for counting and no
    worse for exposure. Failing the developer's action instead would be the
    wrong trade -- the hook sits in front of what they are trying to do.
    """
    path = device_salt_path(root)
    try:
        existing = _read_salt(path)
        if existing:
            return existing
        if path.stat().st_size:
            # Malformed, not empty: left in place, and this process uses its
            # own salt.
            return secrets.token_hex(_SALT_BYTES)
        # Present but EMPTY -- a truncated write or a full disk. The
        # O_EXCL create below then fails, the handler re-reads the same
        # empty file, and the fallback is a process-lifetime salt. Nothing
        # ever rewrote the file, so every hook invocation got its own
        # namespace forever and each laptop's records became mutually
        # incomparable.
        #
        # Removed so the create can succeed. O_EXCL still protects against
        # a concurrent process that is mid-write with a real salt: the
        # loser re-reads and adopts the winner's.
        with contextlib.suppress(OSError):
            path.unlink()
    except OSError:
        pass

    salt = secrets.token_hex(_SALT_BYTES)
    try:
        private_dir(path.parent)
        # 0600 and O_EXCL: a concurrent hook process must not overwrite a
        # salt already in use, or records written either side of the race
        # would be hashed differently with nothing recording that.
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        try:
            os.write(fd, (salt + "\n").encode("utf-8"))
        finally:
            os.close(fd)
    except FileExistsError:
        try:
            return _read_salt(path) or salt
        except OSError:
            return salt
    except IsADirectoryError:
        return salt
    except OSError:
        return salt
    return salt


def device_id(root: str | os.PathLike[str] | None = None) -> str:
    """This device's id for the intake's device header: the salt namespace
    its spooled records carry, which names the device and not the salt."""
    return salt_namespace(device_salt(root))


def salt_namespace(salt: str) -> str:
    """A stable id for the salt that is NOT the salt.

    Written onto every record so a reader can group comparable hashes
    without being handed the means to verify one. Publishing the salt here
    would undo the whole point: an export carrying both the hashes and the
    salt is an export carrying the values.
    """
    if not salt:
        return ""
    return "d" + hashlib.sha256(salt.encode("utf-8")).hexdigest()[:12]


# -- the provisioned salt -------------------------------------------------

SETTING = "hook.device_salt_path"


def _euid() -> int | None:
    return os.geteuid() if hasattr(os, "geteuid") else None


def _warn(message: str) -> None:
    import sys

    print(f"forgd-verdict: {message}", file=sys.stderr)


def provisioned_salt(path: object) -> tuple[str | None, str | None]:
    """`(salt, None)` from the MDM-provisioned file at `path`, or
    `(None, why)` when it is not fit to be one.

    Fit is: an absolute path to a regular file, not a symlink, holding a
    64-hex salt, that this user cannot rewrite. On POSIX that means no
    group or other write bit on the file or its directory, since a
    writable directory lets the file be replaced, and for any user but
    root: not owned by this user and neither writable by them. Elsewhere
    the file's ACL is the provisioner's to set and is not checked here.
    """
    if not isinstance(path, str) or not os.path.isabs(path):
        return None, f"{SETTING} {path!r} is not an absolute path"
    p = Path(path)
    try:
        st = os.lstat(p)
    except OSError as exc:
        return None, f"{SETTING} {path} cannot be read ({type(exc).__name__})"
    if stat.S_ISLNK(st.st_mode) or not stat.S_ISREG(st.st_mode):
        return None, f"{SETTING} {path} is not a regular file"
    if os.name == "posix":
        if st.st_mode & (stat.S_IWGRP | stat.S_IWOTH):
            return None, f"{SETTING} {path} is writable by its group or by others"
        try:
            parent = os.stat(p.parent)
        except OSError as exc:
            return None, f"{SETTING} {path}'s directory cannot be read ({type(exc).__name__})"
        if parent.st_mode & (stat.S_IWGRP | stat.S_IWOTH):
            return None, (f"{SETTING} {path} is in a directory its group or others can "
                          "write, so the file can be replaced")
        # Root owns the file and can write anything, so for an inventory
        # script running as root only the mode bits above say anything.
        euid = _euid()
        if euid != 0:
            if st.st_uid == euid:
                return None, f"{SETTING} {path} is owned by this user, who can rewrite it"
            if os.access(p, os.W_OK):
                return None, f"{SETTING} {path} is writable by this user"
            if os.access(p.parent, os.W_OK):
                return None, (f"{SETTING} {path} is in a directory this user can "
                              "write, so the file can be replaced")
    try:
        salt = _read_salt(p)
    except OSError as exc:
        return None, f"{SETTING} {path} cannot be read ({type(exc).__name__})"
    if not salt:
        return None, f"{SETTING} {path} does not hold a 64-hex-character salt"
    return salt, None


def _configured(policy: object) -> object:
    hook = getattr(policy, "hook", None) or {}
    return hook.get("device_salt_path")


def hook_salt(policy: object) -> str:
    """The salt the hook hashes with: the provisioned one when
    `hook.device_salt_path` is set and fit, a process-lifetime one when it
    is set and not, and the per-user salt when it is unset."""
    from .trust import salt_root

    configured = _configured(policy)
    if configured is None:
        return device_salt(salt_root(policy))
    salt, _ = provisioned_salt(configured)
    return salt or secrets.token_hex(_SALT_BYTES)


def hook_device_id(policy: object, root: str | os.PathLike[str] | None = None) -> str | None:
    """The id the hook sends as its device header, or None.

    From the provisioned salt when `hook.device_salt_path` is set. When it
    is set and not fit, None, said on stderr: a laptop that can change its
    own id defeats denying it, so no id is sent rather than the per-user
    one. When it is unset, the per-user salt under `root` (the spool's
    parent by default), said on stderr.
    """
    from .trust import salt_root

    configured = _configured(policy)
    if configured is not None:
        salt, why = provisioned_salt(configured)
        if salt is None:
            _warn(f"{why}; sending no device id")
            return None
        return salt_namespace(salt)
    root = salt_root(policy) if root is None else root
    _warn(f"{SETTING} is not set; the device id comes from the per-user salt in "
          f"{device_salt_path(root)}, which this user can delete to get a new id")
    return device_id(root)
