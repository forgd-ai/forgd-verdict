"""Where the hook keeps its state, chosen without the project's environment.

A Claude Code project's `.claude/settings.json` `env` block reaches the
hook's environment. Unless the policy sets `hook.project_overrides: true`,
the spool and the device salt are therefore placed from the password
database and the policy file, and `FORGD_VERDICT_SPOOL`, `XDG_STATE_HOME`
and `HOME` are not read. On Windows the home directory still comes from
`USERPROFILE`. The user a decision is attributed to never comes from the
environment.
"""

from __future__ import annotations

import os
import sys
from pathlib import Path
from typing import Any

from ..store.spool import default_spool_root


def overrides(policy: Any) -> bool:
    """True when the policy lets the project's environment configure the hook."""
    hook = getattr(policy, "hook", None) or {}
    return hook.get("project_overrides") is True


def passwd_home() -> Path:
    """This user's home directory from the password database on POSIX, else `~`."""
    if os.name == "posix":
        import pwd

        try:
            return Path(pwd.getpwuid(os.getuid()).pw_dir)
        except KeyError:
            pass
    return Path(os.path.expanduser("~"))


def home() -> Path:
    return passwd_home()


def user_name() -> str:
    """This user's login name: the password database on POSIX, GetUserNameW
    through `os.getlogin` on Windows, never `LOGNAME`, `USER` or `USERNAME`.
    `unknown` when neither answers."""
    try:
        if os.name == "posix":
            import pwd

            return pwd.getpwuid(os.getuid()).pw_name
        return os.getlogin()
    except (KeyError, OSError):
        return "unknown"


def _trusted_default() -> str:
    return str(home() / ".local" / "state" / "forgd-verdict" / "spool")


def spool_root(policy: Any) -> str:
    """The spool directory: `hook.spool` when it is absolute, else
    `~/.local/state/forgd-verdict/spool` under `home()`.

    With project overrides on, the environment-aware `default_spool_root`
    is the fallback, as before. A leading `~` in `hook.spool` is `home()`.
    """
    configured = (getattr(policy, "hook", None) or {}).get("spool")
    if overrides(policy):
        return str(configured) if configured else default_spool_root()
    if not configured:
        return _trusted_default()
    value = str(configured)
    if value == "~" or value.startswith("~/"):
        value = str(home()) + value[1:]
    if os.path.isabs(value):
        return value
    print(f"forgd-verdict: hook.spool {value!r} is not an absolute path; using "
          f"{_trusted_default()}", file=sys.stderr)
    return _trusted_default()


def salt_root(policy: Any) -> Path:
    """The directory holding the device salt: the spool directory's parent."""
    return Path(spool_root(policy)).parent
