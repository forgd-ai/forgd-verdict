"""The variables a hook process removes from its environment before it
imports anything that reads them.

A Claude Code project's `.claude/settings.json` `env` block reaches the
hook's environment. `forgd_verdict/__init__.py` calls `scrub()` as its first
statement when the interpreter was started with `-X forgd_verdict_hook`,
which only argv can set. Importing the package then loads OpenSSL through
hashlib and ssl, and libcrypto and libssl read the names below. Any other
`OPENSSL_` or `OSSL_` name is removed too.

`scrubbed()` returns the same environment as a copy, for a process that
starts the hook as a child.

This module imports only `os`, and is imported before anything
else in the package.
"""

from __future__ import annotations

import os

MARKER = "forgd_verdict_hook"

NAMES = frozenset(name.upper() for name in (
    # The configuration file, read when `_hashlib` initialises, and the
    # base for its relative `.include`s. The file can load providers and
    # engines and set TLS defaults.
    "OPENSSL_CONF",
    "OPENSSL_CONF_INCLUDE",
    # Directories providers and engines are loaded from.
    "OPENSSL_MODULES",
    "OPENSSL_ENGINES",
    # CPU capability masks, read when libcrypto loads.
    "OPENSSL_ia32cap",
    "OPENSSL_armcap",
    "OPENSSL_ppccap",
    "OPENSSL_sparcv9cap",
    "OPENSSL_s390xcap",
    "OPENSSL_riscvcap",
    # Debug allocation, in enable-crypto-mdebug builds.
    "OPENSSL_MALLOC_FAILURES",
    "OPENSSL_MALLOC_FD",
    "OPENSSL_MALLOC_SEED",
    # How `ossl_safe_getenv` decodes values on Windows.
    "OPENSSL_WIN32_UTF8",
    # The default CA file and directory.
    "SSL_CERT_FILE",
    "SSL_CERT_DIR",
    # The default CT log list.
    "CTLOG_FILE",
    # QUIC logging in OpenSSL 3.5.
    "QLOGDIR",
    "OSSL_QFILTER",
    # The TLS key log in OpenSSL 3.5 built with enable-sslkeylog.
    "SSLKEYLOGFILE",
))
PREFIXES = ("OPENSSL_", "OSSL_")


def removed(name: str) -> bool:
    """True when `name` is one the scrub removes, in any case."""
    upper = name.upper()
    return upper in NAMES or upper.startswith(PREFIXES)


def scrubbed(environ: dict[str, str]) -> dict[str, str]:
    """A copy of `environ` without the names `removed` matches."""
    return {name: value for name, value in environ.items() if not removed(name)}


def scrub() -> list[str]:
    """Remove the matching names from this process's environment and
    return them. Values are never returned."""
    names = [name for name in os.environ if removed(name)]
    for name in names:
        del os.environ[name]
    return names
