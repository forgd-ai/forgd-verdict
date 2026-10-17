"""The hook's device certificate: signs each request to the intake.

`hook.device_certificate` names a PEM file holding the device certificate
and any intermediates, leaf first, and a PEM file holding its private key.
Both paths are read from the policy as written, and must be absolute: the
hook runs in the project's directory. A `$VAR` placeholder is refused,
because a project's environment can set it.

A key in a file the developer can read proves which device a batch came
from as well as a per-device token does, and protects it no better: the
key stays on the device only when the platform holds it, which this does
not do. docs/PLATFORM.md says so.
"""

from __future__ import annotations

import sys
from collections.abc import Callable, Mapping
from pathlib import Path
from typing import Any

Signer = Callable[[bytes, str], str]


def device_signer(hook: Mapping[str, Any]) -> Signer | None:
    """A function of (body, route) to the Authorization header value, or
    None when no device certificate is configured or it cannot be loaded;
    the reason is printed on stderr."""
    cfg = hook.get("device_certificate")
    if not cfg:
        return None
    if not isinstance(cfg, Mapping):
        _say("hook.device_certificate must be a mapping with cert_file and key_file")
        return None
    paths = {k: cfg.get(k) for k in ("cert_file", "key_file")}
    for key, value in paths.items():
        if not isinstance(value, str) or not value:
            _say(f"hook.device_certificate.{key} is not set")
            return None
        if value.startswith("$"):
            _say(f"hook.device_certificate.{key} is a placeholder, which a project's "
                 "environment can set; give the path itself")
            return None
        if not Path(value).is_absolute():
            # The hook runs in the project's directory, so a relative path
            # would name a file the repository supplies.
            _say(f"hook.device_certificate.{key} must be an absolute path")
            return None
    try:
        from cryptography import x509
        from cryptography.hazmat.primitives.serialization import load_pem_private_key

        chain = x509.load_pem_x509_certificates(Path(paths["cert_file"]).read_bytes())
        key = load_pem_private_key(Path(paths["key_file"]).read_bytes(), password=None)
    except (OSError, ValueError, TypeError) as exc:
        _say(f"the device certificate could not be loaded ({type(exc).__name__})")
        return None
    from ..intake.devicecert import sign_request

    def sign(body: bytes, route: str) -> str:
        return sign_request(body, route, chain, key)

    try:
        sign(b"", "intake")
    except ValueError as exc:
        _say(f"the device key cannot sign: {exc}")
        return None
    return sign


def _say(message: str) -> None:
    print(f"forgd-verdict: {message}; requests use hook's token instead, if any",
          file=sys.stderr)
