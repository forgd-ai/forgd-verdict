"""One place that decides which Azure credential to use.

Extracted from `store/blob.py`, which learned the rule the hard way and
wrote it down. The findings store and the Azure Monitor sink now both
authenticate the same way, because two copies of this would drift and the
way they would drift is a hang rather than an error.

**A user-assigned identity must be NAMED.** With `AZURE_CLIENT_ID` set,
`DefaultAzureCredential` probes IMDS without the client id, gets an
ambiguous-identity response, and retries until its timeout instead of
failing -- so a misconfiguration presents as the process wedging on
startup. `ManagedIdentityCredential(client_id=...)` asks the question
that has one answer.
"""

from __future__ import annotations

import os
from typing import Any

SCOPE_MONITOR = "https://monitor.azure.com/.default"


def credential() -> tuple[Any, str]:
    """Return (credential, a description that is safe to log).

    The description names the identity, which is a client id and not a
    secret -- it is what makes an "authenticated as nothing" deployment
    diagnosable. See `deploy/helm/README.md`: with the wrong service
    account name the pods authenticate as nobody, the dashboard renders
    empty and the collector accepts exports it then fails to store,
    neither of which looks like an auth failure from outside.
    """
    try:
        from azure.identity import (  # type: ignore
            DefaultAzureCredential,
            ManagedIdentityCredential,
        )
    except ImportError as exc:
        raise RuntimeError(
            "Azure authentication needs the azure extra: "
            "pip install 'forgd-verdict[azure]'"
        ) from exc

    client_id = os.environ.get("AZURE_CLIENT_ID")
    if client_id:
        return ManagedIdentityCredential(client_id=client_id), f"managed:{client_id}"
    return DefaultAzureCredential(), "default-chain"
