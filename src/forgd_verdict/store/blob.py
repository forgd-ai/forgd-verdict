"""Azure Blob store: the same partitioned-JSONL layout, in a container.

Needs the `azure` extra. Imported lazily by `open_store` so the verdict
server carries no dependency on it unless blob storage is configured.

Auth uses the app's managed identity, so no key or connection string exists
anywhere. The ingest job and the dashboard get separate identities: the
writers need Storage Blob Data Contributor, the dashboard needs only Reader.

**A USER-ASSIGNED identity must be named.** `DefaultAzureCredential` cannot
guess which one to use, and with an unnamed user-assigned identity it walks
its entire credential chain with retries -- which does not raise, it
*hangs*. A writer thread stalls there: the queue holds records, nothing
is written, and no error is logged. So when
AZURE_CLIENT_ID is present this uses ManagedIdentityCredential directly, and
the credential is given an explicit timeout either way, so a misconfigured
identity surfaces as a counted error rather than a silent stall.

Container Apps does not set AZURE_CLIENT_ID for you. Set it to the
identity's clientId on any app that writes here.
"""

from __future__ import annotations

import logging
import os
import secrets
import threading
from collections.abc import Collection, Iterable, Iterator, Sequence
from datetime import UTC, datetime
from typing import Any
from urllib.parse import urlparse

from ..models import CONTROL_STATE, safe_state_name, shown_url
from .base import (
    ABSENT,
    AUDIT_DAY,
    AUDIT_PREFIX,
    EXCLUDE_MARKER,
    ORG_UNATTRIBUTED,
    RESET_MARKER,
    STATE_PREFIX,
    ControlRead,
    DenialRecord,
    StoreConflict,
    StoreForbidden,
    StoreReadError,
    VerdictDay,
    VerdictRecord,
    audit_scope,
    by_day_newest_first,
    iter_json_lines,
    partition_keys,
    partition_path,
    safe_audit_name,
)
from .local import DENIALS_SOURCE

log = logging.getLogger("forgd_verdict.store.blob")


def _azure_status(exc: Exception) -> int | None:
    """The HTTP status of an azure.core error, from `status_code` or its type."""
    code = getattr(exc, "status_code", None)
    if isinstance(code, int):
        return code
    return {"ResourceNotFoundError": 404, "ResourceExistsError": 409,
            "ResourceModifiedError": 412}.get(type(exc).__name__)


def new_instance_id() -> str:
    """A RUN-unique id for the writer, used in every object name.

    Extracted so it can be tested without an Azure client.
    """
    hint = (
        os.environ.get("CONTAINER_APP_REPLICA_NAME")
        or os.environ.get("HOSTNAME")
        or str(os.getpid())
    )
    return f"{hint}-{secrets.token_hex(3)}"


class BlobStore:
    # Whether a 403 on `put_audit` proves the writer lockout (forgd_verdict.lockout).
    lockout_provable = True
    # Which lockout_evidence module reads this store's IAM policy.
    evidence_kind = "azure"

    def __init__(self, url: str, instance: str | None = None):
        try:
            from azure.storage.blob import ContainerClient  # type: ignore
        except ImportError as exc:  # pragma: no cover - depends on extra
            raise RuntimeError(
                "Blob storage needs the azure extra: pip install 'forgd-verdict[azure]'"
            ) from exc

        parsed = urlparse(url)
        parts = [p for p in parsed.path.split("/") if p]
        if not parts:
            raise ValueError(
                f"blob URL must include a container: {parsed.hostname or 'no host'!r} "
                "(e.g. https://acct.blob.core.windows.net/findings/prefix)"
            )
        container, *rest = parts
        self.prefix = "/".join(rest)
        self.account_url = f"{parsed.scheme}://{parsed.netloc}"

        # Name the identity when we can. See the module docstring: an
        # unnamed user-assigned identity makes DefaultAzureCredential hang
        # rather than fail. Shared with the Azure Monitor sink, because
        # two copies of that rule would drift and the drift is a hang.
        from ..azure_auth import credential as _credential

        credential, self.identity = _credential()
        self.credential = credential

        self._client = ContainerClient(
            account_url=self.account_url,
            container_name=container,
            credential=credential,
            # Bound every call. A hung writer thread is worse than a failed
            # one: the failure is counted and retried, the hang is silent.
            connection_timeout=10,
            read_timeout=30,
            retry_total=2,
        )
        self.container = container
        # A RUN-unique instance id. Blobs are immutable -- written with
        # overwrite=False -- so two writers that pick the same id do not
        # merge, they fail.
        #
        # A platform name or the pid alone is not enough: the pid of the
        # app in a container is 1, so every pod would call itself `1`, and
        # `_seq` restarts at 0 on every start -- the first write after any
        # restart would target `1-000001.jsonl`, which already exists, and
        # Azure answers BlobAlreadyExists. That is a 503 from /intake,
        # which writes synchronously, and SILENT DATA LOSS on the verdict
        # server and the collector, where `StoreSink` retries and then
        # drops with a counter.
        #
        # The random suffix is what makes the id unique. HOSTNAME is the
        # pod name and is unique for a Deployment, but a StatefulSet
        # reuses it and a recreated pod can take the same name back; the
        # platform hint is kept only so an object can still be attributed
        # to a replica when someone is reading the container by hand.
        self.instance = instance or new_instance_id()
        self._lock = threading.Lock()
        self._seq = 0

    def _key(
        self, prefix: str, source: str, day: str, seq: int, org: str | None = None
    ) -> str:
        rel = partition_path(prefix, source, day, self.instance, seq, org)
        return f"{self.prefix}/{rel}" if self.prefix else rel

    # -- write ------------------------------------------------------------

    def write_verdicts(self, records: Sequence[VerdictRecord]) -> int:
        return self._write("verdicts", records)

    def write_denials(self, records: Sequence[DenialRecord]) -> int:
        return self._write("denials", records, source=DENIALS_SOURCE)

    def _write(self, prefix: str, records: Sequence[Any], source: str | None = None) -> int:
        if not records:
            return 0
        # By (source, org, day): a batch is not guaranteed to be single-org,
        # and one cross-org object would defeat org pruning for every reader.
        buckets: dict[tuple[str, str, str], list[str]] = {}
        for record in records:
            key = (
                source or getattr(record, "source", DENIALS_SOURCE),
                getattr(record, "org", ORG_UNATTRIBUTED),
                record.day,
            )
            buckets.setdefault(key, []).append(record.to_json())

        written = 0
        for (src, org, day), lines in buckets.items():
            with self._lock:
                self._seq += 1
                seq = self._seq
            body = ("\n".join(lines) + "\n").encode("utf-8")
            # One immutable object per batch: no append semantics, no
            # read-modify-write, so concurrent writers never conflict.
            self._client.upload_blob(
                self._key(prefix, src, day, seq, org), body, overwrite=False
            )
            written += len(lines)
        return written

    # -- read -------------------------------------------------------------

    def read_verdicts(
        self, since: str | None = None, orgs: Collection[str] | None = None,
        sources: Collection[str] | None = None,
    ) -> Iterator[VerdictRecord]:
        yield from self._read("verdicts", VerdictRecord, since, orgs, sources)

    def read_denials(
        self, since: str | None = None, orgs: Collection[str] | None = None
    ) -> Iterator[DenialRecord]:
        yield from self._read("denials", DenialRecord, since, orgs)

    def read_verdict_days(
        self, since: str | None = None, orgs: Collection[str] | None = None,
        until: str | None = None, sources: Collection[str] | None = None,
    ) -> Iterator[tuple[str | None, Iterator[VerdictRecord]]]:
        root = self._root("verdicts")
        keys = partition_keys(self._level, self._tree, root, since, orgs, until, sources)
        for day, names in by_day_newest_first(keys, root):
            yield day, VerdictDay(names, self._download, root)

    def _download(self, name: str) -> bytes:
        return self._client.download_blob(name).readall()

    def _records(self, names: Iterable[str], cls) -> Iterator[Any]:
        for name in names:
            for line in iter_json_lines(self._download(name)):
                try:
                    yield cls.from_json(line)
                except (ValueError, TypeError):
                    continue

    def _root(self, prefix: str) -> str:
        # The trailing slash: `name_starts_with` is a character prefix, so
        # `verdicts` alone also lists a sibling such as `verdicts-backup/`.
        return (f"{self.prefix}/{prefix}" if self.prefix else prefix) + "/"

    def _read(
        self, prefix: str, cls, since: str | None, orgs: Collection[str] | None = None,
        sources: Collection[str] | None = None,
    ) -> Iterator[Any]:
        keys = partition_keys(self._level, self._tree, self._root(prefix), since, orgs,
                              sources=sources)
        yield from self._records(keys, cls)

    def _level(self, prefix: str) -> tuple[list[str], list[str]]:
        prefixes, keys = [], []
        # A BlobPrefix's name is the prefix and ends in the delimiter.
        for item in self._client.walk_blobs(name_starts_with=prefix, delimiter="/"):
            if item.name.endswith("/") and item.name != prefix:
                prefixes.append(item.name)
            else:
                keys.append(item.name)
        return prefixes, keys

    def _tree(self, prefix: str) -> list[str]:
        return [b.name for b in self._client.list_blobs(name_starts_with=prefix)]

    def set_reset_marker(self, when: str) -> None:
        key = f"{self.prefix}/{RESET_MARKER}" if self.prefix else RESET_MARKER
        self._client.upload_blob(key, when.encode("utf-8"), overwrite=True)

    def _get_optional(self, key: str, what: str) -> bytes | None:
        """None for a blob that is not there. Any other error is logged and
        also returns None: an access-denied marker read as "no marker" would
        otherwise hide a misconfigured role behind a dashboard that looks
        fine."""
        try:
            return self._client.download_blob(key).readall()
        except Exception as exc:  # noqa: BLE001 - azure.core raises a family
            if _azure_status(exc) != 404:
                log.warning("could not read the %s from the store", what, extra={
                    "fields": {"error": type(exc).__name__, "status": _azure_status(exc)}})
            return None

    def get_reset_marker(self) -> str | None:
        key = f"{self.prefix}/{RESET_MARKER}" if self.prefix else RESET_MARKER
        raw = self._get_optional(key, "reset marker")
        return (raw.decode("utf-8").strip() or None) if raw is not None else None

    def set_excluded(self, request_ids) -> None:
        key = f"{self.prefix}/{EXCLUDE_MARKER}" if self.prefix else EXCLUDE_MARKER
        body = "\n".join(sorted(set(request_ids))).encode("utf-8")
        self._client.upload_blob(key, body, overwrite=True)

    def get_excluded(self) -> set[str]:
        key = f"{self.prefix}/{EXCLUDE_MARKER}" if self.prefix else EXCLUDE_MARKER
        raw = self._get_optional(key, "exclusion marker")
        if raw is None:
            return set()
        return {ln.strip() for ln in raw.decode("utf-8").splitlines() if ln.strip()}

    # -- durable state ----------------------------------------------------

    def put_state(self, name: str, blob: bytes) -> None:
        key = self._state_key(name)
        # overwrite=True: a cursor is the one thing here that is mutable.
        # Every record object stays immutable and append-only.
        self._client.upload_blob(key, blob, overwrite=True)

    def get_state(self, name: str) -> bytes | None:
        # The key is built OUTSIDE the try, so a rejected name raises its
        # ValueError rather than reading as "no state yet". Only a 404 is
        # absence; any other error raises, so a denied read is not taken for
        # a first run.
        key = self._state_key(name)
        try:
            return self._client.download_blob(key).readall()
        except Exception as exc:  # noqa: BLE001 - azure.core raises a family
            if _azure_status(exc) == 404:
                return None
            raise

    def _state_key(self, name: str) -> str:
        rel = f"{STATE_PREFIX}/{safe_state_name(name)}"
        return f"{self.prefix}/{rel}" if self.prefix else rel

    # -- runtime overrides ------------------------------------------------

    def _full(self, rel: str) -> str:
        return f"{self.prefix}/{rel}" if self.prefix else rel

    def read_control(self) -> ControlRead:
        key = self._full(f"{STATE_PREFIX}/{CONTROL_STATE}")
        try:
            download = self._client.download_blob(key)
            body = download.readall()
        except Exception as exc:  # noqa: BLE001 - azure.core raises a family
            if _azure_status(exc) == 404:
                return ABSENT
            raise StoreReadError(type(exc).__name__) from exc
        return ControlRead("ok", body, str(download.properties.etag or ""))

    def write_control(self, body: bytes, if_etag: str | None) -> None:
        key = self._full(f"{STATE_PREFIX}/{CONTROL_STATE}")
        try:
            if if_etag is None:
                self._client.upload_blob(key, body, overwrite=False)
            else:
                from azure.core import MatchConditions  # type: ignore

                self._client.upload_blob(key, body, overwrite=True, etag=if_etag,
                                         match_condition=MatchConditions.IfNotModified)
        except Exception as exc:  # noqa: BLE001 - azure.core raises a family
            if _azure_status(exc) in (404, 409, 412):
                raise StoreConflict("runtime overrides object changed") from exc
            if _azure_status(exc) == 403:
                raise StoreForbidden("the runtime overrides object") from exc
            raise

    def _audit_key(self, name: str) -> str:
        return self._full(f"{AUDIT_PREFIX}/{safe_audit_name(name)}")

    def put_audit(self, name: str, body: bytes) -> None:
        try:
            self._client.upload_blob(self._audit_key(name), body, overwrite=False)
        except Exception as exc:  # noqa: BLE001 - azure.core raises a family
            if _azure_status(exc) in (409, 412):
                raise StoreConflict(f"audit record exists: {name}") from exc
            if _azure_status(exc) == 403:
                raise StoreForbidden("the runtime overrides audit prefix") from exc
            raise

    def get_audit(self, name: str) -> bytes | None:
        try:
            return self._client.download_blob(self._audit_key(name)).readall()
        except Exception as exc:  # noqa: BLE001 - azure.core raises a family
            if _azure_status(exc) == 404:
                return None
            raise

    def audit_modified(self, name: str) -> datetime:
        try:
            modified = self._client.download_blob(self._audit_key(name)).properties.last_modified
        except Exception as exc:  # noqa: BLE001 - azure.core raises a family
            raise StoreReadError(type(exc).__name__) from exc
        if modified is None:
            raise StoreReadError(f"no last-modified time: {name}")
        return modified.astimezone(UTC)

    def list_audit(self, day: str | None = None, leaf: str = "") -> list[str]:
        root = self._full(AUDIT_PREFIX) + "/"
        return sorted(k[len(root):] for k in self._tree(root + audit_scope(day, leaf)))

    def audit_days(self) -> list[str]:
        root = self._full(AUDIT_PREFIX) + "/"
        prefixes, _ = self._level(root)
        return sorted(d for d in (p[len(root):-1] for p in prefixes) if AUDIT_DAY.fullmatch(d))

    def describe(self) -> dict[str, Any]:
        return {
            "backend": "azure-blob",
            "account_url": shown_url(self.account_url),
            "container": self.container,
            "prefix": self.prefix,
            "instance": self.instance,
            "identity": self.identity,
            "reset_at": self.get_reset_marker(),
        }


__all__ = ["BlobStore"]
