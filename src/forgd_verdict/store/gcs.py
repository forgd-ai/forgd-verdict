"""Google Cloud Storage store: the same partitioned-JSONL layout, in a bucket.

Needs the `gcp` extra. Imported lazily by `open_store`, so the verdict server
carries no Google SDK unless GCS is configured.

Spec: `gs://bucket/prefix`. Credentials come from Application Default
Credentials: Workload Identity on GKE, the attached service account on Cloud
Run or GCE. No key is configured here. The dashboard needs
`storage.objects.get` and `storage.objects.list`. The writers need those and
`storage.objects.create`, and `storage.objects.delete` on the objects this
store replaces in place: the cursors under STATE_PREFIX and the two markers,
RESET_MARKER and EXCLUDE_MARKER. GCS checks delete on any write that
replaces an object. Records are written with `if_generation_match=0` and
never replaced, so the writer needs no delete on them, and
`deploy/terraform/modules/store-gcs` grants none: its delete binding is
conditioned on exactly those names. Losing a cursor costs a rescan, and
losing a marker costs an exclusion or a reset, which can be redone; neither
loses evidence. With versioning on, each replaced cursor and marker is kept
as a noncurrent version. Nothing in this backend deletes.

An object is absent only on a 404. A 403 is a denial and is never read as
"not there".
"""

from __future__ import annotations

import logging
import threading
from collections.abc import Collection, Iterable, Iterator, Sequence
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
from .blob import new_instance_id
from .local import DENIALS_SOURCE

log = logging.getLogger("forgd_verdict.store.gcs")

# (connect, read) seconds per request, and the total seconds retries may take.
_TIMEOUT = (10, 30)
_RETRY_SECONDS = 60.0


def _status(exc: Exception) -> int | None:
    code = getattr(exc, "code", None)
    return int(code) if isinstance(code, int) else None


class GCSStore:
    # Whether a 403 on `put_audit` proves the writer lockout (forgd_verdict.lockout).
    lockout_provable = True
    # Which lockout_evidence module reads this store's IAM policy.
    evidence_kind = "gcs"

    def __init__(self, url: str, instance: str | None = None, client: Any = None):
        parsed = urlparse(url)
        if parsed.scheme != "gs" or not parsed.netloc:
            raise ValueError(f"GCS store spec must be gs://bucket[/prefix]: {shown_url(url)!r}")
        self.bucket_name = parsed.netloc
        self.prefix = parsed.path.strip("/")
        try:
            from google.cloud.storage.retry import DEFAULT_RETRY  # type: ignore
        except ImportError as exc:  # pragma: no cover - depends on extra
            raise RuntimeError(
                "GCS storage needs the gcp extra: pip install 'forgd-verdict[gcp]'"
            ) from exc
        if client is None:
            from google.cloud import storage  # type: ignore

            # project=None still takes credentials from ADC, and does not
            # raise when ADC supplies no project; object calls never use one.
            client = storage.Client(project=None)
        self._client = client
        self._bucket = client.bucket(self.bucket_name)
        # Passed on every call, as s3.py bounds its client: a hung writer
        # thread is silent, a failed one is counted and retried.
        self._retry = DEFAULT_RETRY.with_timeout(_RETRY_SECONDS)
        # RUN-unique, as blob.py's is. Records are written with
        # if_generation_match=0, so a collision fails instead of replacing one.
        self.instance = instance or new_instance_id()
        self._lock = threading.Lock()
        self._seq = 0

    def _bounds(self) -> dict[str, Any]:
        return {"timeout": _TIMEOUT, "retry": self._retry}

    def _full(self, rel: str) -> str:
        return f"{self.prefix}/{rel}" if self.prefix else rel

    def _key(
        self, prefix: str, source: str, day: str, seq: int, org: str | None = None
    ) -> str:
        return self._full(partition_path(prefix, source, day, self.instance, seq, org))

    def _put(self, key: str, body: bytes, *, immutable: bool = False,
             content_type: str = "text/plain") -> None:
        kwargs = self._bounds()
        if immutable:
            # Generation 0 means "no live object": GCS refuses the write with
            # 412 if the key exists.
            kwargs["if_generation_match"] = 0
        try:
            self._bucket.blob(key).upload_from_string(body, content_type=content_type, **kwargs)
        except Exception as exc:  # noqa: BLE001 - google.api_core raises a family
            if not (immutable and _status(exc) == 412 and self._already_written(key, body)):
                raise

    def _already_written(self, key: str, body: bytes) -> bool:
        """Whether a 412 on a record write is this write's own earlier attempt.

        GCS can commit an upload and lose the response, and the SDK's
        retry then gets a 412 for the object it just wrote. Identical bytes at
        the key mean that; different bytes, or a failed read, do not.
        """
        try:
            return self._get(key) == body
        except Exception:  # noqa: BLE001 - the 412 stands
            return False

    # -- write ------------------------------------------------------------

    def write_verdicts(self, records: Sequence[VerdictRecord]) -> int:
        return self._write("verdicts", records)

    def write_denials(self, records: Sequence[DenialRecord]) -> int:
        return self._write("denials", records, source=DENIALS_SOURCE)

    def _write(self, prefix: str, records: Sequence[Any], source: str | None = None) -> int:
        if not records:
            return 0
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
            self._put(self._key(prefix, src, day, seq, org), body, immutable=True,
                      content_type="application/x-ndjson")
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
        keys = partition_keys(self._level, self._keys, root, since, orgs, until, sources)
        for day, names in by_day_newest_first(keys, root):
            yield day, VerdictDay(names, self._get, root)

    def _records(self, names: Iterable[str], cls) -> Iterator[Any]:
        for name in names:
            for line in iter_json_lines(self._get(name)):
                try:
                    yield cls.from_json(line)
                except (ValueError, TypeError):
                    continue

    def _keys(self, root: str) -> Iterator[str]:
        # The iterator fetches each further page with the same bounds.
        for blob in self._client.list_blobs(self.bucket_name, prefix=root, **self._bounds()):
            yield blob.name

    def _level(self, prefix: str) -> tuple[list[str], list[str]]:
        # `prefixes` fills as the iterator fetches each page.
        listing = self._client.list_blobs(self.bucket_name, prefix=prefix, delimiter="/",
                                          **self._bounds())
        keys = [blob.name for blob in listing]
        return sorted(listing.prefixes), keys

    def _get(self, key: str) -> bytes:
        return self._bucket.blob(key).download_as_bytes(**self._bounds())

    def _root(self, prefix: str) -> str:
        # The trailing slash: GCS prefixes are character prefixes, so
        # `demo/verdicts` alone also lists `demo/verdicts-backup/...`.
        return self._full(prefix) + "/"

    def _read(
        self, prefix: str, cls, since: str | None, orgs: Collection[str] | None = None,
        sources: Collection[str] | None = None,
    ) -> Iterator[Any]:
        keys = partition_keys(self._level, self._keys, self._root(prefix), since, orgs,
                              sources=sources)
        yield from self._records(keys, cls)

    def _get_optional(self, key: str, what: str) -> bytes | None:
        """None for an object that is not there. Any other error is logged
        and also read as None, so a denied marker shows up in the logs."""
        try:
            return self._get(key)
        except Exception as exc:  # noqa: BLE001 - google.api_core raises a family
            if _status(exc) == 404:
                return None
            log.warning("could not read the %s from the store", what, extra={
                "fields": {"error": type(exc).__name__, "code": _status(exc)}})
            return None

    def set_reset_marker(self, when: str) -> None:
        self._put(self._full(RESET_MARKER), when.encode("utf-8"))

    def get_reset_marker(self) -> str | None:
        raw = self._get_optional(self._full(RESET_MARKER), "reset marker")
        return (raw.decode("utf-8").strip() or None) if raw is not None else None

    def set_excluded(self, request_ids) -> None:
        body = "\n".join(sorted(set(request_ids))).encode("utf-8")
        self._put(self._full(EXCLUDE_MARKER), body)

    def get_excluded(self) -> set[str]:
        raw = self._get_optional(self._full(EXCLUDE_MARKER), "exclusion marker")
        if raw is None:
            return set()
        return {ln.strip() for ln in raw.decode("utf-8").splitlines() if ln.strip()}

    # -- durable state ----------------------------------------------------

    def put_state(self, name: str, blob: bytes) -> None:
        self._put(self._state_key(name), blob, content_type="application/octet-stream")

    def get_state(self, name: str) -> bytes | None:
        """None on a first run. Any other failure RAISES: a cursor that
        could not be read is not a first run."""
        try:
            return self._get(self._state_key(name))
        except Exception as exc:  # noqa: BLE001 - google.api_core raises a family
            if _status(exc) == 404:
                return None
            raise

    def _state_key(self, name: str) -> str:
        return self._full(f"{STATE_PREFIX}/{safe_state_name(name)}")

    # -- runtime overrides ------------------------------------------------

    def _control_key(self) -> str:
        return self._full(f"{STATE_PREFIX}/{CONTROL_STATE}")

    def read_control(self) -> ControlRead:
        """The object's bytes with its generation as the etag.

        The metadata read gives the generation and the download is
        conditional on it, so the bytes are the ones that generation names.
        """
        key = self._control_key()
        try:
            blob = self._bucket.get_blob(key, **self._bounds())
            if blob is None:
                return ABSENT
            generation = blob.generation
            body = blob.download_as_bytes(if_generation_match=generation, **self._bounds())
        except Exception as exc:  # noqa: BLE001 - google.api_core raises a family
            if _status(exc) == 404:
                return ABSENT
            raise StoreReadError(type(exc).__name__) from exc
        return ControlRead("ok", body, str(generation))

    def write_control(self, body: bytes, if_etag: str | None) -> None:
        key = self._control_key()
        generation = 0 if if_etag is None else int(if_etag)
        try:
            self._bucket.blob(key).upload_from_string(
                body, content_type="application/json",
                if_generation_match=generation, **self._bounds())
        except Exception as exc:  # noqa: BLE001 - google.api_core raises a family
            if _status(exc) == 412:
                if self._already_written(key, body):
                    return
                raise StoreConflict("runtime overrides object changed") from exc
            if _status(exc) == 403:
                raise StoreForbidden("the runtime overrides object") from exc
            raise

    def _audit_key(self, name: str) -> str:
        return self._full(f"{AUDIT_PREFIX}/{safe_audit_name(name)}")

    def put_audit(self, name: str, body: bytes) -> None:
        key = self._audit_key(name)
        try:
            self._bucket.blob(key).upload_from_string(
                body, content_type="application/json", if_generation_match=0,
                **self._bounds())
        except Exception as exc:  # noqa: BLE001 - google.api_core raises a family
            if _status(exc) == 412:
                if self._already_written(key, body):
                    return
                raise StoreConflict(f"audit record exists: {name}") from exc
            if _status(exc) == 403:
                raise StoreForbidden("the runtime overrides audit prefix") from exc
            raise

    def get_audit(self, name: str) -> bytes | None:
        key = self._audit_key(name)
        try:
            return self._get(key)
        except Exception as exc:  # noqa: BLE001 - google.api_core raises a family
            if _status(exc) == 404:
                return None
            raise

    def list_audit(self, day: str | None = None, leaf: str = "") -> list[str]:
        root = self._full(AUDIT_PREFIX) + "/"
        return sorted(k[len(root):] for k in self._keys(root + audit_scope(day, leaf)))

    def audit_days(self) -> list[str]:
        root = self._full(AUDIT_PREFIX) + "/"
        prefixes, _ = self._level(root)
        return sorted(d for d in (p[len(root):-1] for p in prefixes) if AUDIT_DAY.fullmatch(d))

    def describe(self) -> dict[str, Any]:
        return {
            "backend": "gcs",
            "bucket": self.bucket_name,
            "prefix": self.prefix,
            "instance": self.instance,
            "reset_at": self.get_reset_marker(),
        }


__all__ = ["GCSStore"]
