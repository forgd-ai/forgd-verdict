"""Amazon S3 store: the same partitioned-JSONL layout, in a bucket.

Needs the `aws` extra. Imported lazily by `open_store`, so the verdict server
carries no AWS SDK unless S3 is configured.

Spec: `s3://bucket/prefix`. Credentials come from the default AWS chain:
EKS Pod Identity or IRSA on EKS, the task role on ECS, an instance profile
on EC2. No key is configured here. The writers need `s3:PutObject`,
`s3:GetObject` and `s3:ListBucket`, the dashboard `s3:GetObject` and
`s3:ListBucket`, and neither needs `s3:DeleteObject`: nothing in this
backend deletes. S3 answers a missing key with 404 only to a caller whose
ListBucket covers that GetObject, and a ListBucket scoped by `s3:prefix`
never does, because a GetObject carries no prefix. So a 403 on a read is
checked with a list for that exact key, which a prefix-scoped grant does
allow, before it is taken as a denial.
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

log = logging.getLogger("forgd_verdict.store.s3")

# Codes S3 answers for an object that is not there, to a caller whose
# ListBucket covers the request. A 403 is resolved by `_absent`.
_ABSENT = frozenset({"NoSuchKey", "404", "NotFound"})
# Codes for a conditional write the object's current state refused.
_CONFLICT = frozenset({"PreconditionFailed", "412", "ConditionalRequestConflict", "409"})
_DENIED = frozenset({"AccessDenied", "403"})


def _code(exc: Exception) -> str:
    response = getattr(exc, "response", None)
    if isinstance(response, dict):
        return str((response.get("Error") or {}).get("Code") or "")
    return ""


class S3Store:
    # Whether a 403 on `put_audit` proves the writer lockout (forgd_verdict.lockout).
    lockout_provable = True
    # Which lockout_evidence module reads this store's IAM policy.
    evidence_kind = "s3"

    def __init__(self, url: str, instance: str | None = None, client: Any = None):
        parsed = urlparse(url)
        if parsed.scheme != "s3" or not parsed.netloc:
            raise ValueError(f"S3 store spec must be s3://bucket[/prefix]: {shown_url(url)!r}")
        self.bucket = parsed.netloc
        self.prefix = parsed.path.strip("/")
        if client is None:
            try:
                import boto3  # type: ignore
                from botocore.config import Config  # type: ignore
            except ImportError as exc:  # pragma: no cover - depends on extra
                raise RuntimeError(
                    "S3 storage needs the aws extra: pip install 'forgd-verdict[aws]'"
                ) from exc
            # Every call bounded, for the reason blob.py gives: a hung writer
            # thread is silent, a failed one is counted and retried.
            client = boto3.client("s3", config=Config(
                connect_timeout=10, read_timeout=30,
                retries={"max_attempts": 3, "mode": "standard"}))
        self._client = client
        # RUN-unique, as blob.py's is, so two writers never pick one name.
        # Objects are written with If-None-Match: *, so a collision fails
        # instead of replacing a record.
        self.instance = instance or new_instance_id()
        self._lock = threading.Lock()
        self._seq = 0

    def _full(self, rel: str) -> str:
        return f"{self.prefix}/{rel}" if self.prefix else rel

    def _key(
        self, prefix: str, source: str, day: str, seq: int, org: str | None = None
    ) -> str:
        return self._full(partition_path(prefix, source, day, self.instance, seq, org))

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
            # A conditional write: S3 refuses it with 412 if the key exists,
            # which makes the object immutable the way blob's overwrite=False
            # does. A plain PutObject would silently replace a record.
            key = self._key(prefix, src, day, seq, org)
            try:
                self._client.put_object(Bucket=self.bucket, Key=key, Body=body,
                                        IfNoneMatch="*", ContentType="application/x-ndjson")
            except Exception as exc:  # noqa: BLE001 - botocore raises a family
                if not (_code(exc) == "PreconditionFailed" and self._already_written(key, body)):
                    raise
            written += len(lines)
        return written

    def _already_written(self, key: str, body: bytes) -> bool:
        """Whether a 412 on a record write is this write's own earlier attempt.

        S3 can commit a PutObject and lose the response, and the SDK's
        retry then gets a 412 for the object it just wrote. Identical bytes at
        the key mean that; different bytes, or a failed read, do not.
        """
        try:
            return self._get(key) == body
        except Exception:  # noqa: BLE001 - the 412 stands
            return False

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
        paginator = self._client.get_paginator("list_objects_v2")
        for page in paginator.paginate(Bucket=self.bucket, Prefix=root):
            for obj in page.get("Contents") or []:
                yield obj["Key"]

    def _level(self, prefix: str) -> tuple[list[str], list[str]]:
        prefixes, keys = [], []
        paginator = self._client.get_paginator("list_objects_v2")
        for page in paginator.paginate(Bucket=self.bucket, Prefix=prefix, Delimiter="/"):
            prefixes.extend(p["Prefix"] for p in page.get("CommonPrefixes") or [])
            keys.extend(obj["Key"] for obj in page.get("Contents") or [])
        return prefixes, keys

    def _get(self, key: str) -> bytes:
        return self._client.get_object(Bucket=self.bucket, Key=key)["Body"].read()

    def _root(self, prefix: str) -> str:
        # The trailing slash: S3 prefixes are character prefixes, so
        # `demo/verdicts` alone also lists `demo/verdicts-backup/...`.
        return self._full(prefix) + "/"

    def _read(
        self, prefix: str, cls, since: str | None, orgs: Collection[str] | None = None,
        sources: Collection[str] | None = None,
    ) -> Iterator[Any]:
        keys = partition_keys(self._level, self._keys, self._root(prefix), since, orgs,
                              sources=sources)
        yield from self._records(keys, cls)

    def _absent(self, key: str, exc: Exception) -> bool:
        """Whether `exc` from reading `key` means the key does not exist.

        A 403 is ambiguous: a real denial, or a missing key under a
        prefix-scoped ListBucket. Listing that exact key settles it; if the
        list is denied too, the 403 stands.
        """
        code = _code(exc)
        if code in _ABSENT:
            return True
        if code not in ("AccessDenied", "403"):
            return False
        try:
            page = self._client.list_objects_v2(Bucket=self.bucket, Prefix=key, MaxKeys=1)
        except Exception:  # noqa: BLE001 - the list's own denial answers it
            return False
        return not any(o.get("Key") == key for o in page.get("Contents") or [])

    def _get_optional(self, key: str, what: str) -> bytes | None:
        """None only for an object that is not there. Any other error is
        logged: an access-denied marker read as "no marker" would hide a
        misconfigured role behind a dashboard that looks fine."""
        try:
            return self._get(key)
        except Exception as exc:  # noqa: BLE001 - botocore raises a family
            if self._absent(key, exc):
                return None
            log.warning("could not read the %s from the store", what, extra={
                "fields": {"error": type(exc).__name__, "code": _code(exc)}})
            return None

    def set_reset_marker(self, when: str) -> None:
        self._client.put_object(Bucket=self.bucket, Key=self._full(RESET_MARKER),
                                Body=when.encode("utf-8"))

    def get_reset_marker(self) -> str | None:
        raw = self._get_optional(self._full(RESET_MARKER), "reset marker")
        return (raw.decode("utf-8").strip() or None) if raw is not None else None

    def set_excluded(self, request_ids) -> None:
        body = "\n".join(sorted(set(request_ids))).encode("utf-8")
        self._client.put_object(Bucket=self.bucket, Key=self._full(EXCLUDE_MARKER), Body=body)

    def get_excluded(self) -> set[str]:
        raw = self._get_optional(self._full(EXCLUDE_MARKER), "exclusion marker")
        if raw is None:
            return set()
        return {ln.strip() for ln in raw.decode("utf-8").splitlines() if ln.strip()}

    # -- durable state ----------------------------------------------------

    def put_state(self, name: str, blob: bytes) -> None:
        # The one mutable object kind, so no If-None-Match here.
        self._client.put_object(Bucket=self.bucket, Key=self._state_key(name), Body=blob)

    def get_state(self, name: str) -> bytes | None:
        """None on a first run. Any other failure RAISES: a cursor that
        could not be read is not a first run, and treating it as one would
        rescan the whole window and report it as success."""
        key = self._state_key(name)
        try:
            return self._get(key)
        except Exception as exc:  # noqa: BLE001 - botocore raises a family
            if self._absent(key, exc):
                return None
            raise

    def _state_key(self, name: str) -> str:
        return self._full(f"{STATE_PREFIX}/{safe_state_name(name)}")

    # -- runtime overrides ------------------------------------------------

    def _control_key(self) -> str:
        return self._full(f"{STATE_PREFIX}/{CONTROL_STATE}")

    def read_control(self) -> ControlRead:
        key = self._control_key()
        try:
            response = self._client.get_object(Bucket=self.bucket, Key=key)
            body = response["Body"].read()
        except Exception as exc:  # noqa: BLE001 - botocore raises a family
            if self._absent(key, exc):
                return ABSENT
            raise StoreReadError(type(exc).__name__) from exc
        return ControlRead("ok", body, str(response.get("ETag") or ""))

    def write_control(self, body: bytes, if_etag: str | None) -> None:
        key = self._control_key()
        condition = {"IfNoneMatch": "*"} if if_etag is None else {"IfMatch": if_etag}
        try:
            self._client.put_object(Bucket=self.bucket, Key=key, Body=body,
                                    ContentType="application/json", **condition)
        except Exception as exc:  # noqa: BLE001 - botocore raises a family
            code = _code(exc)
            # If-Match on an object deleted since it was read answers 404.
            if code in _CONFLICT or (if_etag is not None and code in _ABSENT):
                if self._already_written(key, body):
                    return
                raise StoreConflict("runtime overrides object changed") from exc
            if code in _DENIED:
                raise StoreForbidden("the runtime overrides object") from exc
            raise

    def _audit_key(self, name: str) -> str:
        return self._full(f"{AUDIT_PREFIX}/{safe_audit_name(name)}")

    def put_audit(self, name: str, body: bytes) -> None:
        key = self._audit_key(name)
        try:
            self._client.put_object(Bucket=self.bucket, Key=key, Body=body,
                                    IfNoneMatch="*", ContentType="application/json")
        except Exception as exc:  # noqa: BLE001 - botocore raises a family
            if _code(exc) in _CONFLICT:
                if self._already_written(key, body):
                    return
                raise StoreConflict(f"audit record exists: {name}") from exc
            if _code(exc) in _DENIED:
                raise StoreForbidden("the runtime overrides audit prefix") from exc
            raise

    def get_audit(self, name: str) -> bytes | None:
        key = self._audit_key(name)
        try:
            return self._get(key)
        except Exception as exc:  # noqa: BLE001 - botocore raises a family
            if self._absent(key, exc):
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
        region = getattr(getattr(self._client, "meta", None), "region_name", None)
        return {
            "backend": "s3",
            "bucket": self.bucket,
            "prefix": self.prefix,
            "region": region,
            "instance": self.instance,
            "reset_at": self.get_reset_marker(),
        }


__all__ = ["S3Store"]
