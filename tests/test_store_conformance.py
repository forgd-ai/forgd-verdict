"""One suite of assertions run against every Store backend.

`tests/test_store.py` exercises LocalFileStore only, so BlobStore's half of
the protocol -- org pruning, `since`, the markers, batching -- was covered by
reading it rather than by running it. The two implementations are separate
code that must agree; this file pins the agreement.

The blob half runs with no `azure` package installed and no credential of any
kind. `BlobStore.__init__` imports azure lazily, so the fixture puts inert
stub modules in `sys.modules` first and the real `__init__` then builds its
client through them: URL parsing, prefix handling and the instance id are the
shipped code, only the container underneath is a dict. Constructing the store
by hand with `object.__new__` would have skipped exactly the part of
`__init__` most likely to drift from the local store.

The fake container records which objects were downloaded, and the local
backend records the same thing by watching `Path.read_bytes`, so "an
org-scoped read never opens another org's object" is asserted rather than
assumed. Those assertions compare against the full expected list, not against
emptiness: a recorder that silently stopped recording would fail them.
"""

from __future__ import annotations

import hashlib
import json
import pathlib
import sys
import threading
import types
from contextlib import contextmanager, suppress
from datetime import UTC, date, datetime, timedelta
from pathlib import Path

import pytest

from forgd_verdict.store import (
    SOURCE_COMPLIANCE_SCAN,
    SOURCE_INFERENCE_HOOK,
    DenialRecord,
    FindingRow,
    LocalFileStore,
    VerdictRecord,
)
from forgd_verdict.store.base import EXCLUDE_MARKER, ORG_UNATTRIBUTED, RESET_MARKER

BLOB_URL = "https://acct.blob.core.windows.net/findings/demo"
BLOB_PREFIX = "demo"
S3_URL = "s3://forgd-findings/demo"
GCS_URL = "gs://forgd-findings/demo"


class _ServerClock:
    """The cloud fakes' time: this machine's, moved by `offset`."""

    offset = timedelta(0)

    def now(self) -> datetime:
        return datetime.now(UTC) + self.offset


SERVER_TIME = _ServerClock()


def _write_denied(denied: set[str], key: str) -> bool:
    """Whether a `deny_write` entry covers `key`: the key itself, or a prefix
    ending in "/"."""
    return any(d.startswith("write:") and (d[6:] == key or (d.endswith("/")
                                                          and key.startswith(d[6:])))
               for d in denied)


def rec(
    source: str = SOURCE_INFERENCE_HOOK,
    action: str = "allow",
    day: str = "2026-09-17",
    findings: tuple[FindingRow, ...] = (),
    **kw,
) -> VerdictRecord:
    return VerdictRecord(
        source=source,
        observed_at=f"{day}T10:00:00Z",
        surface="claude-ai",
        action=action,
        findings=list(findings),
        findings_count=len(findings),
        **kw,
    )


def den(day: str = "2026-09-17", **kw) -> DenialRecord:
    kw.setdefault("activity_id", f"act-{day}")
    return DenialRecord(created_at=f"{day}T10:00:00Z", **kw)


# -- the fake container ----------------------------------------------------


def _delimit(keys: list[str], prefix: str, delimiter: str | None) -> tuple[list[str], list[str]]:
    """`keys` split as a delimited listing of `prefix` returns them: the keys
    one level below it, and the sorted common prefixes, each ending in
    `delimiter`, that roll up everything deeper."""
    if not delimiter:
        return keys, []
    direct, rolled = [], set()
    for key in keys:
        rest = key[len(prefix):]
        if delimiter in rest:
            rolled.add(prefix + rest[:rest.index(delimiter) + 1])
        else:
            direct.append(key)
    return direct, sorted(rolled)


def _log_list(client, prefix: str | None, delimited: bool, returned: int) -> None:
    if client.list_log is not None:
        client.list_log.append((prefix or "", delimited, returned))


def _etag(data: bytes) -> str:
    return '"' + hashlib.sha256(data).hexdigest()[:16] + '"'


class _AzureError(Exception):
    """azure.core's HttpResponseError shape: the status is `status_code`."""

    def __init__(self, status: int, message: str = ""):
        super().__init__(message or str(status))
        self.status_code = status


class ResourceNotFoundError(_AzureError, KeyError):
    def __init__(self, name: str):
        super().__init__(404, name)


class ResourceExistsError(_AzureError, FileExistsError):
    def __init__(self, name: str):
        super().__init__(409, f"blob already exists: {name}")


class _FakeProperties:
    def __init__(self, etag: str):
        self.etag = etag
        self.last_modified = SERVER_TIME.now()


class _FakeDownload:
    def __init__(self, data: bytes):
        self._data = data
        self.properties = _FakeProperties(_etag(data))

    def readall(self) -> bytes:
        return self._data


class _FakeBlobProperties:
    def __init__(self, name: str):
        self.name = name


class _FakeBlobPrefix:
    """azure.storage.blob's BlobPrefix: `name` is the prefix, ending in the
    delimiter."""

    def __init__(self, name: str):
        self.name = name
        self.prefix = name


class FakeContainerClient:
    """Enough of azure.storage.blob.ContainerClient for the store to run.

    `overwrite=False` raises, because the blob store's whole concurrency
    story is that objects are immutable and two writers therefore never need
    to coordinate. A fake that silently overwrote would make the concurrent
    writer test pass while losing records.
    """

    def __init__(self, blobs: dict[str, bytes], lock: threading.Lock, kwargs: dict,
                 denied: set[str] | None = None):
        self.blobs = blobs
        self.kwargs = kwargs
        self._lock = lock
        self.download_log: list[str] | None = None
        self.list_log: list[tuple[str, bool, int]] | None = None
        self.denied = denied if denied is not None else set()

    def upload_blob(self, name: str, data: bytes, overwrite: bool = False,
                    etag: str | None = None, match_condition=None) -> None:
        with self._lock:
            if _write_denied(self.denied, name):
                raise _AzureError(403, "AuthorizationPermissionMismatch")
            if etag is not None:
                assert match_condition is not None, "an etag without a match condition"
                if name not in self.blobs or _etag(self.blobs[name]) != etag:
                    raise _AzureError(412, "ResourceModifiedError")
            elif name in self.blobs and not overwrite:
                raise ResourceExistsError(name)
            self.blobs[name] = bytes(data)

    def list_blobs(self, name_starts_with: str | None = None):
        with self._lock:
            names = sorted(n for n in self.blobs
                           if name_starts_with is None or n.startswith(name_starts_with))
        _log_list(self, name_starts_with, False, len(names))
        for name in names:
            yield _FakeBlobProperties(name)

    def walk_blobs(self, name_starts_with: str | None = None, delimiter: str = "/"):
        prefix = name_starts_with or ""
        with self._lock:
            names = sorted(n for n in self.blobs if n.startswith(prefix))
        keys, prefixes = _delimit(names, prefix, delimiter)
        _log_list(self, prefix, True, len(keys) + len(prefixes))
        items = [_FakeBlobProperties(k) for k in keys] + [_FakeBlobPrefix(p) for p in prefixes]
        yield from sorted(items, key=lambda item: item.name)

    def download_blob(self, name: str) -> _FakeDownload:
        with self._lock:
            if name in self.denied:
                raise _AzureError(403, "AuthorizationPermissionMismatch")
            if name not in self.blobs:
                raise ResourceNotFoundError(name)
            data = self.blobs[name]
        if self.download_log is not None:
            self.download_log.append(name)
        return _FakeDownload(data)


class _InertCredential:
    """Stands in for the azure.identity credentials. Holds nothing and
    reaches nowhere; its presence is what the injection test checks."""

    def __init__(self, *args, **kwargs):
        self.args = args
        self.kwargs = kwargs


# -- backends --------------------------------------------------------------


class LocalBackend:
    name = "local"

    def __init__(self, tmp_path: Path):
        self.root = tmp_path

    def make_store(self, instance: str) -> LocalFileStore:
        return LocalFileStore(self.root, instance=instance)

    def put_raw(self, rel: str, body: str) -> None:
        path = self.root / rel
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(body, encoding="utf-8")

    def objects(self) -> list[str]:
        return sorted(
            p.relative_to(self.root).as_posix() for p in self.root.rglob("*.jsonl")
        )

    def all_objects(self) -> list[str]:
        """Every file, not just records. `objects()` filters to *.jsonl, so a
        backend that wrote a temporary or metadata object alongside was
        invisible to any assertion that nothing was written."""
        return sorted(
            p.relative_to(self.root).as_posix()
            for p in self.root.rglob("*")
            if p.is_file()
        )

    def raw(self, rel: str) -> str:
        return (self.root / rel).read_text(encoding="utf-8")

    def exists(self, rel: str) -> bool:
        return (self.root / rel).exists()

    def deny(self, rel: str) -> None:
        """Make the file at `rel` unreadable, as a missing grant would."""
        path = self.root / rel
        path.parent.mkdir(parents=True, exist_ok=True)
        if not path.exists():
            path.write_bytes(b"")
        path.chmod(0)

    @contextmanager
    def record_reads(self):
        """Names of the objects whose bytes were actually fetched.

        Patches `Path.read_bytes` because that is what LocalFileStore reads
        record objects with. If the store stopped using it the list would go
        empty, which the call sites catch by comparing against the full
        expected list rather than against a count.
        """
        seen: list[str] = []
        root = self.root
        original = Path.read_bytes

        def spy(path: Path) -> bytes:
            # Anything outside the root is not a record object.
            with suppress(ValueError):
                seen.append(path.relative_to(root).as_posix())
            return original(path)

        Path.read_bytes = spy  # type: ignore[method-assign]
        try:
            yield seen
        finally:
            Path.read_bytes = original  # type: ignore[method-assign]

    @contextmanager
    def record_lists(self):
        """Each directory enumerated, as `(rel/, True, entries)`: one level,
        as a delimited listing is.

        `glob` binds `os.scandir` when it is imported, so `Path.rglob` is
        caught by patching its globber as well as `os`.
        """
        import glob
        import os

        seen: list[tuple[str, bool, int]] = []
        root = self.root
        original = os.scandir

        class _Listed:
            def __init__(self, entries):
                self._entries = entries

            def __enter__(self):
                return self

            def __exit__(self, *exc):
                return False

            def __iter__(self):
                return iter(self._entries)

            def close(self):
                pass

        def spy(path="."):
            with original(path) as it:
                entries = list(it)
            with suppress(ValueError):
                rel = Path(os.fsdecode(path)).relative_to(root).as_posix()
                seen.append((rel + "/", True, len(entries)))
            return _Listed(entries)

        # From Python 3.13 glob lists through _StringGlobber.scandir, a
        # reference to os.scandir taken at import; before, it calls os.scandir.
        globber = getattr(glob, "_StringGlobber", None)
        previous = globber.__dict__["scandir"] if globber is not None else None
        os.scandir = spy
        if globber is not None:
            globber.scandir = staticmethod(spy)
        try:
            yield seen
        finally:
            os.scandir = original
            if globber is not None:
                globber.scandir = previous


class BlobBackend:
    name = "blob"

    def __init__(self, blobs: dict[str, bytes], lock: threading.Lock, clients: list,
                 denied: set[str] | None = None):
        self.blobs = blobs
        self._lock = lock
        self.clients = clients
        # Keys whose reads the fake refuses with a denial, as a role without
        # read on them would.
        self.denied = denied if denied is not None else set()

    def deny(self, rel: str) -> None:
        self.denied.add(self._key(rel))

    def deny_write(self, rel: str) -> None:
        """Refuse writes to `rel` with a denial, as a role without write would."""
        self.denied.add(f"write:{self._key(rel)}")

    def _key(self, rel: str) -> str:
        return f"{BLOB_PREFIX}/{rel}"

    def make_store(self, instance: str):
        from forgd_verdict.store.blob import BlobStore

        return BlobStore(BLOB_URL, instance=instance)

    def put_raw(self, rel: str, body: str) -> None:
        with self._lock:
            self.blobs[self._key(rel)] = body.encode("utf-8")

    def objects(self) -> list[str]:
        with self._lock:
            return sorted(
                name[len(BLOB_PREFIX) + 1 :]
                for name in self.blobs
                if name.endswith(".jsonl")
            )

    def all_objects(self) -> list[str]:
        """See LocalBackend.all_objects."""
        with self._lock:
            return sorted(
                name[len(BLOB_PREFIX) + 1 :] if name.startswith(BLOB_PREFIX + "/")
                else name
                for name in self.blobs
            )

    def raw(self, rel: str) -> str:
        return self.blobs[self._key(rel)].decode("utf-8")

    def exists(self, rel: str) -> bool:
        return self._key(rel) in self.blobs

    @contextmanager
    def record_reads(self):
        seen: list[str] = []
        for client in self.clients:
            client.download_log = seen
        try:
            yield seen
        finally:
            for client in self.clients:
                client.download_log = None
        # Reported store-relative so both backends assert the same strings.
        seen[:] = [n[len(BLOB_PREFIX) + 1 :] if n.startswith(BLOB_PREFIX + "/") else n for n in seen]

    @contextmanager
    def record_lists(self):
        """Each listing as `(prefix, delimited, names returned)`, the prefix
        store-relative."""
        seen: list[tuple[str, bool, int]] = []
        for client in self.clients:
            client.list_log = seen
        try:
            yield seen
        finally:
            for client in self.clients:
                client.list_log = None
        cut = len(BLOB_PREFIX) + 1
        seen[:] = [(p[cut:] if p.startswith(BLOB_PREFIX + "/") else p, d, n)
                   for p, d, n in seen]


def _install_fake_azure(monkeypatch) -> BlobBackend:
    """Put inert azure modules in `sys.modules` so BlobStore's lazy import
    finds them, and hand back a backend over the dict they write to."""
    # Container Apps sets neither of these in a test run, but a developer
    # machine might; both change what BlobStore.__init__ builds.
    monkeypatch.delenv("AZURE_CLIENT_ID", raising=False)
    monkeypatch.delenv("CONTAINER_APP_REPLICA_NAME", raising=False)

    blobs: dict[str, bytes] = {}
    lock = threading.Lock()
    clients: list[FakeContainerClient] = []
    denied: set[str] = set()

    def container_client(**kwargs):
        client = FakeContainerClient(blobs, lock, kwargs, denied)
        clients.append(client)
        return client

    identity = types.ModuleType("azure.identity")
    identity.DefaultAzureCredential = _InertCredential
    identity.ManagedIdentityCredential = _InertCredential
    blob_mod = types.ModuleType("azure.storage.blob")
    blob_mod.ContainerClient = container_client
    storage = types.ModuleType("azure.storage")
    storage.blob = blob_mod
    core = types.ModuleType("azure.core")
    core.MatchConditions = types.SimpleNamespace(IfNotModified="IfNotModified")
    azure = types.ModuleType("azure")
    azure.identity = identity
    azure.storage = storage
    azure.core = core

    for name, mod in (
        ("azure", azure),
        ("azure.core", core),
        ("azure.identity", identity),
        ("azure.storage", storage),
        ("azure.storage.blob", blob_mod),
    ):
        monkeypatch.setitem(sys.modules, name, mod)

    return BlobBackend(blobs, lock, clients, denied)


class _S3Error(Exception):
    """botocore's ClientError shape: the code is in `response`."""

    def __init__(self, code: str):
        super().__init__(code)
        self.response = {"Error": {"Code": code}}


class _S3Body:
    def __init__(self, data: bytes):
        self._data = data

    def read(self) -> bytes:
        return self._data


class FakeS3Client:
    """Enough of boto3's S3 client for the store to run.

    `IfNoneMatch="*"` on an existing key raises PreconditionFailed, as S3
    does, for the reason FakeContainerClient raises on overwrite=False. There
    is deliberately no delete method: the store calling one fails the test.
    Listing pages two keys at a time, so pagination is exercised.
    """

    PAGE_SIZE = 2

    def __init__(self, objects: dict[str, bytes], lock: threading.Lock, kwargs: dict,
                 denied: set[str] | None = None):
        self.objects = objects
        self.kwargs = kwargs
        self._lock = lock
        self.download_log: list[str] | None = None
        self.list_log: list[tuple[str, bool, int]] | None = None
        self.puts: list[dict] = []
        self.denied = denied if denied is not None else set()

    def put_object(self, Bucket, Key, Body, IfNoneMatch=None, IfMatch=None, **kw):  # noqa: N803
        with self._lock:
            self.puts.append({"Bucket": Bucket, "Key": Key, "IfNoneMatch": IfNoneMatch,
                              "IfMatch": IfMatch})
            if _write_denied(self.denied, Key):
                raise _S3Error("AccessDenied")
            if IfNoneMatch == "*" and Key in self.objects:
                raise _S3Error("PreconditionFailed")
            if IfMatch is not None:
                if Key not in self.objects:
                    raise _S3Error("NoSuchKey")
                if _etag(self.objects[Key]) != IfMatch:
                    raise _S3Error("PreconditionFailed")
            self.objects[Key] = bytes(Body)

    def head_object(self, Bucket, Key):  # noqa: N803
        with self._lock:
            if Key not in self.objects:
                raise _S3Error("NoSuchKey")
            return {"ETag": _etag(self.objects[Key]), "LastModified": SERVER_TIME.now()}

    def get_object(self, Bucket, Key):  # noqa: N803
        with self._lock:
            if Key in self.denied:
                raise _S3Error("AccessDenied")
            if Key not in self.objects:
                raise _S3Error("NoSuchKey")
            data = self.objects[Key]
        if self.download_log is not None:
            self.download_log.append(Key)
        return {"Body": _S3Body(data), "ETag": _etag(data)}

    def list_objects_v2(self, Bucket, Prefix="", MaxKeys=1000):  # noqa: N803
        with self._lock:
            keys = sorted(k for k in self.objects if k.startswith(Prefix))[:MaxKeys]
        return {"Contents": [{"Key": k} for k in keys]} if keys else {"KeyCount": 0}

    def get_paginator(self, name: str):
        assert name == "list_objects_v2"
        client = self

        class _Pages:
            def paginate(self, Bucket, Prefix="", Delimiter=None):  # noqa: N803
                with client._lock:
                    keys = sorted(k for k in client.objects if k.startswith(Prefix))
                keys, prefixes = _delimit(keys, Prefix, Delimiter)
                _log_list(client, Prefix, bool(Delimiter), len(keys) + len(prefixes))
                items = sorted([(k, False) for k in keys] + [(p, True) for p in prefixes])
                size = client.PAGE_SIZE
                for i in range(0, max(len(items), 1), size):
                    chunk = items[i:i + size]
                    page = {}
                    if any(not rolled for _, rolled in chunk):
                        page["Contents"] = [{"Key": k} for k, rolled in chunk if not rolled]
                    if any(rolled for _, rolled in chunk):
                        page["CommonPrefixes"] = [{"Prefix": p} for p, rolled in chunk if rolled]
                    yield page
        return _Pages()


class S3Backend(BlobBackend):
    """The blob backend's helpers over the fake bucket's key dict."""

    name = "s3"

    def make_store(self, instance: str):
        from forgd_verdict.store.s3 import S3Store

        return S3Store(S3_URL, instance=instance)


def _install_fake_boto3(monkeypatch) -> S3Backend:
    objects: dict[str, bytes] = {}
    lock = threading.Lock()
    clients: list[FakeS3Client] = []
    denied: set[str] = set()

    def client(service, **kwargs):
        assert service == "s3"
        c = FakeS3Client(objects, lock, kwargs, denied)
        clients.append(c)
        return c

    boto3 = types.ModuleType("boto3")
    boto3.client = client
    config_mod = types.ModuleType("botocore.config")
    config_mod.Config = _InertCredential
    botocore = types.ModuleType("botocore")
    botocore.config = config_mod
    for name, mod in (("boto3", boto3), ("botocore", botocore),
                      ("botocore.config", config_mod)):
        monkeypatch.setitem(sys.modules, name, mod)
    return S3Backend(objects, lock, clients, denied)


class _GCSError(Exception):
    """google.api_core's error shape: the HTTP status is `code`."""

    def __init__(self, code: int):
        super().__init__(str(code))
        self.code = code


class _FakeRetry:
    """google.api_core's Retry, as far as the store uses it."""

    def __init__(self, timeout: float | None = None):
        self.timeout = timeout

    def with_timeout(self, timeout: float) -> _FakeRetry:
        return _FakeRetry(timeout)


class _FakeListedBlob:
    def __init__(self, name: str):
        self.name = name


class _FakeGCSBlob:
    def __init__(self, client: FakeGCSClient, name: str, generation: int | None = None):
        self._client = client
        self.name = name
        self.generation = generation
        self.updated = SERVER_TIME.now() if generation is not None else None

    def upload_from_string(self, data, content_type="text/plain",
                           if_generation_match=None, **kw):
        c = self._client
        c.calls.append(("upload", self.name, {**kw, "if_generation_match": if_generation_match}))
        with c._lock:
            if _write_denied(c.denied, self.name):
                raise _GCSError(403)
            current = c.generations.get(self.name) if self.name in c.objects else None
            if if_generation_match == 0 and current is not None:
                raise _GCSError(412)
            if if_generation_match not in (None, 0) and current != if_generation_match:
                raise _GCSError(412)
            c.objects[self.name] = bytes(data)
            c.generations[self.name] = c.generations.get(self.name, 0) + 1

    def download_as_bytes(self, if_generation_match=None, **kw) -> bytes:
        c = self._client
        c.calls.append(("download", self.name, kw))
        with c._lock:
            if self.name in c.denied:
                raise _GCSError(403)
            if self.name not in c.objects:
                raise _GCSError(404)
            if (if_generation_match is not None
                    and c.generations.get(self.name) != if_generation_match):
                raise _GCSError(412)
            data = c.objects[self.name]
        if c.download_log is not None:
            c.download_log.append(self.name)
        return data


class _FakeGCSBucket:
    def __init__(self, client: FakeGCSClient, name: str):
        self._client = client
        self.name = name

    def blob(self, name: str) -> _FakeGCSBlob:
        return _FakeGCSBlob(self._client, name)

    def get_blob(self, name: str, **kw) -> _FakeGCSBlob | None:
        c = self._client
        c.calls.append(("get_blob", name, kw))
        with c._lock:
            if name in c.denied:
                raise _GCSError(403)
            if name not in c.objects:
                return None
            return _FakeGCSBlob(c, name, c.generations.get(name, 1))


class FakeGCSClient:
    """Enough of google-cloud-storage's Client for the store to run.

    `if_generation_match=0` on an existing object raises 412, as GCS does, for
    the reason FakeContainerClient raises on overwrite=False. There is
    deliberately no delete method. Listing pages two objects at a time and
    counts the pages it serves. Every call is recorded with its keyword
    arguments, so the timeout and retry on each can be asserted.
    """

    PAGE_SIZE = 2

    def __init__(self, objects: dict[str, bytes], lock: threading.Lock, kwargs: dict,
                 generations: dict[str, int] | None = None,
                 denied: set[str] | None = None):
        self.objects = objects
        self.kwargs = kwargs
        self._lock = lock
        self.download_log: list[str] | None = None
        self.list_log: list[tuple[str, bool, int]] | None = None
        self.calls: list[tuple[str, str, dict]] = []
        self.pages_served = 0
        self.generations = generations if generations is not None else {}
        self.denied = denied if denied is not None else set()

    def bucket(self, name: str) -> _FakeGCSBucket:
        return _FakeGCSBucket(self, name)

    def list_blobs(self, bucket_or_name, prefix=None, delimiter=None, **kw):
        self.calls.append(("list", prefix, kw))
        return _FakeGCSListing(self, prefix or "", delimiter)


class _FakeGCSListing:
    """google-cloud-storage's blob iterator: yields the blobs, and fills
    `prefixes` with the common prefixes of each page as it is fetched."""

    def __init__(self, client: FakeGCSClient, prefix: str, delimiter: str | None):
        self._client = client
        self._prefix = prefix
        self._delimiter = delimiter
        self.prefixes: set[str] = set()

    def __iter__(self):
        c = self._client
        with c._lock:
            keys = sorted(k for k in c.objects if k.startswith(self._prefix))
        keys, prefixes = _delimit(keys, self._prefix, self._delimiter)
        _log_list(c, self._prefix, bool(self._delimiter), len(keys) + len(prefixes))
        items = sorted([(k, False) for k in keys] + [(p, True) for p in prefixes])
        for i in range(0, len(items), c.PAGE_SIZE):
            c.pages_served += 1
            chunk = items[i:i + c.PAGE_SIZE]
            self.prefixes.update(p for p, rolled in chunk if rolled)
            for k, rolled in chunk:
                if not rolled:
                    yield _FakeListedBlob(k)


class GCSBackend(BlobBackend):
    """The blob backend's helpers over the fake bucket's object dict."""

    name = "gcs"

    def make_store(self, instance: str):
        from forgd_verdict.store.gcs import GCSStore

        return GCSStore(GCS_URL, instance=instance)


def _install_fake_gcs(monkeypatch) -> GCSBackend:
    objects: dict[str, bytes] = {}
    lock = threading.Lock()
    clients: list[FakeGCSClient] = []
    generations: dict[str, int] = {}
    denied: set[str] = set()

    def client(**kwargs):
        c = FakeGCSClient(objects, lock, kwargs, generations, denied)
        clients.append(c)
        return c

    retry_mod = types.ModuleType("google.cloud.storage.retry")
    retry_mod.DEFAULT_RETRY = _FakeRetry(timeout=120.0)
    storage = types.ModuleType("google.cloud.storage")
    storage.Client = client
    storage.retry = retry_mod
    cloud = types.ModuleType("google.cloud")
    cloud.storage = storage
    google = types.ModuleType("google")
    google.cloud = cloud
    for name, mod in (("google", google), ("google.cloud", cloud),
                      ("google.cloud.storage", storage),
                      ("google.cloud.storage.retry", retry_mod)):
        monkeypatch.setitem(sys.modules, name, mod)
    return GCSBackend(objects, lock, clients, denied)


BACKENDS = ("local", "blob", "s3", "gcs")


@pytest.fixture(params=BACKENDS)
def backend(request, tmp_path, monkeypatch):
    if request.param == "local":
        return LocalBackend(tmp_path)
    if request.param == "s3":
        return _install_fake_boto3(monkeypatch)
    if request.param == "gcs":
        return _install_fake_gcs(monkeypatch)
    return _install_fake_azure(monkeypatch)


@pytest.fixture
def blob_backend(monkeypatch) -> BlobBackend:
    return _install_fake_azure(monkeypatch)


# -- injection -------------------------------------------------------------


def test_blob_store_is_built_from_the_injected_client_with_no_credential(blob_backend):
    """The blob half of this suite is worthless if it quietly fell back to a
    real client. `azure` is not installed today, so that would raise -- but
    adding the extra to `dev` would make it succeed instead, and a test that
    only checked "it constructed" would then start walking the credential
    chain without anyone noticing."""
    store = blob_backend.make_store("t1")
    assert store._client is blob_backend.clients[-1]
    assert isinstance(store._client.kwargs["credential"], _InertCredential)
    assert store._client.kwargs["container_name"] == "findings"
    assert store.prefix == BLOB_PREFIX
    assert store.account_url == "https://acct.blob.core.windows.net"
    assert store.identity == "default-chain"


def test_the_suite_covers_both_backends():
    """Guards against a future skip quietly halving this file. A skipped case
    still reads as green in most summaries, and the blob half is the half
    that would go: it is the one with an optional dependency behind it.

    Both halves of the check matter. The first reads the fixture's params
    through a pytest internal, so it is asserted rather than assumed that
    both cases are generated; the second scans this file's own source,
    because that survives pytest moving the attribute.
    """
    marker = getattr(backend, "_fixture_function_marker", None) or getattr(
        backend, "_pytestfixturefunction", None
    )
    assert marker is not None, "cannot read fixture params on this pytest version"

    # Written out, NOT compared against BACKENDS. The fixture is parametrised
    # from that constant, so comparing the two asserted that a variable equals
    # itself: setting BACKENDS = ("local",) halved this file from 76 tests to
    # 39 and left every one of them green.
    assert set(marker.params) == {"local", "blob", "s3", "gcs"}, (
        "a backend disappeared from the suite; every case for it silently "
        "stopped running while the summary stayed green"
    )

    # Assembled rather than written out, so the scan does not match itself.
    source = pathlib.Path(__file__).read_text(encoding="utf-8")
    for token in ("pytest." + "skip", "import" + "orskip", "skip" + "if"):
        assert token not in source, f"{token} would silently drop a backend"


# -- round trips -----------------------------------------------------------


def test_verdict_round_trip(backend):
    store = backend.make_store("t1")
    written = store.write_verdicts([
        rec(request_id="a"),
        rec(request_id="b", action="deny", reference_id="ref-1"),
        rec(request_id="c", source=SOURCE_COMPLIANCE_SCAN, session_id="sess-1"),
    ])
    assert written == 3

    back = {r.request_id: r for r in backend.make_store("reader").read_verdicts()}
    assert set(back) == {"a", "b", "c"}
    assert back["b"].action == "deny"
    assert back["b"].reference_id == "ref-1"
    assert back["c"].source == SOURCE_COMPLIANCE_SCAN
    assert back["c"].session_id == "sess-1"


def test_findings_survive_the_round_trip(backend):
    store = backend.make_store("t1")
    store.write_verdicts([
        rec(
            request_id="a",
            action="deny",
            findings=(
                FindingRow("aws_key", "block", "messages[0].content", "sha256:abcd"),
                FindingRow("ssn", "warn", "messages[1].content", "sha256:ef01", "Bash"),
            ),
        )
    ])
    # A fresh reader: reading through the writer would let a backend that
    # buffers in memory return intact findings it never persisted.
    (back,) = list(backend.make_store("reader").read_verdicts())
    assert back.findings_count == 2
    assert [f.detector for f in back.findings] == ["aws_key", "ssn"]
    assert back.findings[1].tool_name == "Bash"
    assert back.detected and back.flagged
    assert back.disposition == "deny"


def test_denial_round_trip(backend):
    store = backend.make_store("t1")
    assert store.write_denials([
        den(activity_id="act-1", reference_id="ref-1", tenant_hash="org_aaa"),
        den(activity_id="act-2"),
    ]) == 2

    back = {d.activity_id: d for d in backend.make_store("reader").read_denials()}
    assert set(back) == {"act-1", "act-2"}
    assert back["act-1"].reference_id == "ref-1"
    assert back["act-1"].org == "org_aaa"
    assert back["act-2"].org == ORG_UNATTRIBUTED


def test_verdicts_and_denials_do_not_bleed_into_each_other(backend):
    store = backend.make_store("t1")
    store.write_verdicts([rec(request_id="a")])
    store.write_denials([den(activity_id="act-1")])
    assert [r.request_id for r in store.read_verdicts()] == ["a"]
    assert [d.activity_id for d in store.read_denials()] == ["act-1"]


def test_a_sibling_prefix_is_not_read_as_the_store(backend):
    """List prefixes are character prefixes, so `verdicts` would also match
    a `verdicts-backup/` beside it, and a copy left there during a migration
    would be read into the dashboard as live records."""
    store = backend.make_store("t1")
    store.write_verdicts([rec(request_id="live")])
    stray = rec(request_id="stray").to_json()
    backend.put_raw("verdicts-backup/source=inference_hook/date=2026-09-17/x.jsonl",
                    stray + "\n")
    backend.put_raw("denials2/date=2026-09-17/x.jsonl", stray + "\n")
    assert [r.request_id for r in store.read_verdicts()] == ["live"]
    assert list(store.read_denials()) == []


def test_an_empty_batch_writes_nothing(backend):
    store = backend.make_store("t1")
    assert store.write_verdicts([]) == 0
    assert store.write_denials([]) == 0
    # all_objects, not objects: the latter filters to *.jsonl, so a backend
    # that wrote a temporary or metadata object alongside passed this.
    assert backend.all_objects() == []


def test_an_empty_store_reads_as_empty_rather_than_raising(backend):
    store = backend.make_store("t1")
    assert list(store.read_verdicts()) == []
    assert list(store.read_denials()) == []


# -- since -----------------------------------------------------------------


def test_since_prunes_by_partition_without_opening_the_old_object(backend):
    store = backend.make_store("t1")
    store.write_verdicts([
        rec(day="2026-09-01", request_id="ancient"),
        rec(day="2026-09-17", request_id="recent"),
    ])
    with backend.record_reads() as read:
        assert {r.request_id for r in store.read_verdicts(since="2026-09-10")} == {"recent"}
    assert len(read) == 1, read
    assert "date=2026-09-17" in read[0]


def test_since_is_inclusive_of_its_own_day(backend):
    store = backend.make_store("t1")
    store.write_verdicts([rec(day="2026-09-17", request_id="same-day")])
    assert [r.request_id for r in store.read_verdicts(since="2026-09-17")] == ["same-day"]
    assert [r.request_id for r in store.read_verdicts(since="2026-09-17T23:59:59Z")] == ["same-day"]


def test_since_prunes_denials_too(backend):
    """Asserting only the returned ids let a backend download every object
    and filter afterwards -- which is filtering, not pruning, and the
    difference is whether another day's data is fetched at all. The verdict
    side already checked downloads; this did not."""
    store = backend.make_store("t1")
    store.write_denials([den(day="2026-09-01", activity_id="old"), den(day="2026-09-17", activity_id="new")])
    with backend.record_reads() as fetched:
        assert [d.activity_id for d in store.read_denials(since="2026-09-10")] == ["new"]
    assert not any("date=2026-09-01" in name for name in fetched), fetched


# -- org partitioning ------------------------------------------------------


def test_a_batch_spanning_orgs_is_split_into_one_object_per_org(backend):
    store = backend.make_store("t1")
    store.write_verdicts([
        rec(request_id="a", tenant_hash="org_aaa"),
        rec(request_id="b", tenant_hash="org_bbb"),
        rec(request_id="c"),
    ])
    objects = backend.objects()
    assert len(objects) == 3, objects
    assert sum("org=org_aaa" in o for o in objects) == 1
    assert sum("org=org_bbb" in o for o in objects) == 1
    assert sum(f"org={ORG_UNATTRIBUTED}" in o for o in objects) == 1


def test_an_org_scoped_read_never_downloads_another_orgs_object(backend):
    """The difference between a partition and a WHERE clause. Filtering after
    the read would return the same records and still have fetched the other
    org's data."""
    store = backend.make_store("t1")
    store.write_verdicts([
        rec(request_id="a", tenant_hash="org_aaa"),
        rec(request_id="b", tenant_hash="org_bbb"),
        rec(request_id="c", tenant_hash="org_ccc"),
        rec(request_id="d"),
    ])
    with backend.record_reads() as read:
        assert [r.request_id for r in store.read_verdicts(orgs={"org_aaa"})] == ["a"]
    assert len(read) == 1, read
    assert "org=org_aaa" in read[0]
    assert not any("org_bbb" in n or "org_ccc" in n or ORG_UNATTRIBUTED in n for n in read)


def test_a_viewer_entitled_to_several_orgs_reads_exactly_those(backend):
    store = backend.make_store("t1")
    store.write_verdicts([
        rec(request_id="a", tenant_hash="org_aaa"),
        rec(request_id="b", tenant_hash="org_bbb"),
        rec(request_id="c", tenant_hash="org_ccc"),
    ])
    with backend.record_reads() as read:
        got = {r.request_id for r in store.read_verdicts(orgs={"org_aaa", "org_bbb"})}
    assert got == {"a", "b"}
    assert len(read) == 2, read
    assert not any("org_ccc" in n for n in read)


def test_orgs_none_reads_every_partition(backend):
    store = backend.make_store("t1")
    store.write_verdicts([
        rec(request_id="a", tenant_hash="org_aaa"),
        rec(request_id="b"),
    ])
    assert {r.request_id for r in store.read_verdicts(orgs=None)} == {"a", "b"}


def test_an_empty_entitlement_reads_nothing_and_downloads_nothing(backend):
    """`orgs=None` is every org and `orgs=set()` is none of them. Collapsing
    the two would turn a viewer entitled to nothing into a viewer entitled to
    everything."""
    store = backend.make_store("t1")
    store.write_verdicts([rec(request_id="a", tenant_hash="org_aaa")])
    with backend.record_reads() as read:
        assert list(store.read_verdicts(orgs=set())) == []
    assert read == []


def test_org_pruning_applies_to_denials(backend):
    store = backend.make_store("t1")
    store.write_denials([
        den(activity_id="act-1", tenant_hash="org_aaa"),
        den(activity_id="act-2", tenant_hash="org_bbb"),
    ])
    with backend.record_reads() as read:
        assert [d.activity_id for d in store.read_denials(orgs={"org_aaa"})] == ["act-1"]
    assert len(read) == 1 and "org=org_aaa" in read[0]


def test_since_and_orgs_prune_together(backend):
    store = backend.make_store("t1")
    store.write_verdicts([
        rec(request_id="old-aaa", day="2026-09-01", tenant_hash="org_aaa"),
        rec(request_id="new-aaa", day="2026-09-17", tenant_hash="org_aaa"),
        rec(request_id="new-bbb", day="2026-09-17", tenant_hash="org_bbb"),
    ])
    with backend.record_reads() as read:
        got = [r.request_id for r in store.read_verdicts(since="2026-09-10", orgs={"org_aaa"})]
    assert got == ["new-aaa"]
    assert len(read) == 1, read


# -- the pre-multi-org layout ----------------------------------------------


LEGACY_DIR = "verdicts/source=inference_hook/date=2026-09-17"
LEGACY_DENIALS_DIR = "denials/source=denials/date=2026-09-17"


def test_objects_written_before_the_org_partition_read_as_unattributed(backend):
    """Objects written before multi-org have no `org=` segment at all. They
    must keep reading back, and must group with unattributed rather than
    appear as an extra tenant nobody configured."""
    backend.put_raw(
        f"{LEGACY_DIR}/legacy-000001.jsonl",
        rec(request_id="from-before").to_json() + "\n",
    )
    store = backend.make_store("t1")
    store.write_verdicts([rec(request_id="from-after")])

    assert {r.request_id for r in store.read_verdicts()} == {"from-before", "from-after"}
    assert {r.request_id for r in store.read_verdicts(orgs={ORG_UNATTRIBUTED})} == {
        "from-before",
        "from-after",
    }
    # Pruned on the name, not filtered after reading: a legacy object must
    # not be fetched at all for an org it cannot belong to.
    with backend.record_reads() as fetched:
        assert list(store.read_verdicts(orgs={"org_aaa"})) == []
    assert not any("legacy-000001" in name for name in fetched), fetched


def test_since_still_prunes_across_the_old_layout(backend):
    backend.put_raw(
        "verdicts/source=inference_hook/date=2026-09-01/legacy-000001.jsonl",
        rec(day="2026-09-01", request_id="ancient").to_json() + "\n",
    )
    store = backend.make_store("t1")
    store.write_verdicts([rec(day="2026-09-17", request_id="recent")])
    assert {r.request_id for r in store.read_verdicts(since="2026-09-10")} == {"recent"}


def test_legacy_denials_without_an_org_segment_read_as_unattributed(backend):
    """Denials got the org partition at the same time verdicts did, and they
    have their own prefix and their own reader. Covering only the verdict
    side would leave the denial reader free to regress on its own: a
    dashboard whose verdicts survived the upgrade and whose denials quietly
    vanished still renders, and reads as a week with no blocks.
    """
    backend.put_raw(
        f"{LEGACY_DENIALS_DIR}/legacy-000001.jsonl",
        den(activity_id="act-before").to_json() + "\n",
    )
    store = backend.make_store("t1")
    store.write_denials([den(activity_id="act-after")])

    assert {d.activity_id for d in store.read_denials()} == {"act-before", "act-after"}
    # The old object has no `org=` at all; it must group with unattributed
    # rather than surface as a tenant nobody configured.
    assert {d.activity_id for d in store.read_denials(orgs={ORG_UNATTRIBUTED})} == {
        "act-before",
        "act-after",
    }
    assert list(store.read_denials(orgs={"org_aaa"})) == []


def test_a_legacy_denial_is_not_downloaded_for_another_org(backend):
    backend.put_raw(
        f"{LEGACY_DENIALS_DIR}/legacy-000001.jsonl",
        den(activity_id="act-before").to_json() + "\n",
    )
    store = backend.make_store("t1")
    store.write_denials([den(activity_id="act-aaa", tenant_hash="org_aaa")])

    with backend.record_reads() as read:
        assert [d.activity_id for d in store.read_denials(orgs={"org_aaa"})] == ["act-aaa"]
    assert len(read) == 1, read
    assert "org=org_aaa" in read[0]
    assert not any("legacy" in name for name in read)


def test_since_still_prunes_legacy_denials(backend):
    backend.put_raw(
        "denials/source=denials/date=2026-09-01/legacy-000001.jsonl",
        den(day="2026-09-01", activity_id="ancient").to_json() + "\n",
    )
    backend.put_raw(
        f"{LEGACY_DENIALS_DIR}/legacy-000002.jsonl",
        den(day="2026-09-17", activity_id="recent-legacy").to_json() + "\n",
    )
    store = backend.make_store("t1")
    store.write_denials([den(day="2026-09-17", activity_id="recent")])

    with backend.record_reads() as read:
        got = {d.activity_id for d in store.read_denials(since="2026-09-10")}
    assert got == {"recent-legacy", "recent"}
    assert len(read) == 2, read
    assert not any("date=2026-09-01" in name for name in read)


def test_a_torn_final_line_does_not_kill_a_read(backend):
    backend.put_raw(
        f"{LEGACY_DIR}/legacy-000001.jsonl",
        rec(request_id="whole").to_json() + '\n{"source":"inference_hook","obse',
    )
    store = backend.make_store("t1")
    assert [r.request_id for r in store.read_verdicts()] == ["whole"]


def test_unknown_fields_from_a_newer_writer_are_tolerated(backend):
    raw = json.loads(rec(request_id="a").to_json())
    raw["some_future_field"] = {"nested": True}
    backend.put_raw(f"{LEGACY_DIR}/legacy-000001.jsonl", json.dumps(raw) + "\n")
    store = backend.make_store("t1")
    (back,) = list(store.read_verdicts())
    assert back.request_id == "a" and back.surface == "claude-ai"


# -- markers ---------------------------------------------------------------


def test_reset_marker_round_trip(backend):
    store = backend.make_store("t1")
    assert store.get_reset_marker() is None
    store.set_reset_marker("2026-09-17T12:00:00Z")
    assert backend.make_store("reader").get_reset_marker() == "2026-09-17T12:00:00Z"
    # Moving it overwrites rather than appending a second marker.
    store.set_reset_marker("2026-09-18T12:00:00Z")
    assert store.get_reset_marker() == "2026-09-18T12:00:00Z"
    assert backend.raw(RESET_MARKER).strip() == "2026-09-18T12:00:00Z"


def test_the_reset_marker_deletes_no_records(backend):
    store = backend.make_store("t1")
    store.write_verdicts([rec(request_id="a", day="2026-09-01")])
    store.set_reset_marker("2026-09-17T00:00:00Z")
    assert [r.request_id for r in store.read_verdicts()] == ["a"]


def test_clearing_the_reset_marker_reads_as_absent(backend):
    store = backend.make_store("t1")
    store.set_reset_marker("2026-09-17T12:00:00Z")
    store.set_reset_marker("")
    assert store.get_reset_marker() is None


def test_excluded_marker_round_trip(backend):
    store = backend.make_store("t1")
    assert store.get_excluded() == set()
    store.set_excluded(["req-b", "req-a", "req-b"])
    assert backend.make_store("reader").get_excluded() == {"req-a", "req-b"}
    # Sorted and deduplicated on the way out, so the object is stable.
    assert backend.raw(EXCLUDE_MARKER).splitlines() == ["req-a", "req-b"]


def test_excluded_marker_can_be_emptied(backend):
    store = backend.make_store("t1")
    store.set_excluded(["req-a"])
    store.set_excluded([])
    assert store.get_excluded() == set()


def test_the_excluded_marker_deletes_no_records(backend):
    store = backend.make_store("t1")
    store.write_verdicts([rec(request_id="req-a")])
    store.set_excluded(["req-a"])
    assert [r.request_id for r in store.read_verdicts()] == ["req-a"]


def test_markers_are_not_mistaken_for_records(backend):
    """Both markers live under the same root as the partitions. A reader that
    globbed too widely would try to parse them as JSONL."""
    store = backend.make_store("t1")
    store.set_reset_marker("2026-09-17T12:00:00Z")
    store.set_excluded(["req-a"])
    store.write_verdicts([rec(request_id="a")])
    assert [r.request_id for r in store.read_verdicts()] == ["a"]
    assert list(store.read_denials()) == []
    assert backend.exists(RESET_MARKER) and backend.exists(EXCLUDE_MARKER)


# -- describe --------------------------------------------------------------


def test_describe_reports_the_backend_the_instance_and_the_reset_marker(backend):
    store = backend.make_store("inst-7")
    described = store.describe()
    assert isinstance(described, dict)
    assert isinstance(described["backend"], str) and described["backend"]
    assert described["instance"] == "inst-7"
    assert described["reset_at"] is None

    store.set_reset_marker("2026-09-17T12:00:00Z")
    assert store.describe()["reset_at"] == "2026-09-17T12:00:00Z"


def test_describe_names_the_two_backends_distinctly(backend):
    expected = {"local": "local", "blob": "azure-blob", "s3": "s3", "gcs": "gcs"}[
        backend.name
    ]
    assert backend.make_store("t1").describe()["backend"] == expected


# -- batching --------------------------------------------------------------


def test_a_batch_is_one_object_not_one_object_per_record(backend):
    store = backend.make_store("t1")
    assert store.write_verdicts([rec(request_id=f"r{i}") for i in range(10)]) == 10
    objects = backend.objects()
    assert len(objects) == 1, objects
    assert backend.raw(objects[0]).strip().count("\n") == 9
    assert len(list(store.read_verdicts())) == 10


EXPECTED_PARTITION = {
    "a": (SOURCE_INFERENCE_HOOK, "org_aaa", "2026-09-16"),
    "b": (SOURCE_INFERENCE_HOOK, "org_aaa", "2026-09-17"),
    "c": (SOURCE_INFERENCE_HOOK, "org_bbb", "2026-09-17"),
    "d": (SOURCE_COMPLIANCE_SCAN, "org_bbb", "2026-09-17"),
    "e": (SOURCE_INFERENCE_HOOK, "org_bbb", "2026-09-17"),
}


def test_a_batch_splits_on_source_org_and_day_and_nothing_else(backend):
    store = backend.make_store("t1")
    store.write_verdicts([
        rec(request_id="a", day="2026-09-16", tenant_hash="org_aaa"),
        rec(request_id="b", day="2026-09-17", tenant_hash="org_aaa"),
        rec(request_id="c", day="2026-09-17", tenant_hash="org_bbb"),
        rec(request_id="d", day="2026-09-17", tenant_hash="org_bbb", source=SOURCE_COMPLIANCE_SCAN),
        # Same (source, org, day) as "c": rides in the same object.
        rec(request_id="e", day="2026-09-17", tenant_hash="org_bbb", action="deny"),
    ])
    # A count alone let a backend that chunked the batch arbitrarily into
    # four objects pass, and said nothing about whether a record landed under
    # the right source, org and day. Assert the mapping instead.
    placed = {
        obj: sorted(
            json.loads(line)["request_id"]
            for line in backend.raw(obj).splitlines()
            if line.strip()
        )
        for obj in backend.objects()
    }
    assert len(placed) == 4, placed
    for obj, ids in placed.items():
        for rid in ids:
            expected = EXPECTED_PARTITION[rid]
            assert f"source={expected[0]}" in obj, (rid, obj)
            assert f"org={expected[1]}" in obj, (rid, obj)
            assert f"date={expected[2]}" in obj, (rid, obj)
    assert sorted(i for ids in placed.values() for i in ids) == [
        "a", "b", "c", "d", "e"
    ]
    # c and e share (source, org, day) so they must share an object.
    assert any(ids == ["c", "e"] for ids in placed.values()), placed


def test_successive_batches_never_reuse_an_object_name(backend):
    store = backend.make_store("t1")
    for i in range(5):
        store.write_verdicts([rec(request_id=f"r{i}")])
    assert len(backend.objects()) == 5
    assert len(list(store.read_verdicts())) == 5


# -- concurrency -----------------------------------------------------------


def test_two_concurrent_writer_instances_preserve_every_record(backend):
    """Two replicas write the same partition at the same time. Each owns its
    own object names, so neither needs a lock the other can see -- and
    nothing may be overwritten, which the fake container enforces by raising
    on a duplicate name."""
    per_writer = 20
    stores = {tag: backend.make_store(tag) for tag in ("a", "b")}
    errors: list[BaseException] = []
    start = threading.Barrier(len(stores))

    def hammer(tag: str) -> None:
        try:
            start.wait(timeout=10)
            for i in range(per_writer):
                stores[tag].write_verdicts([rec(request_id=f"{tag}-{i}")])
        except BaseException as exc:  # noqa: BLE001 - re-raised via the assert below
            errors.append(exc)

    threads = [threading.Thread(target=hammer, args=(tag,)) for tag in stores]
    for t in threads:
        t.start()
    for t in threads:
        t.join(timeout=30)
    assert not any(t.is_alive() for t in threads), "a writer thread hung"
    assert not errors, errors

    expected = {f"{tag}-{i}" for tag in stores for i in range(per_writer)}
    assert {r.request_id for r in backend.make_store("reader").read_verdicts()} == expected
    assert len(backend.objects()) == 2 * per_writer


def test_concurrent_multi_record_batches_lose_no_lines(backend):
    """One object per batch, so 2 writers x 5 batches x 4 records must come
    back as 10 objects and 40 records with nothing interleaved or truncated."""
    stores = {tag: backend.make_store(tag) for tag in ("a", "b")}
    errors: list[BaseException] = []
    start = threading.Barrier(len(stores))

    def hammer(tag: str) -> None:
        try:
            start.wait(timeout=10)
            for batch in range(5):
                stores[tag].write_verdicts(
                    [rec(request_id=f"{tag}-{batch}-{i}") for i in range(4)]
                )
        except BaseException as exc:  # noqa: BLE001
            errors.append(exc)

    threads = [threading.Thread(target=hammer, args=(tag,)) for tag in stores]
    for t in threads:
        t.start()
    for t in threads:
        t.join(timeout=30)
    assert not any(t.is_alive() for t in threads), "a writer thread hung"
    assert not errors, errors

    expected = {f"{tag}-{b}-{i}" for tag in stores for b in range(5) for i in range(4)}
    assert {r.request_id for r in backend.make_store("reader").read_verdicts()} == expected
    assert len(backend.objects()) == 10


# -- durable state ---------------------------------------------------------


def test_state_round_trips(backend):
    store = backend.make_store("t1")
    assert store.get_state("cursor.json") is None
    store.put_state("cursor.json", b'{"last_run_started_at": "2026-09-19T00:00:00Z"}')
    assert json.loads(store.get_state("cursor.json"))["last_run_started_at"] == (
        "2026-09-19T00:00:00Z"
    )


def test_audit_modified_is_the_store_s_time_for_a_record(backend, monkeypatch):
    """Mutation: return this process's clock instead of the record's time."""
    from forgd_verdict.store.base import StoreReadError

    offset = timedelta(0) if isinstance(backend, LocalBackend) else timedelta(hours=3)
    monkeypatch.setattr(SERVER_TIME, "offset", offset)
    store = backend.make_store("t1")
    store.put_audit("2026-10-16/probe-clock-x.json", b"{}\n")
    found = store.audit_modified("2026-10-16/probe-clock-x.json")
    assert found.tzinfo is not None
    assert abs((found - (datetime.now(UTC) + offset)).total_seconds()) < 5
    with pytest.raises(StoreReadError):
        store.audit_modified("2026-10-16/probe-clock-absent.json")


@pytest.mark.parametrize("cloud", ["blob", "s3", "gcs"])
def test_a_record_with_no_time_has_no_audit_modified(cloud, monkeypatch):
    """Mutation: fall back to this process's clock."""
    from forgd_verdict.store.base import StoreReadError

    backend = {"blob": _install_fake_azure, "s3": _install_fake_boto3,
               "gcs": _install_fake_gcs}[cloud](monkeypatch)
    monkeypatch.setattr(_FakeProperties, "__init__",
                        lambda self, etag: setattr(self, "last_modified", None))
    head = FakeS3Client.head_object
    monkeypatch.setattr(FakeS3Client, "head_object",
                        lambda self, **kw: {**head(self, **kw), "LastModified": None})
    get_blob = _FakeGCSBucket.get_blob

    def no_time(self, name, **kw):
        blob = get_blob(self, name, **kw)
        if blob is not None:
            blob.updated = None
        return blob
    monkeypatch.setattr(_FakeGCSBucket, "get_blob", no_time)
    store = backend.make_store("t1")
    store.put_audit("2026-10-16/probe-clock-x.json", b"{}\n")
    with pytest.raises(StoreReadError):
        store.audit_modified("2026-10-16/probe-clock-x.json")


@pytest.mark.parametrize("cloud", ["blob", "s3", "gcs"])
def test_a_denied_state_read_raises_rather_than_reading_as_absent(cloud, monkeypatch):
    """A cursor read that failed for any reason but a 404 returned None on
    Azure, and the Compliance scan then restarted from scratch."""
    backend = {"blob": _install_fake_azure, "s3": _install_fake_boto3,
               "gcs": _install_fake_gcs}[cloud](monkeypatch)
    store = backend.make_store("t1")
    store.put_state("cursor.json", b"{}")
    backend.deny("state/cursor.json")
    with pytest.raises(Exception):  # noqa: B017 - each SDK raises its own family
        store.get_state("cursor.json")


def test_state_outlives_the_instance_that_wrote_it(backend):
    """The whole point. The ingest job's replica is destroyed when a pass
    finishes, so a cursor that only lives in the writer is a cursor that is
    gone before the next run reads it."""
    backend.make_store("writer").put_state("cursor.json", b'{"n": 1}')
    assert json.loads(backend.make_store("reader").get_state("cursor.json"))["n"] == 1


def test_state_is_overwritten_rather_than_appended(backend):
    """Records are immutable and append-only; a cursor is the one mutable
    thing in the store. A second write must replace, not accumulate."""
    store = backend.make_store("t1")
    store.put_state("cursor.json", b'{"n": 1}')
    store.put_state("cursor.json", b'{"n": 2}')
    assert json.loads(store.get_state("cursor.json"))["n"] == 2


def test_two_names_do_not_collide(backend):
    """Two orgs must never share a cursor: a pass that fails midway would
    advance the cursor for an org it never scanned."""
    store = backend.make_store("t1")
    store.put_state("org-a.json", b'{"who": "a"}')
    store.put_state("org-b.json", b'{"who": "b"}')
    assert json.loads(store.get_state("org-a.json"))["who"] == "a"
    assert json.loads(store.get_state("org-b.json"))["who"] == "b"


def test_state_is_not_returned_as_a_record(backend):
    """It lives in the same store as the findings and must not appear in
    them -- a cursor read back as a verdict would be a phantom row."""
    store = backend.make_store("t1")
    store.put_state("cursor.json", b'{"n": 1}')
    store.write_verdicts([rec(request_id="real")])
    assert [r.request_id for r in store.read_verdicts()] == ["real"]
    assert list(store.read_denials()) == []


def test_the_org_registry_is_republished_and_read_by_another_instance(backend):
    from forgd_verdict.orgregistry import REGISTRY_STATE_NAMES, build_registry
    from forgd_verdict.policy import Policy

    first = build_registry(Policy(raw={"privacy": {"hash_salt": "salt-one"},
                                       "orgs": [{"id": "org-x", "label": "X"}]}))
    second = build_registry(Policy(raw={"privacy": {"hash_salt": "salt-two"},
                                        "orgs": [{"id": "org-x", "label": "X"}]}))
    name = REGISTRY_STATE_NAMES["collector"]
    writer = backend.make_store("writer")
    writer.put_state(name, first)
    assert backend.make_store("reader").get_state(name) == first
    writer.put_state(name, second)
    assert backend.make_store("reader").get_state(name) == second
    assert list(writer.read_verdicts()) == []


@pytest.mark.parametrize("bad", ["", " x", "../escape", "a/b", ".hidden"])
def test_a_state_name_that_could_escape_the_namespace_is_refused(backend, bad):
    """These are derived from configuration, so a traversal would be a
    config file reaching outside the store. Refused rather than sanitised:
    silently rewriting a key could give two orgs the same one."""
    store = backend.make_store("t1")
    with pytest.raises(ValueError):
        store.put_state(bad, b"{}")
    with pytest.raises(ValueError):
        store.get_state(bad)


# -- reads at fleet volume -------------------------------------------------

FLEET_DEVICES = 900
FLEET_DAYS = [f"2026-09-{d:02d}" for d in range(1, 31)]
FLEET_ORGS = ("org_fleet1", "org_fleet2", "org_fleet3")
# Server-side batches per org per day: hourly for the live sources, four
# compliance passes.
FLEET_BATCHES = {"inference_hook": 24, "otel_collect": 24, "compliance_scan": 4}
LIST_PAGE = 1000


def _seed_fleet(backend) -> list[str]:
    """Every object a 900-laptop fleet leaves over 30 days, synthetic.

    Each laptop's code-hook batches land as one object per device per day
    in its org, the server-side sources as batches per org per day, and a
    pre-org-partition object sits in each day. Returns every key written,
    store-relative.
    """
    keys = []
    lines: dict[tuple[str, str, str], str] = {}

    def put(rel: str, source: str, org: str | None, day: str) -> None:
        line = lines.get((source, org or "", day))
        if line is None:
            line = lines[(source, org or "", day)] = rec(
                source=source, day=day, tenant_hash=org).to_json() + "\n"
        backend.put_raw(rel, line)
        keys.append(rel)

    for day in FLEET_DAYS:
        for device in range(FLEET_DEVICES):
            org = FLEET_ORGS[device % len(FLEET_ORGS)]
            put(f"verdicts/source=code_hook/org={org}/date={day}/dev{device:04d}-000001.jsonl",
                "code_hook", org, day)
        for org in FLEET_ORGS:
            for source, batches in FLEET_BATCHES.items():
                for n in range(batches):
                    put(f"verdicts/source={source}/org={org}/date={day}/srv-{n:06d}.jsonl",
                        source, org, day)
            backend.put_raw(f"denials/source=denials/org={org}/date={day}/srv-000001.jsonl",
                            den(day=day, tenant_hash=org).to_json() + "\n")
            keys.append(f"denials/source=denials/org={org}/date={day}/srv-000001.jsonl")
        put(f"verdicts/source=inference_hook/date={day}/legacy-000001.jsonl",
            "inference_hook", None, day)
    return keys


def _in_scope(key: str, since: str | None, orgs) -> bool:
    from forgd_verdict.store.base import path_segment

    day = path_segment(key, "date")
    org = path_segment(key, "org") or ORG_UNATTRIBUTED
    return (since is None or day is None or day >= since) and (orgs is None or org in orgs)


def _list_requests(lists, backend) -> int:
    """List calls as a real service would bill them, at LIST_PAGE names a
    page. A local directory read is one call."""
    if backend.name == "local":
        return len(lists)
    return sum(max(1, -(-n // LIST_PAGE)) for _, _, n in lists)


@pytest.mark.serial
@pytest.mark.parametrize("scope", ["one-org-7-days", "every-org-7-days", "one-org-all-days"])
def test_a_read_at_fleet_volume_lists_and_fetches_only_its_window_and_orgs(
        backend, monkeypatch, scope):
    """900 laptops for 30 days across three orgs: a 7-day read for one org
    lists only that org's partitions inside the window and fetches only
    their objects.

    A listing is allowed at the store root and at a source; below that only
    under an org the read is entitled to, and a recursive listing only of
    one `date=` partition the window covers, or of a whole entitled org
    when there is no window. Nothing else is listed and every fetched
    object is one the read needed.
    """
    for client in ("FakeS3Client", "FakeGCSClient"):
        monkeypatch.setattr(globals()[client], "PAGE_SIZE", LIST_PAGE)
    keys = _seed_fleet(backend)
    since, orgs = {
        "one-org-7-days": ("2026-09-24", {"org_fleet1"}),
        "every-org-7-days": ("2026-09-24", None),
        "one-org-all-days": (None, {"org_fleet1"}),
    }[scope]
    store = backend.make_store("reader")

    with backend.record_lists() as lists, backend.record_reads() as fetched:
        n = sum(1 for _ in store.read_verdicts(since=since, orgs=orgs))

    wanted = sorted(k for k in keys if k.startswith("verdicts/") and _in_scope(k, since, orgs))
    counts = {"objects": len(keys), "lists": len(lists),
              "list_requests": _list_requests(lists, backend),
              "names_listed": sum(c for _, _, c in lists), "gets": len(fetched),
              "wanted": len(wanted)}
    print(f"\nfleet read [{backend.name}] {scope}: {counts}")

    from forgd_verdict.store.base import path_segment

    def allowed(prefix: str, delimited: bool) -> bool:
        parts = [p for p in prefix.split("/") if p]
        if parts[:1] != ["verdicts"] or any("=" not in p for p in parts[1:]):
            return False
        if len(parts) <= 2:  # the root, or a source
            return delimited
        org = path_segment(prefix, "org") or ORG_UNATTRIBUTED
        day = path_segment(prefix, "date")
        if orgs is not None and org not in orgs:
            return False
        if day is None:
            # With no window, every day of an entitled org is wanted, so the
            # org's partition may be listed whole.
            return delimited or since is None
        return since is None or day >= since

    stray = [(p, d) for p, d, _ in lists if not allowed(p, d)]
    assert not stray, (counts, stray[:5])
    assert sorted(fetched) == wanted, counts
    assert n == len(wanted)
    # A recursive listing returns only objects the read fetches. A delimited
    # one returns at most a source, org or day of retention per
    # (source, org) the read covers, never one name per object.
    if backend.name != "local":
        assert sum(c for _, d, c in lists if not d) == len(wanted), counts
    pairs = len({tuple(k.split("/")[1:3]) for k in keys if k.startswith("verdicts/")
                 and (orgs is None or path_segment(k, "org") in orgs)})
    delimited = sum(c for _, d, c in lists if d)
    assert delimited <= pairs * (len(FLEET_DAYS) + 1) + 16 + (
        len(wanted) if backend.name == "local" else 0), counts


@pytest.mark.serial
def test_a_denial_read_at_fleet_volume_lists_only_its_window_and_org(backend, monkeypatch):
    for client in ("FakeS3Client", "FakeGCSClient"):
        monkeypatch.setattr(globals()[client], "PAGE_SIZE", LIST_PAGE)
    keys = _seed_fleet(backend)
    store = backend.make_store("reader")
    with backend.record_lists() as lists, backend.record_reads() as fetched:
        got = list(store.read_denials(since="2026-09-24", orgs={"org_fleet2"}))
    wanted = sorted(k for k in keys if k.startswith("denials/")
                    and _in_scope(k, "2026-09-24", {"org_fleet2"}))
    print(f"\nfleet denial read [{backend.name}]: lists={len(lists)} "
          f"names_listed={sum(c for _, _, c in lists)} gets={len(fetched)}")
    assert sorted(fetched) == wanted
    assert len(got) == len(wanted) == 7
    assert sum(c for _, _, c in lists) <= 7 + len(FLEET_DAYS) + 16, lists


ODD_LAYOUT = (
    "verdicts/source=inference_hook/org=org_aaa/date=2026-09-01/a-000001.jsonl",
    "verdicts/source=inference_hook/org=org_aaa/date=2026-09-17/a-000002.jsonl",
    "verdicts/source=inference_hook/org=org_bbb/date=2026-09-17/b-000001.jsonl",
    "verdicts/source=code_hook/org=unattributed/date=2026-09-17/u-000001.jsonl",
    "verdicts/source=inference_hook/date=2026-09-01/legacy-000001.jsonl",
    "verdicts/source=inference_hook/date=2026-09-17/legacy-000002.jsonl",
    "verdicts/source=inference_hook/org=org_aaa/date=2026-09-17/sub/deeper-000001.jsonl",
    "verdicts/source=inference_hook/org=org_aaa/stray-000001.jsonl",
    "verdicts/source=inference_hook/org=org_aaa/other/x-000001.jsonl",
    "verdicts/source=inference_hook/stray-000002.jsonl",
    "verdicts/source=inference_hook/other/date=2026-09-01/x-000002.jsonl",
    "verdicts/source=inference_hook/org=org_aaa/date=not-a-day/x-000003.jsonl",
    "verdicts/flat-000001.jsonl",
    "verdicts/elsewhere/org=org_aaa/date=2026-09-17/x-000004.jsonl",
    "verdicts/elsewhere/date=2026-09-01/x-000005.jsonl",
)


@pytest.mark.parametrize("since", [None, "2026-09-10", "2026-09-17T12:00:00Z", "2026-10-01"])
@pytest.mark.parametrize("orgs", [None, {"org_aaa"}, {"org_aaa", "org_bbb"},
                                  {ORG_UNATTRIBUTED}, {"org_aaa", ORG_UNATTRIBUTED}, set()],
                         ids=["all", "aaa", "aaa+bbb", "unattributed", "aaa+unattributed",
                              "none"])
def test_the_partition_walk_reads_what_the_name_rules_select(backend, since, orgs):
    """Whatever the walk lists, it fetches the objects whose `date=` and
    `org=` segments the read selects, layouts outside the partition shape
    included: an object with no date segment is in every window and one
    with no org segment is unattributed."""
    for n, rel in enumerate(ODD_LAYOUT):
        backend.put_raw(rel, rec(request_id=f"r{n}").to_json() + "\n")
    store = backend.make_store("reader")
    with backend.record_reads() as fetched:
        got = sorted(r.request_id for r in store.read_verdicts(since=since, orgs=orgs))
    day = since[:10] if since else None
    wanted = sorted(rel for rel in ODD_LAYOUT if _in_scope(rel, day, orgs))
    assert sorted(fetched) == wanted
    assert got == sorted(f"r{ODD_LAYOUT.index(rel)}" for rel in wanted)


@pytest.mark.parametrize("org", ["org_aaa/date=2026-09-17", "../org=org_aaa", "org_aaa/",
                                 "", ".", ".."])
def test_an_org_that_is_not_one_path_component_reads_nothing(backend, org):
    """An entitlement is matched against one `org=` segment, so an org value
    carrying a separator must not be joined into a listing prefix that names
    another org's partition."""
    store = backend.make_store("t1")
    store.write_verdicts([rec(request_id="a", tenant_hash="org_aaa")])
    with backend.record_reads() as fetched:
        assert list(store.read_verdicts(orgs={org})) == []
    assert fetched == []


# -- audit listings at fleet volume ----------------------------------------

AUDIT_DAYS = [date.fromordinal(date(2026, 7, 3).toordinal() + i) for i in range(90)]
AUDIT_NOW = datetime(2026, 9, 30, 23, 59, 30, tzinfo=UTC)
# Dashboard replicas each writing a verification record an hour; writer
# instances whose probe creates succeed, an hour each per role.
AUDIT_REPLICAS = 6
AUDIT_PROBERS = 8
AUDIT_ROLES = ("writer", "collector", "ingest")
AUDIT_CHANGES = 30


def _seed_audit(backend) -> dict[str, int]:
    """90 days of audit records: probes and verification records each
    hour, and an override change every third day. Synthetic throughout."""
    from forgd_verdict import lockout
    from forgd_verdict.store.base import AUDIT_PREFIX

    def put(name: str, body: bytes) -> None:
        backend.put_raw(f"{AUDIT_PREFIX}/{name}", body.decode("utf-8"))

    counts = {"probes": 0, "verifications": 0, "requests": 0}
    base_id = base_hash = None
    for day in AUDIT_DAYS:
        for hour in range(24):
            for inst in range(AUDIT_PROBERS):
                for role in AUDIT_ROLES:
                    moment = datetime(day.year, day.month, day.day, hour, inst, tzinfo=UTC)
                    put(lockout.probe_name(role, f"host{inst}-0000000{inst}", moment), b"{}\n")
                    counts["probes"] += 1
            for replica in range(AUDIT_REPLICAS):
                audit_id = f"{day:%Y%m%d}T{hour:02d}{replica * 7:02d}00000000Z-{replica:012x}"
                record = {"version": lockout.REPORT_VERSION, "kind": lockout.VERIFY_KIND,
                          "id": audit_id, "at": f"{day}T{hour:02d}:{replica * 7:02d}:00Z",
                          "store": "fake", "identities": {}, "ok": False,
                          "base_id": base_id, "base_hash": base_hash,
                          "head": dict(lockout.NO_HEAD)}
                body = (json.dumps(record, sort_keys=True) + "\n").encode()
                put(lockout.verification_name(audit_id), body)
                base_id, base_hash = audit_id, hashlib.sha256(body).hexdigest()
                counts["verifications"] += 1
    previous = None
    for n in range(AUDIT_CHANGES):
        day = AUDIT_DAYS[n * 3]
        audit_id = f"{day:%Y%m%d}T120000Z-{n:012x}"
        request = {"version": 1, "kind": "request", "id": audit_id, "at": f"{day}T12:00:00Z",
                   "action": "set", "base_revision": n,
                   "base_audit_id": previous[0] if previous else None,
                   "base_hash": previous[1] if previous else None}
        body = (json.dumps(request, sort_keys=True) + "\n").encode()
        put(f"{day}/{audit_id}-request.json", body)
        put(f"{day}/{audit_id}-outcome.json", (json.dumps(
            {"kind": "outcome", "request_id": audit_id, "result": "applied"}) + "\n").encode())
        previous = (audit_id, hashlib.sha256(body).hexdigest())
        counts["requests"] += 1
    return counts


def _audit_callers():
    from forgd_verdict import lockout, overrides
    from forgd_verdict.detectors.t0_regex import T0RegexDetector
    from forgd_verdict.lockout_evidence import verifier

    def first_run(store):
        return overrides.RuntimeOverrides(store, "test").refresh()

    def orphan_check(store):
        with suppress(overrides.Refused):
            overrides.apply_change(store, {"issuer": "cli", "subject": "t", "name": "t",
                                           "verified": False},
                                   overrides.Change(overrides.ACTION_SET,
                                                    "detectors.t0_regex.enabled", False),
                                   detectors=(T0RegexDetector(),), now=AUDIT_NOW)

    # name -> (call, what it needs): "newest" reads the newest verification
    # records, "requests" every override record and no probe or
    # verification, "exists" stops at the first override record.
    return {
        "verifier.uninitialized": (lambda s: verifier.uninitialized(s, None, AUDIT_NOW),
                                   "exists"),
        "lockout.anchored_head": (lambda s: lockout.anchored_head(s, None, AUDIT_NOW),
                                  "newest"),
        "lockout.fresh_record": (lambda s: lockout.fresh_record(s, None, AUDIT_NOW), "newest"),
        "overrides.highest_revision": (overrides.highest_revision, "requests"),
        "overrides.latest_request_revision": (overrides.latest_request_revision, "requests"),
        "overrides.history": (lambda s: overrides.history(s, None), "requests"),
        "overrides._chained_migration": (overrides._chained_migration, "requests"),
        "overrides._retired_request": (overrides._retired_request, "requests"),
        # Two passes: latest_request_revision's, then the candidates'.
        "overrides._recoverable": (lambda s: overrides._recoverable(s, None), "requests*2"),
        "RuntimeOverrides._first_run": (first_run, "exists"),
        "apply_change orphan check": (orphan_check, "exists"),
        "lockout.write_verification": (
            lambda s: lockout.write_verification(s, {}, "fake", AUDIT_NOW), "newest"),
    }


@pytest.mark.serial
def test_audit_listings_at_fleet_volume_do_not_grow_with_probes_or_old_days(
        backend, monkeypatch):
    """A caller lists the days, then only the day partitions and leaf
    prefixes it needs: no caller's listing grows with the probes, an
    override caller's not with the verification records, and a caller that
    wants the newest verification record lists only the newest days.

    A local directory read returns every entry in it, so on the local
    backend only the directories read and the fetches are bounded.
    """
    for client in ("FakeS3Client", "FakeGCSClient"):
        monkeypatch.setattr(globals()[client], "PAGE_SIZE", LIST_PAGE)
    counts = _seed_audit(backend)
    store = backend.make_store("reader")
    days = len(AUDIT_DAYS)
    per_day_verifications = AUDIT_REPLICAS * 24
    report, failures = {}, []
    for name, (call, need) in _audit_callers().items():
        with backend.record_lists() as lists, backend.record_reads() as fetched:
            call(store)
        listed = sum(c for _, _, c in lists)
        got = {"lists": len(lists), "list_requests": _list_requests(lists, backend),
               "names_listed": listed, "gets": len(fetched)}
        report[name] = got
        if need == "newest":
            max_lists, max_names, max_gets = 6, 2 * per_day_verifications + days + 4, 6
        elif need == "exists":
            max_lists, max_names, max_gets = days + 6, days + 2 * AUDIT_CHANGES + 4, 6
        else:
            passes = 2 if need == "requests*2" else 1
            max_lists = passes * (days + 1) + 4
            max_names = passes * (days + 2 * AUDIT_CHANGES) + 4
            max_gets = 12 * AUDIT_CHANGES
        if backend.name == "local":
            max_names = None
        if (len(lists) > max_lists or (max_names is not None and listed > max_names)
                or len(fetched) > max_gets):
            failures.append((name, got, (max_lists, max_names, max_gets)))
    print(f"\naudit listings [{backend.name}] {counts}")
    for name, got in report.items():
        print(f"  {name}: {got}")
    assert not failures, failures


def test_a_scoped_audit_listing_lists_one_day_and_leaf_prefix(backend):
    store = backend.make_store("t1")
    for name in ("2026-09-16/20260916T100000Z-000000000001-request.json",
                 "2026-09-17/20260917T100000Z-000000000002-request.json",
                 "2026-09-17/20260917T100000Z-000000000002-outcome.json",
                 "2026-09-17/probe-writer-h-20260917T100000Z.json",
                 "2026-09-17/verify-20260917T100000000000Z-000000000003.json"):
        store.put_audit(name, b"{}\n")
    assert store.audit_days() == ["2026-09-16", "2026-09-17"]
    assert len(store.list_audit()) == 5
    assert store.list_audit("2026-09-17", "20260917") == [
        "2026-09-17/20260917T100000Z-000000000002-outcome.json",
        "2026-09-17/20260917T100000Z-000000000002-request.json"]
    assert store.list_audit("2026-09-17", "verify-") == [
        "2026-09-17/verify-20260917T100000000000Z-000000000003.json"]
    assert len(store.list_audit("2026-09-17")) == 4
    assert store.list_audit("2026-09-18") == []


@pytest.mark.parametrize("day, leaf", [("2026-09-17/..", ""), ("../x", ""), ("2026-9-17", ""),
                                       ("2026-09-17", "../"), ("2026-09-17", "a/b"),
                                       ("2026-09-17", "*"), ("2026-09-17", ".x"), (None, "x")])
def test_a_scoped_audit_listing_refuses_a_scope_that_is_not_one_day_and_leaf(
        backend, day, leaf):
    store = backend.make_store("t1")
    with pytest.raises(ValueError):
        store.list_audit(day, leaf)


def test_probe_and_verification_names_never_share_an_override_records_leaf():
    """override_records lists a day by its digits, so a probe or a
    verification name starting with a digit would be read as an override's."""
    from forgd_verdict import lockout

    for prefix in (lockout.PROBE_PREFIX, lockout.VERIFY_PREFIX):
        assert not prefix[:1].isdigit(), prefix
    moment = datetime(2026, 9, 17, 10, tzinfo=UTC)
    leaf = lockout.override_record_leaf("2026-09-17")
    assert not lockout.probe_name("writer", "h", moment).split("/")[1].startswith(leaf)
    assert lockout.verification_name("20260917T100000000000Z-000000000003").split(
        "/")[1].startswith(lockout.VERIFY_PREFIX)


# -- the event log page ----------------------------------------------------


def _sorted_events(records):
    return sorted(records, key=lambda r: r.observed_at or "", reverse=True)


@pytest.mark.serial
def test_an_event_page_at_fleet_volume_reads_only_the_newest_days(backend, monkeypatch):
    """A 30-day Event Log page for one org fetches the newest day's objects,
    not the window's, and shows the same newest rows a full read would."""
    from forgd_verdict.store.views import EVENT_PAGE, event_page

    for client in ("FakeS3Client", "FakeGCSClient"):
        monkeypatch.setattr(globals()[client], "PAGE_SIZE", LIST_PAGE)
    keys = _seed_fleet(backend)
    store = backend.make_store("reader")
    orgs = {"org_fleet1"}
    newest = [k for k in keys if k.startswith("verdicts/") and _in_scope(k, "2026-09-30", orgs)]
    with backend.record_reads() as fetched:
        page = event_page(store, "2026-09-01", orgs)
    print(f"\nevent page [{backend.name}]: gets={len(fetched)} rows={len(page.records)} "
          f"newest-day objects={len(newest)}")
    assert sorted(fetched) == sorted(newest)
    full = _sorted_events(store.read_verdicts("2026-09-01", orgs))
    assert len(page.records) == EVENT_PAGE
    assert [r.observed_at for r in page.records] == [
        r.observed_at for r in full[:len(page.records)]]
    assert (page.before.kind, page.before.day, page.before.label) == (
        "time", "2026-09-30", "2026-09-30 10:00:00 UTC")


def test_following_the_cursor_reads_every_event_once(backend):
    """Pages chained by `before` cover the window exactly: none skipped at
    a page edge, including rows that share a timestamp, and none twice."""
    from forgd_verdict.store.views import event_page, event_time_key

    store = backend.make_store("t1")
    batch, n = [], 0
    for day in ("2026-09-14", "2026-09-15", "2026-09-17"):
        for hour, repeat in ((9, 1), (10, 3), (11, 1)):
            for source in (SOURCE_INFERENCE_HOOK, SOURCE_COMPLIANCE_SCAN):
                for _ in range(repeat):
                    r = rec(source=source, day=day, request_id=f"r{n}")
                    r.observed_at = f"{day}T{hour:02d}:00:00Z"
                    batch.append(r)
                    n += 1
    store.write_verdicts(batch)
    seen, before, pages = [], None, 0
    while True:
        page = event_page(store, "2026-09-01", None, before=before, limit=4)
        seen += [r.request_id for r in page.records]
        assert page.records == _sorted_events(page.records)
        assert len(page.records) <= 4
        pages += 1
        if page.before is None:
            break
        assert all(event_time_key(r.observed_at) >= page.before.order[0]
                   for r in page.records)
        before = page.before
        assert pages < 40
    assert sorted(seen) == sorted(r.request_id for r in batch)
    assert len(seen) == len(set(seen))
    assert pages > 3


def test_a_page_that_finds_too_little_stops_at_a_day_boundary_after_its_budget(backend):
    """A filter that matches nothing does not read the whole window: the page
    stops after the day on which its scan budget ran out, and names where
    the next page starts."""
    from forgd_verdict.store.views import EventCursor, event_page

    store = backend.make_store("t1")
    store.write_verdicts([rec(day=f"2026-09-{d:02d}", request_id=f"r{d}-{i}")
                          for d in range(10, 18) for i in range(3)])
    with backend.record_reads() as fetched:
        page = event_page(store, "2026-09-01", None, action="deny", budget=5)
    assert page.records == []
    assert page.before == EventCursor.done("2026-09-16")
    assert sorted(path_day(n) for n in fetched) == ["2026-09-16", "2026-09-17"]
    later = event_page(store, "2026-09-01", None, action="deny", budget=5,
                       before=page.before)
    assert later.before == EventCursor.done("2026-09-14")


def test_a_day_over_the_budget_is_paged_by_position_and_read_once(backend):
    """A page whose budget runs out inside a day stops after the object it
    is reading; the next page resumes there, and older days stay exact."""
    from forgd_verdict.store.views import event_page

    store = backend.make_store("t1")
    ids = []
    for day in ("2026-09-16", "2026-09-17"):
        for n in range(12):
            r = rec(day=day, request_id=f"{day}-{n:02d}")
            store.write_verdicts([r])
            ids.append(r.request_id)
    seen, before, pages, approximate = [], None, 0, set()
    while True:
        with backend.record_reads() as fetched:
            page = event_page(store, "2026-09-01", None, before=before, limit=5, budget=4)
        assert len(page.records) <= 5
        assert len(fetched) <= 5
        seen += [r.request_id for r in page.records]
        approximate.add(page.approximate)
        pages += 1
        if page.before is None:
            break
        before = page.before
        assert pages < 40
    assert sorted(seen) == sorted(ids)
    assert len(seen) == len(set(seen))
    assert approximate >= {"2026-09-17", "2026-09-16"}


def path_day(name: str) -> str:
    from forgd_verdict.store.base import path_segment

    return path_segment(name, "date") or ""


def test_an_event_page_never_shows_another_orgs_row(backend):
    from forgd_verdict.store.views import event_page

    store = backend.make_store("t1")
    store.write_verdicts([rec(request_id="a", tenant_hash="org_aaa"),
                          rec(request_id="b", tenant_hash="org_bbb")])
    assert [r.request_id for r in event_page(store, None, {"org_aaa"}).records] == ["a"]
    assert event_page(store, None, set()).records == []


# -- fleet partitions and source pruning -----------------------------------


def _fleet_records():
    from forgd_verdict.store.base import SOURCE_CODE_HOOK, SOURCE_OTEL_COLLECT

    return [
        rec(request_id="a", tenant_hash="org_aaa"),
        rec(request_id="b", tenant_hash="org_bbb"),
        rec(source=SOURCE_CODE_HOOK, request_id="f1", tenant_hash="fleet-laptops"),
        rec(source=SOURCE_CODE_HOOK, request_id="f2", tenant_hash="fleet-builders"),
        rec(source=SOURCE_OTEL_COLLECT, request_id="o", tenant_hash="org_bbb"),
    ]


def test_any_fleet_reads_every_fleet_partition_and_no_other_org(backend):
    from forgd_verdict.store.base import ANY_FLEET

    store = backend.make_store("t1")
    store.write_verdicts(_fleet_records())
    with backend.record_reads() as read:
        got = {r.request_id for r in store.read_verdicts(orgs={"org_aaa", ANY_FLEET})}
    assert got == {"a", "f1", "f2"}
    assert not any("org_bbb" in n for n in read), read
    days = {r.request_id for _, records in store.read_verdict_days(
        orgs={"org_aaa", ANY_FLEET}) for r in records}
    assert days == got


def test_any_fleet_alone_reads_only_fleet_partitions(backend):
    from forgd_verdict.store.base import ANY_FLEET

    store = backend.make_store("t1")
    store.write_verdicts(_fleet_records())
    assert {r.request_id for r in store.read_verdicts(orgs={ANY_FLEET})} == {"f1", "f2"}


def test_a_literal_fleet_star_partition_is_not_a_wildcard_to_a_plain_org_read(backend):
    store = backend.make_store("t1")
    store.write_verdicts(_fleet_records())
    assert {r.request_id for r in store.read_verdicts(orgs={"fleet-laptops"})} == {"f1"}


def test_sources_prunes_by_source_partition(backend):
    from forgd_verdict.store.base import SOURCE_OTEL_COLLECT

    store = backend.make_store("t1")
    store.write_verdicts(_fleet_records())
    with backend.record_reads() as read:
        got = [r.request_id for r in store.read_verdicts(sources=(SOURCE_OTEL_COLLECT,))]
    assert got == ["o"]
    assert len(read) == 1 and f"source={SOURCE_OTEL_COLLECT}" in read[0]
    days = [r.request_id for _, records in store.read_verdict_days(
        sources=(SOURCE_OTEL_COLLECT,)) for r in records]
    assert days == ["o"]
