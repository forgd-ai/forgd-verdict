from collections.abc import Sequence

from ..models import shown_url
from ..plugins import (
    BUILTIN_STORE_SCHEMES,
    PluginAllow,
    build_plugin,
    find_entry,
    refuse_shadowing,
    refuse_unlisted,
    store_scheme,
)
from .base import (
    SCHEMA_VERSION,
    SOURCE_CODE_HOOK,
    SOURCE_COMPLIANCE_SCAN,
    SOURCE_INFERENCE_HOOK,
    DenialRecord,
    FindingRow,
    Store,
    VerdictRecord,
    verdict_from_log_row,
)
from .local import LocalFileStore
from .query import Summary, build_summary, families
from .spool import Spool, drain

__all__ = [
    "DenialRecord",
    "FindingRow",
    "LocalFileStore",
    "SCHEMA_VERSION",
    "SOURCE_CODE_HOOK",
    "SOURCE_COMPLIANCE_SCAN",
    "SOURCE_INFERENCE_HOOK",
    "Spool",
    "Store",
    "Summary",
    "VerdictRecord",
    "build_summary",
    "drain",
    "families",
    "verdict_from_log_row",
]


def store_is_empty(store) -> bool:
    """No partitions at all, which a mistyped path produces.

    `open_store` on a path that does not exist returns a working
    LocalFileStore, `_partitions` returns silently when the directory is
    absent, and the dashboard renders a healthy page with nothing in it --
    the dashboard's version of a clean scan.

    Distinct from "configured and quiet": a store that has ever been
    written to keeps its partition directories.
    """
    try:
        desc = store.describe()
    except Exception:  # noqa: BLE001 - describe must never decide a page
        return False
    files = desc.get("partition_files") or {}
    return bool(files) and not any(files.values())


class StoreNotConfigured(ValueError):
    """The policy names a store through a variable that is not set."""


BUILTIN_SCHEMES = BUILTIN_STORE_SCHEMES


def check_store_spec(spec: str, *, plugins: Sequence[PluginAllow] = ()) -> None:
    """Raise as `open_store(spec)` would on a spec it refuses, without
    opening anything, importing a backend or loading a plugin."""
    if spec.startswith("$"):
        raise StoreNotConfigured(
            f"the findings store is {spec!r} and {spec[1:]} is not set. "
            "Set it to a path or a blob URL, or set `store: \"\"` in the "
            "policy to run without a durable store."
        )
    refuse_shadowing(plugins, "stores", BUILTIN_SCHEMES)
    scheme = store_scheme(spec)
    if scheme is not None:
        if find_entry(plugins, "stores", scheme) is not None:
            return
        refuse_unlisted("stores", scheme, f"the store scheme {scheme!r}")
    if spec.startswith(("https://", "http://", "s3://", "gs://")) and "@" in spec.split("/")[2]:
        raise ValueError(
            f"the findings store spec {shown_url(spec)!r} carries credentials in the URL; "
            "remove them and give the service an identity with access to the store")
    if spec.startswith(("https://", "http://")):
        from ..safehttp import cleartext_refusal

        refused = cleartext_refusal(spec)
        if refused:
            raise ValueError(f"the findings store spec {shown_url(spec)!r} is refused: "
                             f"{refused}. The service's identity token goes with every "
                             "request.")


def open_store(spec: str, instance: str | None = None, *,
               plugins: Sequence[PluginAllow] = (), profile: str | None = None):
    """Open a store from a URI-ish spec.

        ./findings                      -> local filesystem
        file:///var/lib/forgd/findings  -> local filesystem
        https://acct.blob.core.windows.net/container/prefix -> Azure Blob
        s3://bucket/prefix              -> Amazon S3
        gs://bucket/prefix              -> Google Cloud Storage
        <name>:...                      -> the `stores` plugin `<name>`, when
                                           `plugins` lists it

    A scheme that is neither built-in nor listed refuses when an installed
    distribution publishes it as a `forgd_verdict.stores` entry point, and is
    otherwise a local path, as it always has been. A spec with no scheme
    reads no entry points.

    Blob support needs the `azure` extra, S3 the `aws` extra and GCS the
    `gcp` extra; each is imported lazily so the verdict server keeps no
    dependency on any of them.

    A spec still starting with `$` is refused. It is a policy placeholder
    whose variable was never set, and taken as a path it becomes a
    directory with that literal name: the writes succeed, health passes,
    and the findings land somewhere nobody configured.
    """
    check_store_spec(spec, plugins=plugins)
    scheme = store_scheme(spec)
    if scheme is not None:
        entry = find_entry(plugins, "stores", scheme)
        if entry is not None:
            return build_plugin(entry, profile, set(BUILTIN_SCHEMES), Store, spec, instance)
    if spec.startswith(("https://", "http://")):
        from .blob import BlobStore

        return BlobStore(spec, instance=instance)
    if spec.startswith("s3://"):
        from .s3 import S3Store

        return S3Store(spec, instance=instance)
    if spec.startswith("gs://"):
        from .gcs import GCSStore

        return GCSStore(spec, instance=instance)
    if spec.startswith("file://"):
        spec = spec[len("file://") :]
    return LocalFileStore(spec, instance=instance)
