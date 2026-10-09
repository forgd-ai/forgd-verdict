"""The org registry: org id or workspace key -> store pseudonym and label,
published by salted writers.

Readers (the dashboard, the connector) name orgs by id and Managed Agents
workspaces by key in configuration, but the store keys them by
`pseudonym(id, salt, "org")` and `pseudonym(key, salt, "workspace")`, and a
chart deployment does not give readers the salt. Each writer that holds it -- the verdict
server, the collector and the intake -- writes its own file at startup,
`state/org-registry-<role>.json`. A reader without the salt merges the three
files, resolves ids through the result, and takes each org's label from it.

A reader that holds the salt computes pseudonyms directly. With a store it
also reads the files, only to warn when the writers' pseudonyms differ from
its own.
"""

from __future__ import annotations

import json
import logging
import re
import threading
import time
from collections.abc import Callable, Iterator, Mapping
from dataclasses import dataclass
from typing import Any

from .models import env_or_literal, pseudonym

# The writer roles in label precedence order, and each one's state name.
REGISTRY_STATE_NAMES = {
    "verdict": "org-registry-verdict.json",
    "collector": "org-registry-collector.json",
    "intake": "org-registry-intake.json",
}
REGISTRY_VERSION = 2
READABLE_VERSIONS = (1, 2)
REFRESH_S = 60.0

KIND_ORG = "org"
KIND_WORKSPACE = "workspace"
# The kind is the pseudonym's prefix, so a partition names its own kind.
_PARTITION = re.compile(r"^(org|workspace)_[0-9a-f]{10}\Z")

_log = logging.getLogger("forgd_verdict.orgregistry")
_monotonic = time.monotonic


def _resolved(value: Any) -> str:
    return str(env_or_literal(value) or "")


def _add(out: dict[str, str | None], value: str, label: Any) -> None:
    if not value:
        return
    label = str(label or "") or None
    if out.get(value) is None:
        out[value] = label


def partition_kind(value: str) -> str | None:
    """`org` or `workspace` for a store pseudonym of that kind, else None."""
    found = _PARTITION.match(value) if isinstance(value, str) else None
    return found.group(1) if found else None


def workspace_pseudonym(key: str, salt: str) -> str | None:
    """The partition adapter 6 files a workspace's records under."""
    return pseudonym(key, salt, KIND_WORKSPACE)


def workspace_key(ws: Any) -> str:
    """A `managed_agents.workspaces[]` entry's `key` as a string, or ''."""
    key = ws.get("key") if isinstance(ws, dict) else None
    return key if isinstance(key, str) else ""


def configured_workspaces(policy: Any) -> list[tuple[str, str]]:
    """`(key, label)` for every `managed_agents.workspaces` entry with a key,
    in policy order, duplicates included."""
    block = policy.raw.get("managed_agents")
    raw = block.get("workspaces") if isinstance(block, dict) else None
    return [(workspace_key(ws), str(ws.get("label") or ""))
            for ws in (raw if isinstance(raw, list) else []) if workspace_key(ws)]


def check_workspace_pseudonyms(workspaces: list[tuple[str, str]], salt: str) -> None:
    """Raise ValueError when two `(key, label)` pairs share a pseudonym.

    The message names the two workspaces by label, never by key.
    """
    seen: dict[str, str] = {}
    for key, label in workspaces:
        name = str(workspace_pseudonym(key, salt))
        if name in seen:
            raise ValueError(
                f"managed_agents.workspaces entries {seen[name]!r} and {label!r} "
                "have keys that file findings under the same partition. Give the "
                "newer of the two a different `key`.")
        seen[name] = label


def referenced_workspaces(policy: Any) -> dict[str, str | None]:
    """`{key: label or None}` for every configured workspace with a key."""
    out: dict[str, str | None] = {}
    for key, label in configured_workspaces(policy):
        _add(out, key, label)
    return out


def _org_references(policy: Any) -> list[tuple[Any, Any]]:
    """`(id as written, label)` for every org id the policy names, in the
    order `referenced_orgs` reads them."""
    raw = policy.raw
    out: list[tuple[Any, Any]] = []
    for org in raw.get("orgs") or []:
        if isinstance(org, dict):
            out.append((org.get("id"), org.get("label")))
    compliance = raw.get("compliance") or {}
    out.append((compliance.get("org_id"), None))
    for org in compliance.get("orgs") or []:
        if isinstance(org, dict):
            out.append((org.get("id"), org.get("label")))
    for org in (raw.get("otel") or {}).get("orgs") or []:
        if isinstance(org, dict):
            ids = org["ids"] if isinstance(org.get("ids"), list) else [org.get("id")]
            out.extend((org_id, org.get("label")) for org_id in ids)
    ent = ((raw.get("dashboard") or {}).get("entitlements") or {})
    for entry in ent.get("map") or []:
        if isinstance(entry, dict):
            out.extend((org_id, None) for org_id in entry.get("orgs") or [])
    return out


def referenced_orgs(policy: Any) -> dict[str, str | None]:
    """`{id: label or None}` for every org id the policy names.

    From `orgs`, `dashboard.entitlements.map`, `compliance` and
    `otel.orgs` (`id`, or each of `ids`). A label is taken from the first of `orgs`, `compliance`
    and `otel.orgs` that gives one. Workspaces are not orgs and are not
    included; see `referenced_workspaces`. A `$VAR` that is unset names
    nothing here; `unresolved_org_references` lists it.
    """
    out: dict[str, str | None] = {}
    for value, label in _org_references(policy):
        _add(out, _resolved(value), label)
    return out


def unresolved_org_references(policy: Any) -> list[str]:
    """Each `$VAR` org reference `referenced_orgs` reads that resolves to
    nothing, as written, once each in policy order. Variable names only,
    never a value."""
    out: list[str] = []
    for value, _ in _org_references(policy):
        if (isinstance(value, str) and value.startswith("$")
                and not _resolved(value) and value not in out):
            out.append(value)
    return out


def build_registry(policy: Any, with_workspaces: bool = True) -> bytes:
    """The registry file for `policy`, byte-identical for the same policy and salt.

    `{"version": 2, "orgs": [{"id", "pseudonym", "label"?}, ...],
    "workspaces": [{"key", "pseudonym", "label"?}, ...]}`, each sorted by id
    or key. `label` is present only when one is configured. With
    `with_workspaces` it raises ValueError when two workspace keys share a
    pseudonym; without it the workspaces list is empty.
    """
    salt = policy.hash_salt
    if with_workspaces:
        check_workspace_pseudonyms(configured_workspaces(policy), salt)
    orgs = []
    for value, label in sorted(referenced_orgs(policy).items()):
        entry = {"id": value, "pseudonym": pseudonym(value, salt, KIND_ORG)}
        if label:
            entry["label"] = label
        orgs.append(entry)
    workspaces = []
    for key, label in sorted(referenced_workspaces(policy).items() if with_workspaces else []):
        entry = {"key": key, "pseudonym": workspace_pseudonym(key, salt)}
        if label:
            entry["label"] = label
        workspaces.append(entry)
    body = {"version": REGISTRY_VERSION, "orgs": orgs, "workspaces": workspaces}
    return (json.dumps(body, sort_keys=True, separators=(",", ":")) + "\n").encode("utf-8")


def publish_registry(store: Any, policy: Any, role: str,
                     log: logging.Logger | None = None) -> bool:
    """Write `role`'s registry to `store`. Logs and returns False when it does not.

    Writes nothing when `privacy.hash_salt` is empty. When two Managed Agents
    workspace keys share a pseudonym it logs an error naming them by label and
    publishes the orgs with an empty workspaces list, so readers resolve no
    workspace and every org as before.
    """
    name = REGISTRY_STATE_NAMES[role]
    log = log or _log
    if not policy.hash_salt:
        log.warning(
            "privacy.hash_salt is empty; not publishing the org registry. A "
            "dashboard or connector without the salt will resolve no org "
            "entitlements or labels")
        return False
    try:
        blob = build_registry(policy)
    except ValueError as exc:
        log.error("publishing the org registry without its workspaces: %s", exc)
        blob = build_registry(policy, with_workspaces=False)
    try:
        store.put_state(name, blob)
    except Exception as exc:  # noqa: BLE001 - any backend's write error
        log.error(
            "could not publish the org registry; a dashboard or connector without "
            "the hash salt will resolve no org entitlements or labels",
            extra={"fields": {"error": type(exc).__name__}},
        )
        return False
    return True


@dataclass(frozen=True)
class RegistryEntry:
    pseudonym: str
    label: str | None = None


Ref = tuple[str, str]


class OrgResolver:
    """Org id or workspace key -> registry entry for a reader.

    With a salt, the pseudonym is computed directly. With a store as well,
    the registry files are read at most every `ttl_s` seconds, only to warn
    once per refresh if any valid entry's pseudonym differs from the one the
    salt computes; unreadable or malformed files are skipped. Without a
    salt, entries come from the writers' registry files, merged and re-read
    at most every `ttl_s` seconds. No file present, any present file
    unreadable, malformed or of an unknown version, a value the files give
    different pseudonyms, or a value with no entry, resolves to None. A
    workspace also resolves to None when no present file is version 2, the
    version that carries workspaces; a version 1 file is read for orgs only.
    """

    def __init__(self, salt: str, store: Any = None, *, ttl_s: float = REFRESH_S,
                 clock: Callable[[], float] | None = None,
                 log: logging.Logger | None = None):
        self.salt = salt
        self.store = store
        self.ttl_s = ttl_s
        self.clock = clock or _monotonic
        self.log = log or _log
        self._lock = threading.Lock()
        self._entries: dict[Ref, RegistryEntry] = {}
        self._disputed: frozenset[Ref] = frozenset()
        self._usable = False
        self._has_workspaces = False
        self._loaded_at: float | None = None
        self._warned: set[str] = set()

    def pseudonym(self, org_id: str) -> str | None:
        return self.resolve((KIND_ORG, org_id))

    def workspace_pseudonym(self, key: str) -> str | None:
        return self.resolve((KIND_WORKSPACE, key))

    def resolve(self, ref: Ref) -> str | None:
        """The store pseudonym for `(kind, value)`, or None."""
        kind, value = ref
        if not value:
            return None
        if self.salt:
            self.check_salt()
            return pseudonym(value, self.salt, kind)
        entry = self.lookup(ref)
        return entry.pseudonym if entry else None

    def entry(self, org_id: str) -> RegistryEntry | None:
        """The registry's entry for `org_id`. Always read from the registry."""
        return self.lookup((KIND_ORG, org_id))

    def workspace_entry(self, key: str) -> RegistryEntry | None:
        """The registry's entry for workspace `key`. Always read from the registry."""
        return self.lookup((KIND_WORKSPACE, key))

    def lookup(self, ref: Ref) -> RegistryEntry | None:
        kind = ref[0]
        with self._lock:
            now = self.clock()
            if self._loaded_at is None or now - self._loaded_at >= self.ttl_s:
                self._usable, self._has_workspaces, self._entries, self._disputed = \
                    self._load()
                self._loaded_at = now
                self._warned = set()
            if kind == KIND_WORKSPACE and self._usable and not self._has_workspaces:
                if "no-workspaces" not in self._warned:
                    self._warned.add("no-workspaces")
                    self.log.warning(
                        "no org registry in the store carries workspaces, so the "
                        "writers predate version 2; Managed Agents workspaces grant "
                        "no access and show no label until a writer republishes")
                return None
            found = self._entries.get(ref)
            # Only a registry that loaded reports a missing value; an
            # unusable one, or a disputed value, has already been warned
            # about for this refresh.
            if (found is None and self._usable and kind not in self._warned
                    and ref not in self._disputed):
                self._warned.add(kind)
                self.log.warning(
                    f"{'a workspace' if kind == KIND_WORKSPACE else 'an org'} named "
                    "in the policy has no entry in the org registry; it grants no "
                    "access and shows no label until a writer publishes a registry "
                    "that includes it")
            return found

    def check_salt(self) -> None:
        """Warn if the registry's pseudonyms differ from this reader's salt.

        At most once per refresh; a no-op before the refresh interval has
        passed since the last check.
        """
        if not self.salt or self.store is None:
            return
        with self._lock:
            now = self.clock()
            if self._loaded_at is not None and now - self._loaded_at < self.ttl_s:
                return
            self._loaded_at = now
            roles = self._salt_mismatches()
            if roles:
                self.log.warning(
                    "this reader's hash salt differs from the org registry "
                    "writers'; its org entitlements and labels name other "
                    "partitions than the writers' findings are stored under",
                    extra={"fields": {"roles": roles}})

    def _salt_mismatches(self) -> list[str]:
        """The roles whose registry gives any org or workspace a pseudonym
        other than this reader's salt computes."""
        roles = []
        for role, name in REGISTRY_STATE_NAMES.items():
            try:
                blob = self.store.get_state(name)
                entries = _parse(blob)[1] if blob is not None else {}
            except Exception:  # noqa: BLE001 - any backend or parse error
                continue
            if any(entry.pseudonym != pseudonym(value, self.salt, kind)
                   for (kind, value), entry in entries.items()):
                roles.append(role)
        return roles

    def _load(self) -> tuple[bool, bool, dict[Ref, RegistryEntry], frozenset[Ref]]:
        """(usable, any file carries workspaces, entries, disputed)."""
        if self.store is None:
            self.log.warning(
                "no hash salt and no store to read the org registry from; org "
                "entitlements grant nothing and org labels do not resolve")
            return False, False, {}, frozenset()
        parsed: list[tuple[str, dict[Ref, RegistryEntry]]] = []
        has_workspaces = False
        for role, name in REGISTRY_STATE_NAMES.items():
            try:
                blob = self.store.get_state(name)
            except Exception as exc:  # noqa: BLE001 - any backend's read error
                self.log.warning(
                    "the org registry could not be read; org entitlements grant "
                    "nothing and org labels do not resolve until it can",
                    extra={"fields": {"role": role, "error": type(exc).__name__}})
                return False, False, {}, frozenset()
            if blob is None:
                continue
            try:
                version, entries = _parse(blob)
            except (ValueError, TypeError, KeyError, AttributeError, RecursionError):
                self.log.warning(
                    "the org registry is malformed or of an unknown version; org "
                    "entitlements grant nothing and org labels do not resolve until "
                    "its writer republishes it",
                    extra={"fields": {"role": role}})
                return False, False, {}, frozenset()
            has_workspaces = has_workspaces or version >= 2
            parsed.append((role, entries))
        if not parsed:
            self.log.warning(
                "the org registry is missing; org entitlements grant nothing and "
                "org labels do not resolve until a writer publishes it")
            return False, False, {}, frozenset()
        entries, disputed, roles = _merge(parsed)
        if disputed:
            self.log.warning(
                "the org registry's writers give an org or workspace different "
                "pseudonyms, so they hold different hash salts; it grants no access "
                "and shows no label until they agree",
                extra={"fields": {"roles": roles}})
        return True, has_workspaces, entries, disputed


def _merge(parsed: list[tuple[str, dict[Ref, RegistryEntry]]]
           ) -> tuple[dict[Ref, RegistryEntry], frozenset[Ref], list[str]]:
    """Merge per-role registries given in label precedence order.

    Returns the entries, the refs whose pseudonyms disagree, and the roles
    involved in any disagreement. An agreed ref takes the first label given.
    """
    by_ref: dict[Ref, list[tuple[str, RegistryEntry]]] = {}
    for role, entries in parsed:
        for ref, entry in entries.items():
            by_ref.setdefault(ref, []).append((role, entry))
    out: dict[Ref, RegistryEntry] = {}
    disputed: set[Ref] = set()
    roles: set[str] = set()
    for ref, found in by_ref.items():
        if len({entry.pseudonym for _, entry in found}) > 1:
            disputed.add(ref)
            roles.update(role for role, _ in found)
            continue
        label = next((entry.label for _, entry in found if entry.label), None)
        out[ref] = RegistryEntry(found[0][1].pseudonym, label)
    ordered = [role for role in REGISTRY_STATE_NAMES if role in roles]
    return out, frozenset(disputed), ordered


def _parse(blob: bytes) -> tuple[int, dict[Ref, RegistryEntry]]:
    """(version, entries). Version 1 files carry orgs only."""
    body = json.loads(blob)
    version = body.get("version")
    if version not in READABLE_VERSIONS or isinstance(version, bool) \
            or not isinstance(body["orgs"], list):
        raise ValueError
    sections = [(KIND_ORG, "id", body["orgs"])]
    if version >= 2:
        if not isinstance(body["workspaces"], list):
            raise ValueError
        sections.append((KIND_WORKSPACE, "key", body["workspaces"]))
    out: dict[Ref, RegistryEntry] = {}
    for kind, field_name, items in sections:
        for item in items:
            value, key, label = item[field_name], item["pseudonym"], item.get("label")
            if not (isinstance(value, str) and isinstance(key, str) and value and key):
                raise ValueError
            if partition_kind(key) != kind:
                raise ValueError
            out[(kind, value)] = RegistryEntry(
                key, label if isinstance(label, str) and label else None)
    return version, out


class OrgLabels(Mapping[str, str]):
    """`{pseudonym: label}`, resolved on each read.

    `lookup` maps each of `values` to `(pseudonym, label)` or None; an
    earlier value wins a pseudonym shared with a later one.
    """

    def __init__(self, values: list[Any],
                 lookup: Callable[[Any], tuple[str, str] | None]):
        self._values = values
        self._lookup = lookup

    def _current(self) -> dict[str, str]:
        out: dict[str, str] = {}
        for value in self._values:
            found = self._lookup(value)
            if found:
                out.setdefault(*found)
        return out

    def __getitem__(self, key: str) -> str:
        return self._current()[key]

    def __iter__(self) -> Iterator[str]:
        return iter(self._current())

    def __len__(self) -> int:
        return len(self._current())

    def __repr__(self) -> str:
        return f"OrgLabels({self._current()!r})"
