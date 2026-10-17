"""Third-party detectors, stores and sinks, loaded from an explicit allowlist.

A plugin is an installed distribution that publishes an entry point in
`forgd_verdict.<group>`. Nothing installed is loaded unless `plugins.allow`
in the policy names it, pins the distribution and its exact version, and
lists the profile the current process runs as. An installed entry point that
is not listed is logged by name and group and never imported.

    plugins:
      allow:
        - name: acme_ids
          group: detectors
          dist: acme-forgd-detectors
          version: 1.4.2
          profiles: [server, compliance]

`load_plugins` checks every applicable entry against the installed metadata
before importing any of them, then imports each entry point's module and
checks its `PLUGIN_API` before calling `ep.load()` on any of them. A refusal
at any stage raises one `RuntimeError` naming every problem found at that
stage, and no plugin object is returned.
"""

from __future__ import annotations

import importlib
import importlib.metadata
import logging
import re
import weakref
from collections.abc import Callable, Iterable, Iterator, Mapping, Sequence
from dataclasses import dataclass, replace
from types import MappingProxyType
from typing import Any

from .detectors import (
    ChecksumDetector,
    EntropyDetector,
    GitleaksDetector,
    LLMGuardPIIDetector,
    PresidioPIIDetector,
    ShellExfilDetector,
    T0RegexDetector,
)
from .detectors.base import DetectorFailed
from .detectors.injection import InjectionDetector
from .models import Finding, ScanUnit

log = logging.getLogger("forgd_verdict.plugins")

PLUGIN_API = 1

GROUPS = ("detectors", "stores", "sinks")

PROFILES = (
    "server", "collector", "intake", "compliance", "hook", "dashboard",
    "connector", "managed",
)

ENTRY_POINT_PREFIX = "forgd_verdict."

# Every name `detectors:` accepts without a plugin. `provenance` and `taint`
# are read by `behaviour/provenance.py`, not by `build_detectors`.
BUILTIN_DETECTORS = frozenset({
    "t0_regex", "checksums", "entropy", "shell_exfil", "gitleaks",
    "presidio_pii", "llmguard_pii", "provenance", "taint", "envelope", "injection",
})

# The prefixes of the finding ids the built-ins emit (`regex:aws-...`).
BUILTIN_FINDING_PREFIXES = frozenset({
    "regex", "checksum", "entropy", "shell", "gitleaks", "presidio",
    "llmguard", "provenance", "taint", "envelope", "injection", "flag",
})

BUILTIN_DETECTOR_CLASSES = (
    T0RegexDetector, ChecksumDetector, EntropyDetector, ShellExfilDetector,
    GitleaksDetector, PresidioPIIDetector, LLMGuardPIIDetector, InjectionDetector,
)

# The `.name` each built-in has at runtime (`regex`, `shell`, ...), which
# skip lists, `detectors_run`, `detectors_skipped` and `_blocking_tiers` key on.
# `provenance` is `behaviour.provenance.ProvenanceDetector.name`, spelled out
# because `behaviour` sits a layer above this module.
BUILTIN_RUNTIME_NAMES = frozenset({c.name for c in BUILTIN_DETECTOR_CLASSES} | {"provenance"})

# Names a detector plugin may use neither as its name nor its finding prefix.
RESERVED_DETECTOR_NAMES = BUILTIN_DETECTORS | BUILTIN_RUNTIME_NAMES | BUILTIN_FINDING_PREFIXES

PHRASE_MAX = 60

FINDING_ID_MAX = 64

_ENTRY_KEYS = ("name", "group", "dist", "version", "profiles")
_SECTION_KEYS = ("allow",)
_VERSION_SPECIFIER = re.compile(r"[<>=~^*,! ]")
_NAME = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.\-]*\Z")


def normalize_dist(name: str) -> str:
    """A distribution name as packaging's `canonicalize_name` spells it."""
    return re.sub(r"[-_.]+", "-", name).lower()


@dataclass(frozen=True)
class PluginAllow:
    name: str
    group: str
    dist: str
    version: str
    profiles: tuple[str, ...]


def parse_allow(raw: Any) -> tuple[PluginAllow, ...]:
    """Validate the `plugins:` section. Absent or null is no plugins."""
    if raw is None:
        return ()
    if not isinstance(raw, dict):
        raise ValueError("plugins must be a mapping")
    unknown = sorted(set(raw) - set(_SECTION_KEYS))
    if unknown:
        raise ValueError(f"plugins has unknown keys {unknown}; allowed: {list(_SECTION_KEYS)}")
    allow = raw.get("allow")
    if allow is None:
        return ()
    if not isinstance(allow, list):
        raise ValueError("plugins.allow must be a list")

    out: list[PluginAllow] = []
    seen: set[tuple[str, str]] = set()
    for i, item in enumerate(allow):
        entry = _parse_entry(f"plugins.allow[{i}]", item)
        if (entry.group, entry.name) in seen:
            raise ValueError(
                f"plugins.allow[{i}]: {entry.group}.{entry.name} is listed twice"
            )
        seen.add((entry.group, entry.name))
        out.append(entry)
    return tuple(out)


def _parse_entry(where: str, item: Any) -> PluginAllow:
    if not isinstance(item, dict):
        raise ValueError(f"{where} must be a mapping")
    unknown = sorted(set(item) - set(_ENTRY_KEYS))
    if unknown:
        raise ValueError(f"{where} has unknown keys {unknown}; allowed: {list(_ENTRY_KEYS)}")
    missing = [k for k in _ENTRY_KEYS if k not in item]
    if missing:
        raise ValueError(f"{where} is missing {missing}")

    for key in ("name", "group", "dist", "version"):
        if not isinstance(item[key], str) or not item[key]:
            raise ValueError(f"{where}.{key} must be a non-empty string, got {item[key]!r}")
    name, group, dist, version = (item[k] for k in ("name", "group", "dist", "version"))

    if not _NAME.match(name):
        raise ValueError(f"{where}.name must be an entry point name, got {name!r}")
    if group not in GROUPS:
        raise ValueError(f"{where}.group must be one of {GROUPS}, got {group!r}")
    if not _NAME.match(dist):
        raise ValueError(f"{where}.dist must be a distribution name, got {dist!r}")
    if _VERSION_SPECIFIER.search(version):
        raise ValueError(
            f"{where}.version must be one exact version, got {version!r}. "
            "Ranges and wildcards are refused."
        )

    profiles = item["profiles"]
    if not isinstance(profiles, list) or not profiles:
        raise ValueError(f"{where}.profiles must be a non-empty list of {PROFILES}")
    bad = [p for p in profiles if p not in PROFILES]
    if bad:
        raise ValueError(f"{where}.profiles must be drawn from {PROFILES}, got {bad!r}")
    if len(set(profiles)) != len(profiles):
        raise ValueError(f"{where}.profiles lists a profile twice: {profiles!r}")

    return PluginAllow(name=name, group=group, dist=dist, version=version,
                       profiles=tuple(profiles))


_REPORTED_UNLISTED: set[tuple[str, str]] = set()


class PluginRegistry:
    """The detector plugins one loaded policy put in use: their phrases,
    their `public_keys` by `(name, dist, version)`, and their distributions.

    `load_policy` gives each policy a new one, and `Policy.for_profile`
    shares it. A registry counts toward `loaded_distributions` while a
    policy holding it is alive.
    """

    def __init__(self) -> None:
        self.phrases: dict[str, str] = {}
        self.public_keys: dict[tuple[str, str, str], frozenset[str]] = {}
        self.dists: set[tuple[str, str]] = set()
        _LIVE_REGISTRIES.add(self)

    def register(self, detector: PluginDetector) -> None:
        self.phrases.update(detector.phrases())
        if detector.entry is not None:
            dist, version = normalize_dist(detector.entry.dist), detector.entry.version
            self.public_keys[(detector.name, dist, version)] = detector.public_keys
            self.dists.add((dist, version))

    def public_keys_for(self, entry: PluginAllow) -> frozenset[str]:
        """The public keys of the plugin `entry` names, if this registry
        holds that plugin at that distribution and version."""
        key = (entry.name, normalize_dist(entry.dist), entry.version)
        return self.public_keys.get(key, frozenset())


_LIVE_REGISTRIES: weakref.WeakSet[PluginRegistry] = weakref.WeakSet()
# Store and sink plugins, recorded when their factory returns a conforming
# object. They are opened once per process, so they are not per-policy.
_PROCESS_DISTS: set[tuple[str, str]] = set()


def loaded_distributions() -> list[str]:
    """`<dist>=<version>` for every plugin distribution in use in this
    process, sorted: store and sink plugins opened, and detector plugins
    built by a policy still alive."""
    dists = set(_PROCESS_DISTS)
    for registry in list(_LIVE_REGISTRIES):
        dists |= registry.dists
    return sorted(f"{d}={v}" for d, v in dists)


def load_plugins(allow: Iterable[PluginAllow], group: str, profile: str,
                 builtins: set[str]) -> dict[str, Any]:
    """Load the allowlisted plugins of `group` for `profile`, by name.

    Entries whose `profiles` omit `profile` are skipped, and with none left
    the installed entry points are not read. An unlisted entry point is
    logged once per process. Raises
    RuntimeError, before any `ep.load()`, when an applicable entry is not
    installed, is installed from a different distribution or version, is
    published more than once, or has a module whose `PLUGIN_API` differs
    from this one. A listed name in `builtins` is refused for every profile.
    """
    if group not in GROUPS:
        raise ValueError(f"plugin group must be one of {GROUPS}, got {group!r}")
    if profile not in PROFILES:
        raise ValueError(f"plugin profile must be one of {PROFILES}, got {profile!r}")

    entries = [e for e in allow if e.group == group]
    listed = {e.name for e in entries}
    problems: list[str] = []

    for e in entries:
        if e.name in builtins:
            problems.append(f"{group}.{e.name} is a built-in name and cannot be a plugin")
    applicable = [e for e in entries if profile in e.profiles and e.name not in builtins]
    if not applicable:
        if problems:
            raise RuntimeError(_refusal(group, profile, problems))
        return {}

    installed: dict[str, list[importlib.metadata.EntryPoint]] = {}
    for ep in importlib.metadata.entry_points(group=ENTRY_POINT_PREFIX + group):
        installed.setdefault(ep.name, []).append(ep)
    for name in sorted(set(installed) - listed):
        if (group, name) in _REPORTED_UNLISTED:
            continue
        _REPORTED_UNLISTED.add((group, name))
        log.info("plugin not in plugins.allow, not loaded",
                 extra={"fields": {"plugin": name, "group": group}})

    matched: list[tuple[PluginAllow, importlib.metadata.EntryPoint]] = []
    for e in applicable:
        eps = installed.get(e.name, [])
        where = f"{group}.{e.name}"
        if not eps:
            problems.append(f"{where} is in plugins.allow but no installed "
                            f"distribution publishes it")
            continue
        if len(eps) > 1:
            owners = sorted(_dist_label(ep) for ep in eps)
            problems.append(f"{where} is published by more than one distribution: {owners}")
            continue
        ep = eps[0]
        dist = ep.dist
        if dist is None or normalize_dist(dist.name) != normalize_dist(e.dist):
            problems.append(f"{where} is published by {_dist_label(ep)}, "
                            f"plugins.allow expects {e.dist}")
            continue
        if dist.version != e.version:
            problems.append(f"{where} is {e.dist} {dist.version} installed, "
                            f"plugins.allow pins {e.version}")
            continue
        matched.append((e, ep))

    if problems:
        raise RuntimeError(_refusal(group, profile, problems))

    from . import policy

    env_before = policy.ENV_OVERRIDES
    snapshot = dict(env_before)
    for e, ep in matched:
        where = f"{group}.{e.name}"
        module, problem = _problem(where, f"importing {ep.module}",
                                   lambda ep=ep: importlib.import_module(ep.module))
        if problem is None:
            api, problem = _problem(where, f"{ep.module}.PLUGIN_API",
                                    lambda m=module: getattr(m, "PLUGIN_API", None))
        if problem is not None:
            problems.append(problem)
        elif not (type(api) is int and api == PLUGIN_API):
            shown = repr(api) if type(api) is int or api is None else type(api).__name__
            problems.append(f"{where}: {ep.module}.PLUGIN_API is {shown}, "
                            f"this core is {PLUGIN_API!r}")
    if problems:
        raise RuntimeError(_refusal(group, profile, problems))

    loaded: dict[str, Any] = {}
    for e, ep in matched:
        obj, problem = _problem(f"{group}.{e.name}", "loading the entry point",
                                lambda ep=ep: ep.load())
        if problem is not None:
            problems.append(problem)
        loaded[e.name] = obj
    if problems:
        raise RuntimeError(_refusal(group, profile, problems))
    if policy.ENV_OVERRIDES is not env_before or dict(policy.ENV_OVERRIDES) != snapshot:
        raise RuntimeError(f"plugins.allow refused for {group} in the {profile} profile: "
                           "ENV_OVERRIDES changed while the plugins loaded")
    for e, _ep in matched:
        log.info("plugin loaded", extra={"fields": {
            "plugin": e.name, "group": group, "dist": e.dist, "version": e.version}})
    return loaded


def _dist_label(ep: importlib.metadata.EntryPoint) -> str:
    return ep.dist.name if ep.dist is not None else "<unknown distribution>"


def _call(where: str, what: str, fn: Callable[[], Any]) -> Any:
    """`fn()`, or `RuntimeError("<where>: <what> raised <Type>")` with no
    message and no cause or context if it raises."""
    failed = None
    try:
        return fn()
    except Exception as exc:  # noqa: BLE001 - reported by type only
        failed = type(exc).__name__
    raise RuntimeError(f"{where}: {what} raised {failed}") from None


def _bracketed(where: str, fn: Callable[[], Any]) -> Any:
    """`fn()`, refusing if `policy.ENV_OVERRIDES` was rebound or its
    contents changed while it ran, or no longer match the module's
    definition."""
    from . import policy

    before = policy.ENV_OVERRIDES
    snapshot = dict(before)
    out = fn()
    if policy.ENV_OVERRIDES is not before or dict(policy.ENV_OVERRIDES) != snapshot:
        raise RuntimeError(f"{where}: ENV_OVERRIDES changed while the plugin was built")
    if snapshot != dict(policy._ENV_OVERRIDE_ITEMS):
        raise RuntimeError(f"{where}: ENV_OVERRIDES differs from its definition; a plugin "
                           "built earlier in this process changed it")
    return out


def _problem(where: str, what: str, fn: Callable[[], Any]) -> tuple[Any, str | None]:
    """(`fn()`, None), or (None, "<where>: <what> raised <Type>")."""
    try:
        return _call(where, what, fn), None
    except RuntimeError as exc:
        return None, str(exc)


def _refusal(group: str, profile: str, problems: list[str]) -> str:
    lines = "\n  ".join(problems)
    return (f"plugins.allow refused for {group} in the {profile} profile; "
            f"no plugin was loaded:\n  {lines}")


# -- stores and sinks ------------------------------------------------------


def protocol_members(proto: type) -> tuple[list[str], list[str]]:
    """(methods, properties) a Protocol class declares, excluding dunders."""
    methods, props = [], []
    for name, value in vars(proto).items():
        if name.startswith("_"):
            continue
        if isinstance(value, property):
            props.append(name)
        elif callable(value):
            methods.append(name)
    return methods, props


_MISSING = object()


def check_conforms(obj: Any, proto: type, where: str) -> Any:
    """Return `obj` if it has every method and property `proto` declares."""
    methods, props = protocol_members(proto)
    missing = [m for m in methods
               if not callable(_call(where, m, lambda m=m: getattr(obj, m, None)))]
    for p in props:
        if _call(where, p, lambda p=p: getattr(obj, p, _MISSING)) is _MISSING:
            missing.append(p)
    if missing:
        raise RuntimeError(f"{where}: the plugin's {type(obj).__name__} does not "
                           f"satisfy {proto.__name__}; missing {sorted(missing)}")
    return obj


def build_plugin(entry: PluginAllow, profile: str | None, builtins: set[str],
                 proto: type, *args: Any, **kwargs: Any) -> Any:
    """Load `entry`, call its factory, and check the result against `proto`.

    Raises when the profile is None or not in `entry.profiles`: the caller
    has already decided this spec or type belongs to the plugin, so there
    is no built-in to fall back to.
    """
    where = f"{entry.group}.{entry.name}"
    if profile is None or profile not in entry.profiles:
        raise RuntimeError(f"{where} is configured here, but plugins.allow does not list "
                           f"the {profile or 'current'} profile for it")
    factory = load_plugins([entry], entry.group, profile, builtins)[entry.name]
    obj = _bracketed(where, lambda: (
        check_conforms(_call(where, "the plugin factory", lambda: factory(*args, **kwargs)),
                       proto, where)))
    _PROCESS_DISTS.add((normalize_dist(entry.dist), entry.version))
    return PluginGuard(obj, where)


class PluginCallFailed(RuntimeError):
    """A store or sink plugin raised an exception that is neither a builtin
    nor a forgd_verdict class, or one that could not be rebuilt."""


def _core_class(exc_type: type[BaseException]) -> type[BaseException]:
    """The first class in `exc_type`'s MRO that is a builtin or defined in
    forgd_verdict, so an `except` the core wrote still matches."""
    for k in exc_type.__mro__:
        if k.__module__ == "builtins" or k.__module__.startswith("forgd_verdict."):
            return k
    return PluginCallFailed


def _guarded(where: str, what: str, fn: Callable[[], Any]) -> Any:
    """`fn()`, with any exception replaced by the nearest builtin or core
    class carrying only `<where>: <what> raised <Type>`, and no chain."""
    failed: tuple[type[BaseException], str] | None = None
    try:
        return fn()
    except Exception as exc:  # noqa: BLE001 - re-raised as its type only
        failed = (_core_class(type(exc)), type(exc).__name__)
    cls, name = failed
    message = f"{where}: {what} raised {name}"
    try:
        replacement = cls(message)
    except Exception:  # noqa: BLE001 - a class that takes other arguments
        replacement = PluginCallFailed(message)
    raise replacement from None


class _GuardedIterator:
    def __init__(self, it: Iterator[Any], where: str, what: str):
        self._it, self._where, self._what = it, where, what

    def __iter__(self) -> _GuardedIterator:
        return self

    def __next__(self) -> Any:
        try:
            return _guarded(self._where, self._what, lambda: next(self._it))
        except StopIteration:
            raise StopIteration from None


class PluginGuard:
    """A store or sink plugin as the core holds it.

    Every attribute read and method call goes to the plugin object. An
    exception from either, or from iterating an iterator a method
    returned, is re-raised by `_guarded`: same core or builtin class, no
    message from the plugin, no cause or context.
    """

    def __init__(self, obj: Any, where: str):
        object.__setattr__(self, "_plugin_obj", obj)
        object.__setattr__(self, "plugin", where)

    def __getattr__(self, name: str) -> Any:
        if name.startswith("__"):
            raise AttributeError(name)
        obj, where = self._plugin_obj, self.plugin
        value = _guarded(where, name, lambda: getattr(obj, name))
        if not callable(value):
            return value

        def method(*args: Any, **kwargs: Any) -> Any:
            out = _guarded(where, name, lambda: value(*args, **kwargs))
            return _GuardedIterator(out, where, name) if isinstance(out, Iterator) else out

        return method

    def __setattr__(self, name: str, value: Any) -> None:
        setattr(self._plugin_obj, name, value)

    def __repr__(self) -> str:
        return f"<{self.plugin} plugin>"


def describe_for_log(obj: Any) -> dict[str, Any]:
    """`obj.describe()`, or `{"plugin": "<group>.<name>"}` for a store or
    sink plugin, whose description is the plugin's own text."""
    if isinstance(obj, PluginGuard):
        return {"plugin": obj.plugin}
    return obj.describe()


def refuse_shadowing(allow: Iterable[PluginAllow], group: str, builtins: Iterable[str]) -> None:
    clash = sorted({e.name for e in allow if e.group == group} & set(builtins))
    if clash:
        raise RuntimeError(f"plugins.allow names built-in {group} {clash}; "
                           "a plugin cannot replace a built-in")


BUILTIN_STORE_SCHEMES = ("https", "http", "s3", "gs", "file")
# Two characters or more, so a Windows drive letter (`C:\\findings`) is a path.
_STORE_SCHEME = re.compile(r"^([a-z][a-z0-9+.-]+):")


def store_scheme(spec: str) -> str | None:
    """The scheme of a store spec that is not a built-in one, or None."""
    m = _STORE_SCHEME.match(spec)
    return m.group(1) if m and m.group(1) not in BUILTIN_STORE_SCHEMES else None


def find_entry(allow: Iterable[PluginAllow], group: str, name: str) -> PluginAllow | None:
    return next((e for e in allow if e.group == group and e.name == name), None)


def refuse_unlisted(group: str, name: str, what: str) -> None:
    """Raise when an installed distribution publishes `name` in `group`.

    For a store scheme or sink type that no `plugins.allow` entry covers:
    with a publisher installed, the spec was meant for that plugin, and
    falling back to a built-in would write somewhere nobody configured.
    """
    eps = [ep for ep in importlib.metadata.entry_points(group=ENTRY_POINT_PREFIX + group)
           if ep.name == name]
    if not eps:
        return
    ep = eps[0]
    dist = _dist_label(ep)
    version = ep.dist.version if ep.dist is not None else "<version>"
    raise RuntimeError(
        f"{what} is published by the installed distribution {dist} as "
        f"{ENTRY_POINT_PREFIX}{group} entry point {name!r}, and plugins.allow has no "
        f"entry for it. Add {{name: {name}, group: {group}, dist: {dist}, "
        f"version: {version}, profiles: [...]}} to plugins.allow, or uninstall {dist}.")


# -- the detector boundary ------------------------------------------------

_HASH = re.compile(r"^[0-9a-f]{64}\Z")
_PREFIX = re.compile(r"^[a-z0-9][a-z0-9._-]*\Z")


def _id_pattern(prefix: str) -> re.Pattern[str]:
    """A finding id a plugin with `prefix` may report: the prefix, or the
    prefix, a colon and a suffix."""
    return re.compile(rf"^{re.escape(prefix)}(:[a-z0-9._-]+)?\Z")
_TIERS = (0, 1, 2)
FOREIGN_LOCATOR = "<not an input locator>"


def _withheld(_text: str) -> str:
    return "<withheld>"


def _normalize(text: str) -> str:
    return " ".join("".join(c if c.isprintable() else " " for c in text).split())


class PluginDetector:
    """A plugin detector as the core sees it.

    Findings are checked against the units they came from and dropped with
    an ERROR naming the detector, the check and the locator. An exception
    from the plugin's `scan` becomes `DetectorFailed("<name>: <type>")` with
    no cause and no context. `scrub` is applied to every locator this class
    logs and screens every phrase from `phrases()`. `build_detectors` sets it
    to the core's label scrub over the built-in cheap tiers while detectors
    are built, and over those plus every plugin detector it kept once they
    all are.
    """

    def __init__(self, name: str, inner: Any, severity: str, hasher: Callable[[str], str],
                 scrub: Callable[[str], str] = _withheld, entry: PluginAllow | None = None):
        if name in RESERVED_DETECTOR_NAMES:
            raise RuntimeError(f"detectors.{name}: the name belongs to a built-in detector")
        self.name = name
        self.entry = entry
        self.severity = severity
        self.scrub = scrub
        self._inner = inner
        self._hasher = hasher

        where = f"detectors.{name}"
        tier = _call(where, "tier", lambda: getattr(inner, "tier", None))
        if type(tier) is not int or tier not in _TIERS:
            raise RuntimeError(f"detectors.{name}: the plugin's tier must be one of {_TIERS}")
        self.tier = tier

        prefix = _call(where, "finding_prefix", lambda: getattr(inner, "finding_prefix", name))
        if type(prefix) is not str or not _PREFIX.match(prefix):
            raise RuntimeError(f"detectors.{name}: finding_prefix must match {_PREFIX.pattern}")
        if prefix in RESERVED_DETECTOR_NAMES:
            raise RuntimeError(f"detectors.{name}: finding_prefix {prefix!r} "
                               "belongs to a built-in detector")
        self.finding_prefix = prefix
        self._id = _id_pattern(prefix)

        public = _call(where, "public_keys", lambda: getattr(inner, "public_keys", ()))
        keys = None if isinstance(public, (str, bytes)) else _call(
            where, "public_keys", lambda: list(public))
        if keys is None or not all(type(k) is str for k in keys):
            raise RuntimeError(f"detectors.{name}: public_keys must be a collection of str")
        self.public_keys = frozenset(keys)

        local_only = _call(where, "local_only", lambda: getattr(inner, "local_only", False))
        if not isinstance(local_only, bool):
            raise RuntimeError(f"detectors.{name}: local_only must be a bool")
        self.local_only = local_only

        self._finding_ids = self._declared_ids(name, inner)
        self._phrases = self._declared_phrases(name, inner)

    def _declared_ids(self, name: str, inner: Any) -> frozenset[str]:
        where = f"detectors.{name}"
        fn = _call(where, "finding_ids", lambda: getattr(inner, "finding_ids", None))
        if not callable(fn):
            raise RuntimeError(f"detectors.{name}: the plugin must declare finding_ids()")

        def read() -> list[Any] | None:
            ids = fn()
            return None if isinstance(ids, (str, bytes)) else list(ids)

        ids = _call(where, "finding_ids()", read)
        if not ids:
            raise RuntimeError(f"detectors.{name}: finding_ids() must return a "
                               "non-empty collection of str")
        for i, fid in enumerate(ids):
            if not (type(fid) is str and len(fid) <= FINDING_ID_MAX
                    and self._id.match(fid)):
                raise RuntimeError(
                    f"detectors.{name}: finding_ids()[{i}] must be a str of at most "
                    f"{FINDING_ID_MAX} characters matching {self._id.pattern}")
        return frozenset(ids)

    def _declared_phrases(self, name: str, inner: Any) -> Mapping[str, str]:
        """`phrases()` normalized and screened, or empty when the plugin
        declares none or is not available."""
        where = f"detectors.{name}"
        fn = _call(where, "phrases", lambda: getattr(inner, "phrases", None))
        if fn is None:
            return MappingProxyType({})

        def read() -> list[tuple[Any, Any]] | None:
            raw = fn() if callable(fn) else None
            return list(raw.items()) if isinstance(raw, Mapping) else None

        items = _call(where, "phrases()", read)
        if items is None:
            raise RuntimeError(f"detectors.{name}: phrases() must return a mapping")

        phrases: dict[str, str] = {}
        for fid, value in items:
            if type(fid) is not str or fid not in self._finding_ids:
                raise RuntimeError(f"detectors.{name}: phrases() has a key that is not "
                                   "one of finding_ids()")
            phrase = _normalize(value) if type(value) is str else ""
            if not phrase or len(phrase) > PHRASE_MAX:
                raise RuntimeError(f"detectors.{name}: the phrase for {fid} must be a "
                                   f"non-empty str of at most {PHRASE_MAX} characters")
            if self.scrub(phrase) != phrase:
                raise RuntimeError(f"detectors.{name}: the phrase for {fid} matches a "
                                   "built-in detector")
            phrases[fid] = phrase
        if not phrases or not self.available():
            return MappingProxyType({})

        units = [ScanUnit(f"phrases[{fid}]", None, p) for fid, p in phrases.items()]
        found = _call(where, "scanning its phrases", lambda: list(inner.scan(units)))
        if found:
            raise RuntimeError(f"detectors.{name}: the plugin's own scan matches one of "
                               "its phrases")
        return MappingProxyType(phrases)

    @classmethod
    def build(cls, name: str, factory: Callable[..., Any], cfg: Mapping[str, Any],
              severity: str, hasher: Callable[[str], str],
              scrub: Callable[[str], str] = _withheld,
              entry: PluginAllow | None = None) -> PluginDetector:
        where = f"detectors.{name}"

        def construct() -> PluginDetector:
            inner = _call(where, "the plugin factory", lambda: factory(cfg, severity, hasher))
            return cls(name, inner, severity, hasher, scrub, entry)

        return _bracketed(where, construct)

    def available(self) -> bool:
        """The plugin's `available()`, called only while building. An
        exception refuses to start, reported by type."""
        return _call(f"detectors.{self.name}", "available()",
                     lambda: bool(self._inner.available()))

    def finding_ids(self) -> list[str]:
        """The ids the plugin declared when it was built, sorted."""
        return sorted(self._finding_ids)

    def phrases(self) -> Mapping[str, str]:
        """The deny-reason phrases the plugin declared when it was built."""
        return self._phrases

    def probe_all(self, texts: Sequence[str]) -> set[int]:
        """The indexes of `texts` the plugin's own scan returns anything for,
        in one call. Same rules as `probe`: every finding counts, so if any
        finding does not name one of the units it falls back to `probe` per
        text rather than drop it."""
        failed = None
        try:
            found = list(self._inner.scan([ScanUnit(str(i), None, t)
                                           for i, t in enumerate(texts)]))
            names = [getattr(f, "locator", None) for f in found]
        except Exception as exc:  # noqa: BLE001 - reported by type only
            failed = type(exc).__name__
        if failed is not None:
            raise DetectorFailed(f"{self.name}: {failed}") from None
        index = {str(i): i for i in range(len(texts))}
        if all(type(n) is str and n in index for n in names):
            return {index[n] for n in names}
        return {i for i, t in enumerate(texts) if self.probe(t)}

    def probe(self, text: str) -> bool:
        """Whether the plugin's own scan returns anything for `text`.

        Every finding counts, including one `scan` would refuse, and nothing
        is logged. An exception becomes `DetectorFailed("<name>: <type>")`
        as in `scan`.
        """
        failed = None
        try:
            hit = bool(list(self._inner.scan([ScanUnit("_", None, text)])))
        except Exception as exc:  # noqa: BLE001 - reported by type only
            failed = type(exc).__name__
        if failed is not None:
            raise DetectorFailed(f"{self.name}: {failed}") from None
        return hit

    def scan(self, units: Iterable[ScanUnit]) -> list[Finding]:
        units = list(units)
        failed = None
        try:
            found = list(self._inner.scan(units))
        except Exception as exc:  # noqa: BLE001 - reported by type only
            failed = type(exc).__name__
        # Raised outside the except block so `__context__` is None as well
        # as `__cause__`.
        if failed is not None:
            raise DetectorFailed(f"{self.name}: {failed}") from None

        texts: dict[tuple[str, str | None], list[str]] = {}
        for u in units:
            texts.setdefault((u.locator, u.tool_name), []).append(u.text)
        out: list[Finding] = []
        for f in found:
            try:
                check = self._refusal(f, texts)
            except Exception:  # noqa: BLE001 - a malformed finding is refused, never raised
                check = "type"
            if check is None:
                # The value is the span the hash was checked against, never
                # one the plugin supplied, and only the core seals.
                out.append(replace(f, matched=self._span_value(f, texts), sealed=None))
                continue
            where = FOREIGN_LOCATOR if check in ("type", "locator") else self.scrub(f.locator)
            log.error("plugin finding refused", extra={"fields": {
                "detector": self.name, "check": check, "locator": where}})
        return out

    def _span_value(self, f: Finding, texts: dict[tuple[str, str | None], list[str]]
                    ) -> str | None:
        """The text at `f`'s span whose digest is `f.excerpt_hash`."""
        for t in texts[(f.locator, f.tool_name)]:
            s = t[f.start:f.end]
            if self._hasher(s) == f.excerpt_hash:
                return s
        return None

    def _refusal(self, f: Any, texts: dict[tuple[str, str | None], list[str]]) -> str | None:
        """The first check `f` fails, or None.

        Exact types, never isinstance: a str subclass can override __eq__
        and pass every comparison below while carrying matched text.
        """
        if type(f) is not Finding:
            return "type"
        if type(f.locator) is not str or not (f.tool_name is None
                                              or type(f.tool_name) is str):
            return "locator"
        key = (f.locator, f.tool_name)
        if key not in texts:
            return "locator"
        if type(f.excerpt_hash) is not str or not _HASH.match(f.excerpt_hash):
            return "excerpt_hash"
        if type(f.detector) is not str or f.detector not in self._finding_ids:
            return "detector"
        if type(f.severity) is not str or f.severity != self.severity:
            return "severity"
        if not (type(f.start) is int and type(f.end) is int):
            return "span"
        spans = [t[f.start:f.end] for t in texts[key] if 0 <= f.start < f.end <= len(t)]
        if not spans:
            return "span"
        if not any(self._hasher(s) == f.excerpt_hash for s in spans):
            return "excerpt_hash"
        return None
