"""The plugin allowlist: parsing `plugins:` and loading entry points from it.

Each loading test installs a real distribution into a scratch directory on
`sys.path` -- a `.dist-info` with METADATA and entry_points.txt beside the
module -- so `importlib.metadata` resolves `ep.dist` the way it would for a
pip-installed plugin.
"""

from __future__ import annotations

import json
import logging
import sys
import textwrap
import weakref
from collections.abc import Mapping

import pytest

from forgd_verdict import plugins as plugins_mod
from forgd_verdict.detectors.base import DetectorFailed
from forgd_verdict.models import Finding, ScanUnit, digest, hasher_for
from forgd_verdict.plugins import (
    BUILTIN_DETECTORS,
    GROUPS,
    PHRASE_MAX,
    PLUGIN_API,
    PROFILES,
    PluginAllow,
    PluginDetector,
    load_plugins,
    parse_allow,
)


def _entry(**over):
    base = {"name": "acme_ids", "group": "detectors", "dist": "acme-forgd",
            "version": "1.4.2", "profiles": ["server"]}
    base.update(over)
    return base


def _allow(**over):
    return parse_allow({"allow": [_entry(**over)]})


@pytest.fixture
def install(tmp_path, monkeypatch):
    """Install a distribution publishing one entry point; returns its module name."""
    n = 0

    def _install(*, dist="acme_forgd", version="1.4.2", group="detectors",
                 name="acme_ids", api=PLUGIN_API, module=None, attr="Detector",
                 source=""):
        nonlocal n
        n += 1
        module = module or f"acme_plugin_{n}"
        root = tmp_path / f"site{n}"
        info = root / f"{dist}-{version}.dist-info"
        info.mkdir(parents=True)
        (info / "METADATA").write_text(
            f"Metadata-Version: 2.1\nName: {dist}\nVersion: {version}\n")
        (info / "entry_points.txt").write_text(
            f"[forgd_verdict.{group}]\n{name} = {module}:{attr}\n")
        api_line = "" if api is None else f"PLUGIN_API = {api!r}\n"
        (root / f"{module}.py").write_text(api_line + textwrap.dedent("""
            LOADED = []
            class Detector:
                pass
            LOADED.append(1)
        """) + textwrap.dedent(source))
        monkeypatch.syspath_prepend(str(root))
        monkeypatch.delitem(sys.modules, module, raising=False)
        return module

    return _install


# -- parse_allow ---------------------------------------------------------


def test_absent_section_is_no_plugins():
    assert parse_allow(None) == ()
    assert parse_allow({}) == ()


def test_a_valid_entry_parses():
    (e,) = _allow(profiles=["server", "compliance"])
    assert e == PluginAllow("acme_ids", "detectors", "acme-forgd", "1.4.2",
                            ("server", "compliance"))


@pytest.mark.parametrize("version", [
    ">=1.4", "1.4.*", "~=1.4", "^1.4", "==1.4.2", "1.4,<2", "!=1.4", "1.4 ", "",
])
def test_a_version_that_is_not_exact_is_refused(version):
    with pytest.raises(ValueError, match=r"plugins\.allow\[0\]\.version"):
        _allow(version=version)


@pytest.mark.parametrize("profiles", [[], ["everywhere"], "server", ["server", "server"]])
def test_profiles_must_be_a_nonempty_subset(profiles):
    with pytest.raises(ValueError, match=r"plugins\.allow\[0\]\.profiles"):
        _allow(profiles=profiles)


def test_an_unknown_group_is_refused():
    with pytest.raises(ValueError, match=r"\.group must be one of"):
        _allow(group="exporters")


def test_a_missing_key_is_refused():
    raw = _entry()
    del raw["dist"]
    with pytest.raises(ValueError, match=r"missing \['dist'\]"):
        parse_allow({"allow": [raw]})


def test_an_unknown_key_is_refused():
    with pytest.raises(ValueError, match="unknown keys"):
        parse_allow({"allow": [_entry(enabled=True)]})
    with pytest.raises(ValueError, match="unknown keys"):
        parse_allow({"allow": [], "trust": "all"})


def test_a_name_listed_twice_in_a_group_is_refused():
    with pytest.raises(ValueError, match="listed twice"):
        parse_allow({"allow": [_entry(), _entry(dist="other")]})


def test_the_same_name_in_two_groups_is_allowed():
    assert len(parse_allow({"allow": [_entry(), _entry(group="sinks")]})) == 2


def test_the_constants():
    assert GROUPS == ("detectors", "stores", "sinks")
    assert "hook" in PROFILES and "collector" in PROFILES


# -- load_plugins --------------------------------------------------------


def test_an_exact_match_loads(install):
    mod = install()
    out = load_plugins(_allow(), "detectors", "server", set())
    assert out["acme_ids"].__name__ == "Detector"
    assert sys.modules[mod].LOADED == [1]


def test_the_dist_name_is_compared_normalised(install):
    install(dist="Acme_Forgd")
    assert "acme_ids" in load_plugins(_allow(dist="acme.forgd"), "detectors", "server", set())


def test_a_profile_outside_the_entry_is_skipped_without_import(install):
    mod = install()
    assert load_plugins(_allow(profiles=["compliance"]), "detectors", "server", set()) == {}
    assert mod not in sys.modules


def test_a_profile_outside_the_entry_is_not_required_to_be_installed():
    assert load_plugins(_allow(profiles=["compliance"]), "detectors", "server", set()) == {}


def test_hook_is_not_implied_by_any_other_profile(install):
    install()
    every_other = [p for p in PROFILES if p != "hook"]
    assert load_plugins(_allow(profiles=every_other), "detectors", "hook", set()) == {}


def test_the_profile_must_be_known():
    with pytest.raises(ValueError, match="profile must be one of"):
        load_plugins((), "detectors", "audit", set())


def test_a_listed_plugin_that_is_not_installed_is_refused():
    with pytest.raises(RuntimeError, match="no installed distribution publishes it"):
        load_plugins(_allow(), "detectors", "server", set())


def test_the_wrong_dist_is_refused_before_import(install):
    mod = install(dist="evil_forgd")
    with pytest.raises(RuntimeError, match="published by evil_forgd"):
        load_plugins(_allow(), "detectors", "server", set())
    assert mod not in sys.modules


def test_the_wrong_version_is_refused_before_import(install):
    mod = install(version="1.4.3")
    with pytest.raises(RuntimeError, match="1.4.3 installed, plugins.allow pins 1.4.2"):
        load_plugins(_allow(), "detectors", "server", set())
    assert mod not in sys.modules


def test_a_name_published_twice_is_refused(install):
    install()
    install(dist="other_forgd")
    with pytest.raises(RuntimeError, match="more than one distribution"):
        load_plugins(_allow(), "detectors", "server", set())


def test_a_builtin_name_is_refused_in_every_profile():
    with pytest.raises(RuntimeError, match="built-in name"):
        load_plugins(_allow(name="t0_regex", profiles=["compliance"]),
                     "detectors", "server", {"t0_regex"})


@pytest.mark.parametrize("api", [PLUGIN_API + 1, None, str(PLUGIN_API)])
def test_an_api_mismatch_is_refused_before_ep_load(install, api):
    mod = install(api=api)
    with pytest.raises(RuntimeError, match="PLUGIN_API"):
        load_plugins(_allow(), "detectors", "server", set())
    assert sys.modules[mod].LOADED == [1]  # imported to read PLUGIN_API, never handed out


def test_one_bad_entry_loads_nothing(install):
    good = install()
    install(name="beta_ids", dist="beta_forgd", version="2.0.0")
    allow = parse_allow({"allow": [
        _entry(), _entry(name="beta_ids", dist="beta-forgd", version="2.0.1"),
    ]})
    with pytest.raises(RuntimeError) as exc:
        load_plugins(allow, "detectors", "server", set())
    assert "beta_ids" in str(exc.value)
    assert good not in sys.modules


def test_every_problem_is_in_the_one_error(install):
    install(version="9.9.9")
    allow = parse_allow({"allow": [_entry(), _entry(name="gone")]})
    with pytest.raises(RuntimeError) as exc:
        load_plugins(allow, "detectors", "server", set())
    assert "acme_ids" in str(exc.value) and "gone" in str(exc.value)


def _unlisted(caplog):
    return [r for r in caplog.records if "not in plugins.allow" in r.getMessage()]


def test_an_unlisted_entry_point_is_logged_and_never_imported(install, caplog):
    install()
    mod = install(name="stray", dist="stray_forgd")
    caplog.set_level(logging.INFO, logger="forgd_verdict.plugins")
    assert set(load_plugins(_allow(), "detectors", "server", set())) == {"acme_ids"}
    assert mod not in sys.modules
    (rec,) = _unlisted(caplog)
    assert rec.levelno == logging.INFO
    assert rec.fields == {"plugin": "stray", "group": "detectors"}


def test_an_unlisted_entry_point_is_logged_once_per_process(install, caplog):
    install()
    install(name="stray", dist="stray_forgd")
    caplog.set_level(logging.INFO, logger="forgd_verdict.plugins")
    for _ in range(3):
        load_plugins(_allow(), "detectors", "server", set())
    assert len(_unlisted(caplog)) == 1


def test_nothing_applicable_reads_no_entry_points(monkeypatch):
    def boom(**kw):
        raise AssertionError("entry_points read")

    monkeypatch.setattr(plugins_mod.importlib.metadata, "entry_points", boom)
    assert load_plugins((), "detectors", "server", set()) == {}
    assert load_plugins(_allow(profiles=["compliance"]), "detectors", "server", set()) == {}
    with pytest.raises(RuntimeError, match="built-in name"):
        load_plugins(_allow(name="t0_regex"), "detectors", "server", {"t0_regex"})


def test_other_groups_are_not_consulted(install):
    install(group="sinks")
    assert load_plugins(_allow(), "sinks", "server", set()) == {}
    with pytest.raises(RuntimeError, match="no installed distribution"):
        load_plugins(_allow(), "detectors", "server", set())


# -- the policy ----------------------------------------------------------


def test_the_policy_without_plugins_is_unchanged(tmp_path):
    from forgd_verdict.policy import load_policy, redacted

    p = tmp_path / "policy.yaml"
    p.write_text("server: {mode: observe}\n")
    policy = load_policy(p)
    assert policy.plugin_allow == ()
    assert "plugins" not in policy.raw
    assert "plugins" not in redacted(policy)


def test_the_policy_exposes_the_allowlist(tmp_path):
    from forgd_verdict.policy import load_policy

    p = tmp_path / "policy.yaml"
    p.write_text(textwrap.dedent("""
        plugins:
          allow:
            - {name: acme_ids, group: detectors, dist: acme-forgd,
               version: 1.4.2, profiles: [server]}
    """))
    assert load_policy(p).plugin_allow == _allow()


def test_a_malformed_plugins_section_refuses_the_load(tmp_path):
    from forgd_verdict.policy import load_policy

    p = tmp_path / "policy.yaml"
    p.write_text("plugins: {allow: [{name: x, group: detectors, dist: d, "
                 "version: '>=1', profiles: [server]}]}\n")
    with pytest.raises(ValueError, match="exact version"):
        load_policy(p)


# -- detectors -------------------------------------------------------------

AWS = "AKIAQYLPMN5HGZTHX4UQ"  # gitleaks:allow
SALT = "deployment-salt-7f3a9c"

DETECTOR_SOURCE = """
import re

SEEN = []
DESCRIBED = []


class Zebra:
    tier = 1
    finding_prefix = "zebra"

    def __init__(self, cfg, severity, hasher):
        self.cfg, self.severity, self.hasher = cfg, severity, hasher
        self.local_only = bool(cfg.get("local_only_for_test", False))

    def available(self):
        return not self.cfg.get("unavailable_for_test", False)

    def finding_ids(self):
        return self.cfg.get("ids_for_test", ["zebra:stripe"])

    def phrases(self):
        return {"zebra:stripe": self.cfg.get("phrase_for_test", "a zebra code")}

    def describe(self, finding_id):
        DESCRIBED.append(finding_id)
        raise AssertionError("describe is not part of the plugin API")

    def scan(self, units):
        from forgd_verdict.models import Finding
        out = []
        for u in units:
            for m in re.finditer(r"zebra-[0-9]{6}", u.text):
                out.append(Finding("zebra:stripe", self.severity, u.locator,
                                   self.hasher(m.group()), u.tool_name,
                                   m.start(), m.end()))
        return out


def make(cfg, severity, hasher):
    SEEN.append((cfg, severity, hasher))
    return Zebra(cfg, severity, hasher)
"""


@pytest.fixture(autouse=True)
def _fresh_plugin_state(monkeypatch):
    monkeypatch.setattr(plugins_mod, "_REPORTED_UNLISTED", set())
    monkeypatch.setattr(plugins_mod, "_PROCESS_DISTS", set())
    monkeypatch.setattr(plugins_mod, "_LIVE_REGISTRIES", weakref.WeakSet())


def _policy(tmp_path, *, profiles=("server",), cfg=None, extra=""):
    from forgd_verdict.policy import load_policy

    cfg = {"enabled": True, "severity": "block", **(cfg or {})}
    p = tmp_path / "policy.yaml"
    p.write_text(textwrap.dedent(f"""
        privacy: {{hash_salt: {SALT}}}
        plugins:
          allow:
            - {{name: zebra, group: detectors, dist: acme-forgd, version: 1.4.2,
               profiles: {json.dumps(list(profiles))}}}
        detectors:
          zebra: {json.dumps(cfg)}
    """) + extra)
    return load_policy(p)


@pytest.fixture
def zebra(install):
    return install(name="zebra", attr="make", source=DETECTOR_SOURCE)


def _zebras(dets):
    return [d for d in dets if isinstance(d, PluginDetector)]


def test_builtin_detector_names_are_the_default_policy(tmp_path):
    from forgd_verdict.policy import DEFAULT_POLICY

    assert set(DEFAULT_POLICY["detectors"]) == BUILTIN_DETECTORS


@pytest.mark.parametrize("section", ["", "server", "hook", "compliance", "otel"])
def test_an_unknown_detector_name_refuses(tmp_path, section):
    from forgd_verdict.policy import load_policy

    p = tmp_path / "policy.yaml"
    body = "detectors: {t0_regexx: {enabled: true}}\n"
    p.write_text(f"{section}:\n  " + body if section else body)
    policy = load_policy(p)
    with pytest.raises(RuntimeError, match="t0_regexx is enabled but is not a built-in"):
        policy.build_detectors()
    with pytest.raises(RuntimeError, match="t0_regexx"):
        policy.build_detectors(profile="server")


def _unknown_warnings(caplog):
    return [r for r in caplog.records
            if r.getMessage() == "unknown detector name, disabled and ignored"]


@pytest.mark.parametrize("cfg", ["{enabled: true}", "{enabled: auto}", "true"])
def test_an_enabled_unknown_detector_name_refuses_naming_it(tmp_path, cfg):
    from forgd_verdict.policy import load_policy

    p = tmp_path / "policy.yaml"
    p.write_text(f"server:\n  detectors:\n    zebrah: {cfg}\n")
    with pytest.raises(RuntimeError, match=r"server\.detectors\.zebrah is enabled but") as exc:
        load_policy(p).build_detectors(profile="server")
    assert "remove it" in str(exc.value)
    assert "plugins.allow" in str(exc.value)


@pytest.mark.parametrize("cfg", ["{enabled: false}", "{severity: warn}"])
def test_a_disabled_unknown_detector_name_warns_once_per_load(tmp_path, caplog, cfg):
    from forgd_verdict.policy import load_policy

    p = tmp_path / "policy.yaml"
    p.write_text(f"detectors:\n  zebrah: {cfg}\nserver:\n  detectors:\n    zebrah: {cfg}\n")
    caplog.set_level(logging.WARNING, logger="forgd_verdict.policy")
    pol = load_policy(p)
    names = {d.name for d in pol.build_detectors()}
    pol.build_detectors(profile="server")
    pol.for_profile("server").build_detectors(profile="server")
    assert "zebrah" not in names
    (rec,) = _unknown_warnings(caplog)
    assert rec.levelno == logging.WARNING
    assert rec.fields == {"detector": "detectors.zebrah"}
    load_policy(p).build_detectors()
    assert len(_unknown_warnings(caplog)) == 2


def test_the_shipped_policy_logs_nothing_new(caplog):
    assert_logs_nothing_new("policy.yaml", caplog)


def assert_logs_nothing_new(path: str, caplog) -> None:
    from forgd_verdict.policy import load_policy

    caplog.set_level(logging.DEBUG, logger="forgd_verdict.policy")
    caplog.set_level(logging.DEBUG, logger="forgd_verdict.plugins")
    pol = load_policy(path)
    for prof in ("server", "hook", "compliance", "otel"):
        pol.for_profile(prof).build_detectors(profile="server")
    assert [r for r in caplog.records
            if r.name in ("forgd_verdict.policy", "forgd_verdict.plugins")] == []


def test_an_unknown_sink_detector_name_refuses(tmp_path):
    from forgd_verdict.policy import load_policy

    p = tmp_path / "policy.yaml"
    p.write_text("otel: {sink_detectors: {presidio: {enabled: true}}}\n")
    with pytest.raises(RuntimeError, match=r"otel\.sink_detectors\.presidio"):
        load_policy(p).build_detectors()


@pytest.mark.parametrize("profile", PROFILES)
def test_no_plugins_touches_neither_metadata_nor_the_logger(profile, monkeypatch, caplog):
    from forgd_verdict.policy import load_policy

    def boom(**kw):
        raise AssertionError("entry_points read")

    monkeypatch.setattr(plugins_mod.importlib.metadata, "entry_points", boom)
    caplog.set_level(logging.DEBUG, logger="forgd_verdict.plugins")
    pol = load_policy("policy.yaml")
    for section in ("server", "hook", "compliance", "otel"):
        pol.for_profile(section).build_detectors(include_local_only=True, profile=profile)
    assert [r for r in caplog.records if r.name == "forgd_verdict.plugins"] == []


def test_the_shipped_policy_builds_unchanged():
    assert_builds_unchanged("policy.yaml")


def assert_builds_unchanged(path: str) -> None:
    from forgd_verdict.policy import load_policy

    pol = load_policy(path)
    assert pol.plugin_allow == ()
    for prof in ("server", "hook", "compliance", "otel"):
        assert not _zebras(pol.for_profile(prof).build_detectors(profile="server"))


def _builtin_detector_classes():
    """Every class under `detectors/` and `behaviour/` with a str `name` and an
    int `tier`."""
    import importlib
    import inspect
    import pkgutil

    import forgd_verdict.behaviour
    import forgd_verdict.detectors

    found = set()
    for pkg in (forgd_verdict.detectors, forgd_verdict.behaviour):
        for info in pkgutil.iter_modules(pkg.__path__):
            mod = importlib.import_module(f"{pkg.__name__}.{info.name}")
            for _n, cls in inspect.getmembers(mod, inspect.isclass):
                if (cls.__module__ == mod.__name__ and isinstance(getattr(cls, "name", None), str)
                        and type(getattr(cls, "tier", None)) is int):
                    found.add(cls)
    return found


def test_every_builtin_detector_class_is_reserved():
    import forgd_verdict.detectors

    classes = _builtin_detector_classes()
    in_detectors = {c for c in classes if c.__module__.startswith(forgd_verdict.detectors.__name__)}
    assert in_detectors == set(plugins_mod.BUILTIN_DETECTOR_CLASSES)
    assert {c.name for c in classes} <= plugins_mod.BUILTIN_RUNTIME_NAMES
    assert plugins_mod.BUILTIN_RUNTIME_NAMES <= plugins_mod.RESERVED_DETECTOR_NAMES


@pytest.mark.parametrize("name", ["regex", "shell", "checksum", "presidio_pii", "presidio",
                                  "provenance"])
def test_a_plugin_named_like_a_builtin_runtime_name_refuses(tmp_path, install, name):
    from forgd_verdict.policy import load_policy

    install(name=name, attr="make", source=DETECTOR_SOURCE)
    p = tmp_path / "policy.yaml"
    p.write_text(f"plugins: {{allow: [{{name: {name}, group: detectors, dist: acme-forgd, "
                 f"version: 1.4.2, profiles: [server]}}]}}\n")
    with pytest.raises(RuntimeError, match="built-in detectors"):
        load_policy(p).build_detectors(profile="server")
    with pytest.raises(RuntimeError, match="built-in"):
        load_plugins(parse_allow({"allow": [_entry(name=name)]}), "detectors", "server",
                     set(plugins_mod.RESERVED_DETECTOR_NAMES))
    with pytest.raises(RuntimeError, match="belongs to a built-in"):
        PluginDetector(name, _Inner(), "block", HASHER)


@pytest.mark.parametrize("prefix", ["shell", "presidio_pii", "llmguard_pii", "t0_regex"])
def test_a_finding_prefix_naming_a_builtin_refuses(prefix):
    class Inner(_Inner):
        finding_prefix = prefix

        def finding_ids(self):
            return [prefix]

    with pytest.raises(RuntimeError, match="belongs to a built-in"):
        PluginDetector("zebra", Inner(), "block", HASHER)


def test_a_builtin_name_in_the_allowlist_refuses(tmp_path):
    from forgd_verdict.policy import load_policy

    p = tmp_path / "policy.yaml"
    p.write_text("plugins: {allow: [{name: entropy, group: detectors, dist: x, "
                 "version: '1', profiles: [server]}]}\n")
    with pytest.raises(RuntimeError, match="built-in detectors"):
        load_policy(p).build_detectors()


def test_a_plugin_detector_builds_scans_and_is_wrapped(tmp_path, zebra):
    from forgd_verdict.core import scan

    dets = _policy(tmp_path).build_detectors(profile="server")
    (z,) = _zebras(dets)
    assert (z.name, z.tier, z.severity, z.finding_prefix, z.local_only) == \
        ("zebra", 1, "block", "zebra", False)
    assert z.finding_ids() == ["zebra:stripe"]
    assert [d.tier for d in dets] == sorted(d.tier for d in dets)
    res = scan([ScanUnit("msg[0]", None, "pay zebra-123456 now")], dets)
    (f,) = [f for f in res.findings if f.detector == "zebra:stripe"]
    assert f.excerpt_hash == digest("zebra-123456", SALT)
    assert "zebra" in res.detectors_run


def test_without_a_profile_a_configured_plugin_is_skipped(tmp_path, zebra):
    assert not _zebras(_policy(tmp_path).build_detectors())
    assert zebra not in sys.modules


def test_the_hook_profile_does_not_load_a_plugin_that_did_not_opt_in(tmp_path, zebra):
    others = [p for p in PROFILES if p != "hook"]
    dets = _policy(tmp_path, profiles=others).build_detectors(
        include_local_only=True, profile="hook")
    assert not _zebras(dets)
    assert zebra not in sys.modules


def test_the_hook_profile_loads_a_plugin_that_opted_in(tmp_path, zebra):
    dets = _policy(tmp_path, profiles=["hook"]).build_detectors(
        include_local_only=True, salt="device-salt", profile="hook")
    (z,) = _zebras(dets)
    (f,) = z.scan([ScanUnit("m", None, "zebra-000001")])
    assert f.excerpt_hash == digest("zebra-000001", "device-salt")


def test_a_disabled_plugin_is_not_imported(tmp_path, zebra):
    assert not _zebras(_policy(tmp_path, cfg={"enabled": False})
                       .build_detectors(profile="server"))
    assert zebra not in sys.modules


def test_a_local_only_plugin_needs_include_local_only(tmp_path, zebra):
    pol = _policy(tmp_path, cfg={"local_only_for_test": True})
    assert not _zebras(pol.build_detectors(profile="server"))
    assert _zebras(pol.build_detectors(include_local_only=True, profile="server"))


def test_availability_follows_enabled(tmp_path, zebra):
    auto = _policy(tmp_path, cfg={"enabled": "auto", "unavailable_for_test": True})
    assert not _zebras(auto.build_detectors(profile="server"))
    required = _policy(tmp_path, cfg={"unavailable_for_test": True})
    with pytest.raises(RuntimeError, match="required here but unavailable"):
        required.build_detectors(profile="server")


def test_the_factory_gets_a_read_only_copy_and_a_hasher_not_the_salt(tmp_path, zebra):
    pol = _policy(tmp_path)
    pol.build_detectors(profile="server")
    ((cfg, severity, hasher),) = sys.modules[zebra].SEEN
    with pytest.raises(TypeError):
        cfg["severity"] = "warn"
    assert dict(cfg) == pol.raw["detectors"]["zebra"]
    assert cfg is not pol.raw["detectors"]["zebra"]
    assert hasher("x") == digest("x", SALT)

    def reachable(obj, depth=0):
        if depth > 6:
            return []
        out = [obj]
        for cell in getattr(obj, "__closure__", None) or ():
            out += reachable(cell.cell_contents, depth + 1)
        if isinstance(obj, (tuple, list)):
            for x in obj:
                out += reachable(x, depth + 1)
        if isinstance(obj, Mapping):
            for x in obj.values():
                out += reachable(x, depth + 1)
        return out

    for obj in reachable((cfg, severity, hasher)):
        assert not (isinstance(obj, (str, bytes)) and SALT in str(obj)), obj
        assert SALT not in repr(obj)
    assert SALT not in repr(hasher.__closure__)


def test_a_plugin_claiming_a_builtin_prefix_refuses(tmp_path, install):
    install(name="zebra", attr="make", source=DETECTOR_SOURCE
            + "\nZebra.finding_prefix = 'regex'\n")
    with pytest.raises(RuntimeError, match="belongs to a built-in"):
        _policy(tmp_path).build_detectors(profile="server")


# -- the finding checks ----------------------------------------------------


class _Inner:
    tier = 0
    finding_prefix = "zebra"

    def __init__(self, findings=(), exc=None):
        self.findings, self.exc = list(findings), exc

    def available(self):
        return True

    def finding_ids(self):
        return ["zebra:stripe"]

    def scan(self, units):
        if self.exc is not None:
            raise self.exc
        return self.findings


def _refusals(caplog):
    return [r for r in caplog.records if r.getMessage() == "plugin finding refused"]


HASHER = hasher_for(SALT)
UNIT = ScanUnit("msg[0].content", "Bash", "x" * 20 + AWS)
GOOD = dict(detector="zebra:stripe", severity="block", locator=UNIT.locator,
            excerpt_hash=HASHER(AWS), tool_name="Bash", start=20, end=40)


def test_a_well_formed_finding_passes():
    det = PluginDetector("zebra", _Inner([Finding(**GOOD)]), "block", HASHER)
    assert det.scan([UNIT]) == [Finding(**GOOD)]


@pytest.mark.parametrize("check,over", [
    ("locator", {"locator": AWS}),
    ("locator", {"tool_name": "Read"}),
    ("excerpt_hash", {"excerpt_hash": "A" * 64}),
    ("excerpt_hash", {"excerpt_hash": "a" * 63}),
    ("excerpt_hash", {"excerpt_hash": AWS}),
    ("excerpt_hash", {"excerpt_hash": "a" * 64}),
    ("excerpt_hash", {"excerpt_hash": digest(AWS)}),
    ("excerpt_hash", {"start": 21, "end": 40}),
    ("detector", {"detector": "regex:aws-access-key-id"}),
    ("detector", {"detector": "zebra:" + AWS}),
    ("detector", {"detector": "zebras"}),
    ("severity", {"severity": "warn"}),
    ("span", {"start": 20, "end": 41}),
    ("span", {"start": -1, "end": 4}),
    ("span", {"start": 5, "end": 5}),
    ("span", {"start": 5, "end": None}),
    ("span", {"start": True, "end": 4}),
    ("span", {"start": None, "end": None}),
    ("span", {"start": None, "end": 40}),
])
def test_each_check_drops_the_finding_and_logs_no_content(check, over, caplog):
    det = PluginDetector("zebra", _Inner([Finding(**{**GOOD, **over})]), "block", HASHER,
                         scrub=lambda s: s)
    caplog.set_level(logging.ERROR, logger="forgd_verdict.plugins")
    assert det.scan([UNIT]) == []
    (rec,) = _refusals(caplog)
    assert rec.levelno == logging.ERROR
    assert rec.fields["check"] == check
    assert set(rec.fields) == {"detector", "check", "locator"}
    assert AWS not in caplog.text and AWS not in repr(rec.fields)


def test_a_matched_hex_token_reported_as_the_hash_is_refused(caplog):
    """A 64-hex secret passes the format check; only recomputing the hash
    from the span catches a plugin that copies the match into it."""
    token = "3f9c" * 16
    unit = ScanUnit("msg[0].content", None, f"export API_TOKEN={token}")
    f = Finding(**{**GOOD, "locator": unit.locator, "tool_name": None,
                   "excerpt_hash": token, "start": 17, "end": 81})
    det = PluginDetector("zebra", _Inner([f]), "block", HASHER, scrub=lambda s: s)
    caplog.set_level(logging.DEBUG)
    assert det.scan([unit]) == []
    (rec,) = _refusals(caplog)
    assert rec.fields["check"] == "excerpt_hash"
    assert token not in caplog.text and token[:16] not in caplog.text


def test_the_hash_may_match_any_unit_sharing_the_locator():
    other = ScanUnit(UNIT.locator, UNIT.tool_name, "y" * 40)
    det = PluginDetector("zebra", _Inner([Finding(**GOOD)]), "block", HASHER)
    assert det.scan([other, UNIT]) == [Finding(**GOOD)]
    wrong = Finding(**{**GOOD, "excerpt_hash": HASHER("y" * 20)})
    assert PluginDetector("zebra", _Inner([wrong]), "block", HASHER).scan([UNIT]) == []


def test_a_non_finding_is_dropped(caplog):
    det = PluginDetector("zebra", _Inner([{"locator": AWS}]), "block", HASHER)
    caplog.set_level(logging.ERROR, logger="forgd_verdict.plugins")
    assert det.scan([UNIT]) == []
    assert _refusals(caplog)[0].fields["check"] == "type"
    assert AWS not in caplog.text


class _Ids(_Inner):
    def __init__(self, ids):
        super().__init__()
        self.ids = ids

    def finding_ids(self):
        if isinstance(self.ids, Exception):
            raise self.ids
        return self.ids


@pytest.mark.parametrize("ids", [
    [],
    "zebra:stripe",
    ["zebra:stripe", 42],
    ["zebra:stripe", "regex:aws-access-key-id"],
    ["zebra:stripe", "zebra:" + AWS],
    ["zebra:" + "a" * (plugins_mod.FINDING_ID_MAX - 5)],
    None,
])
def test_malformed_finding_ids_refuse_to_start(ids):
    with pytest.raises(RuntimeError, match="finding_ids") as exc:
        PluginDetector("zebra", _Ids(ids), "block", HASHER)
    assert AWS not in str(exc.value)


def test_an_id_of_exactly_the_cap_is_accepted():
    fid = "zebra:" + "a" * (plugins_mod.FINDING_ID_MAX - 6)
    assert PluginDetector("zebra", _Ids([fid]), "block", HASHER).finding_ids() == [fid]


def test_a_plugin_without_finding_ids_refuses_to_start():
    class NoIds(_Inner):
        finding_ids = None

    with pytest.raises(RuntimeError, match="must declare finding_ids"):
        PluginDetector("zebra", NoIds(), "block", HASHER)


def test_finding_ids_that_raise_refuse_by_type():
    with pytest.raises(RuntimeError) as exc:
        PluginDetector("zebra", _Ids(KeyError(AWS)), "block", HASHER)
    assert str(exc.value) == "detectors.zebra: finding_ids() raised KeyError"
    assert exc.value.__cause__ is None and exc.value.__context__ is None


def test_finding_ids_are_a_snapshot_taken_at_build():
    inner = _Ids(["zebra:stripe"])
    det = PluginDetector("zebra", inner, "block", HASHER)
    inner.ids.append("zebra:late")
    inner.findings = [Finding(**{**GOOD, "detector": "zebra:late"})]
    assert det.finding_ids() == ["zebra:stripe"]
    assert det.scan([UNIT]) == []


def test_an_undeclared_id_carrying_the_match_is_refused(caplog, capsys):
    """A well-formed id that embeds the matched text is refused, so the text
    never reaches a finding, a log or the reference_id."""
    import io

    from forgd_verdict.applog import JsonFormatter
    from forgd_verdict.core import decide, scan
    from forgd_verdict.policy import load_policy

    matched = "titanicsecret99"
    unit = ScanUnit("msg[0].content", None, f"the password is {matched} ok")
    f = Finding(**{**GOOD, "detector": "zebra:" + matched, "locator": unit.locator,
                   "tool_name": None, "start": 16, "end": 31})
    det = PluginDetector("zebra", _Inner([f]), "block", HASHER, scrub=lambda s: s)
    buf = io.StringIO()
    handler = logging.StreamHandler(buf)
    handler.setFormatter(JsonFormatter())
    logger = logging.getLogger("forgd_verdict")
    logger.addHandler(handler)
    caplog.set_level(logging.DEBUG)
    try:
        res = scan([unit], [det])
        verdict = decide(res.findings, load_policy("policy.yaml"))
    finally:
        logger.removeHandler(handler)
    assert res.findings == []
    (rec,) = _refusals(caplog)
    assert rec.fields["check"] == "detector"
    out = capsys.readouterr()
    for text in (buf.getvalue(), caplog.text, out.out, out.err, repr(res), repr(verdict)):
        assert matched not in text and matched[:10] not in text


def test_a_refused_locator_is_logged_scrubbed(tmp_path, zebra, caplog):
    """A unit locator can itself be a match; it is logged through the core's scrub."""
    (z,) = _zebras(_policy(tmp_path).build_detectors(profile="server"))
    unit = ScanUnit(f"msg[0].{AWS}", None, "zebra-123456")
    z._inner.severity = "warn"
    caplog.set_level(logging.ERROR, logger="forgd_verdict.plugins")
    assert z.scan([unit]) == []
    (rec,) = _refusals(caplog)
    assert rec.fields["check"] == "severity"
    assert AWS not in caplog.text
    assert "<redacted>" in rec.fields["locator"]



class _Unhashable:
    __hash__ = None  # type: ignore[assignment]


@pytest.mark.parametrize("field,value,check", [
    ("tool_name", [], "locator"), ("tool_name", {}, "locator"), ("tool_name", 7, "locator"),
    ("locator", ["x"], "locator"), ("severity", _Unhashable(), "severity"),
    ("detector", ["zebra:stripe"], "detector"),
])
def test_a_finding_with_a_malformed_field_is_refused_not_raised(
        tmp_path, zebra, caplog, field, value, check):
    """A plugin returning a field of the wrong type (an unhashable tool_name was
    the reported case) has that finding dropped; the scan carries on."""
    (z,) = _zebras(_policy(tmp_path).build_detectors(profile="server"))
    unit = ScanUnit("msg[0].text", None, "zebra-123456")
    good = _good(z)
    good[field] = value
    z._inner.scan = lambda units: [Finding(**good)]
    caplog.set_level(logging.ERROR, logger="forgd_verdict.plugins")
    assert z.scan([unit]) == []
    (rec,) = _refusals(caplog)
    assert rec.fields["check"] == check


def _posing_as(legit: str, carried: str) -> str:
    """A str subclass carrying `carried` that compares, hashes and != like `legit`."""

    class _Poser(str):
        def __eq__(self, other):  # noqa: D105
            return True

        def __ne__(self, other):  # noqa: D105
            return False

        def __hash__(self):  # noqa: D105
            return hash(legit)

    return _Poser(carried)


class _FindingSub(Finding):
    pass


def _good(z):
    return dict(detector="zebra:stripe", severity=z.severity, locator="msg[0].text",
                excerpt_hash=z._hasher("zebra-123456"), tool_name=None, start=0, end=12)


# Each value is WRONG and poses as the right one; only an exact-type check
# can refuse it. excerpt_hash is the reported case: 64 hex characters that
# are not the digest.
@pytest.mark.parametrize("field,wrong", [
    ("excerpt_hash", "abcdef0123456789" * 4),
    ("detector", "zebra:leaked-value"),
    ("severity", "not-a-severity"),
])
def test_a_str_subclass_field_is_refused(tmp_path, zebra, caplog, field, wrong):
    """A str subclass can override __eq__, __ne__ and __hash__ and pass every
    comparison while carrying arbitrary text, so only exact str is accepted."""
    (z,) = _zebras(_policy(tmp_path).build_detectors(profile="server"))
    unit = ScanUnit("msg[0].text", None, "zebra-123456")
    good = _good(z)
    z._inner.scan = lambda units: [Finding(**good)]
    assert len(z.scan([unit])) == 1, "the baseline finding must be accepted"
    good[field] = _posing_as(good[field], wrong)
    z._inner.scan = lambda units: [Finding(**good)]
    caplog.set_level(logging.ERROR, logger="forgd_verdict.plugins")
    assert z.scan([unit]) == []


def test_a_finding_subclass_is_refused(tmp_path, zebra, caplog):
    (z,) = _zebras(_policy(tmp_path).build_detectors(profile="server"))
    unit = ScanUnit("msg[0].text", None, "zebra-123456")
    sub = _FindingSub(**_good(z))
    z._inner.scan = lambda units: [sub]
    caplog.set_level(logging.ERROR, logger="forgd_verdict.plugins")
    assert z.scan([unit]) == []
    (rec,) = _refusals(caplog)
    assert rec.fields["check"] == "type"


ZEBRA = "zebra-123456"


def test_a_refused_locator_the_refusing_plugin_matches_is_logged_redacted(
        tmp_path, zebra, caplog):
    (z,) = _zebras(_policy(tmp_path).build_detectors(profile="server"))
    unit = ScanUnit(f"msg[0].{ZEBRA}", None, f"code {ZEBRA}")
    z._inner.severity = "warn"
    caplog.set_level(logging.ERROR)
    assert z.scan([unit]) == []
    (rec,) = _refusals(caplog)
    assert rec.fields["detector"] == "zebra"
    assert rec.fields["check"] == "severity"
    assert ZEBRA not in rec.fields["locator"]
    assert rec.fields["locator"].startswith("<redacted>")
    assert ZEBRA not in caplog.text


def test_a_plugin_raising_in_the_refusal_scrub_redacts_the_locator(tmp_path, zebra, caplog):
    (z,) = _zebras(_policy(tmp_path).build_detectors(profile="server"))
    real = z._inner.scan

    def scan(units):
        units = list(units)
        if units and units[0].locator == "_":
            raise ValueError(ZEBRA)
        return real(units)

    z._inner.scan = scan
    z._inner.severity = "warn"
    caplog.set_level(logging.ERROR)
    assert z.scan([ScanUnit("msg[0].innocuous_name", None, f"code {ZEBRA}")]) == []
    (rec,) = _refusals(caplog)
    assert rec.fields["locator"].startswith("<redacted>")
    (failed,) = [r for r in caplog.records if "label scrub" in r.getMessage()]
    assert failed.fields == {"detector": "zebra", "reason": "zebra: ValueError"}
    assert ZEBRA not in caplog.text


def test_the_plugin_label_scrub_probes_plugins_of_every_tier():
    from forgd_verdict.core import scrub_plugin_label

    class Deep(_Inner):
        tier = 2

    f = Finding(**{**GOOD, "locator": "_"})
    det = PluginDetector("zebra", Deep([f]), "block", HASHER)
    assert scrub_plugin_label("innocuous_name", [], [det]).startswith("<redacted>")
    assert scrub_plugin_label("innocuous_name", [], []) == "innocuous_name"


def test_the_finding_scrub_counts_a_plugin_finding_scan_would_refuse(caplog):
    from forgd_verdict.core import _scrub

    wrong = Finding(**{**GOOD, "locator": "_", "severity": "warn"})
    det = PluginDetector("zebra", _Inner([wrong]), "block", HASHER)
    f = Finding(**{**GOOD, "locator": "msg[0].innocuous_name"})
    caplog.set_level(logging.ERROR)
    (g,) = _scrub([f], [det])
    assert g.locator.startswith("msg[0].<redacted>")
    assert _refusals(caplog) == []


# -- exceptions ------------------------------------------------------------


def test_an_exception_becomes_its_type_with_no_chain():
    import traceback

    det = PluginDetector("zebra", _Inner(exc=ValueError(f"saw {AWS}")), "block", HASHER)
    with pytest.raises(DetectorFailed) as exc:
        det.scan([UNIT])
    e = exc.value
    assert str(e) == "zebra: ValueError"
    assert e.__cause__ is None and e.__context__ is None and e.__suppress_context__
    assert AWS not in "".join(traceback.format_exception(e))


def test_a_detector_failed_from_the_plugin_is_rewrapped():
    det = PluginDetector("zebra", _Inner(exc=DetectorFailed(AWS)), "block", HASHER)
    with pytest.raises(DetectorFailed, match="^zebra: DetectorFailed$"):
        det.scan([UNIT])


def test_the_formatted_log_carries_the_type_only():
    import io

    from forgd_verdict.applog import JsonFormatter
    from forgd_verdict.core import scan

    buf = io.StringIO()
    handler = logging.StreamHandler(buf)
    handler.setFormatter(JsonFormatter())
    logger = logging.getLogger("forgd_verdict")
    logger.addHandler(handler)
    try:
        det = PluginDetector("zebra", _Inner(exc=RuntimeError(f"saw {AWS}")), "block", HASHER)
        res = scan([UNIT], [det])
        try:
            det.scan([UNIT])
        except DetectorFailed:
            logger.exception("verdict failed")
    finally:
        logger.removeHandler(handler)
    out = buf.getvalue()
    assert res.detectors_skipped == ["zebra"]
    assert "zebra: RuntimeError" in out
    assert AWS not in out and "saw" not in out
    assert "During handling" not in out and "direct cause" not in out


def test_a_factory_that_raises_refuses_by_type():
    def factory(cfg, sev, hasher):
        raise KeyError(AWS)

    with pytest.raises(RuntimeError) as exc:
        PluginDetector.build("zebra", factory, {}, "block", lambda t: t)
    assert "KeyError" in str(exc.value) and AWS not in str(exc.value)
    assert exc.value.__context__ is None


# -- construction exceptions -------------------------------------------


def _assert_by_type(exc, message, caplog):
    import traceback

    assert str(exc) == message
    assert exc.__cause__ is None and exc.__context__ is None
    assert AWS not in "".join(traceback.format_exception(exc))
    logging.getLogger("forgd_verdict").exception("startup failed", exc_info=exc)
    assert AWS not in caplog.text


class _Raising(_Inner):
    """An _Inner whose `raising` attribute raises ValueError(AWS)."""

    raising = ""

    def __getattribute__(self, attr):
        if attr == type(self).raising:
            raise ValueError(AWS)
        return super().__getattribute__(attr)


class _BadKeys:
    def __iter__(self):
        raise ValueError(AWS)


@pytest.mark.parametrize("attr,what,over", [
    ("tier", "tier", {}),
    ("finding_prefix", "finding_prefix", {}),
    ("public_keys", "public_keys", {}),
    ("", "public_keys", {"public_keys": _BadKeys()}),
    ("local_only", "local_only", {}),
    ("finding_ids", "finding_ids", {}),
    ("", "finding_ids()", {"finding_ids": lambda self: (_ for _ in ()).throw(ValueError(AWS))}),
    ("phrases", "phrases", {}),
    ("", "phrases()", {"phrases": lambda self: (_ for _ in ()).throw(ValueError(AWS))}),
    ("", "scanning its phrases", {"phrases": lambda self: {"zebra:stripe": "a zebra code"},
                                  "scan": lambda self, units: (_ for _ in ()).throw(
                                      ValueError(AWS))}),
    ("", "available()", {"phrases": lambda self: {"zebra:stripe": "a zebra code"},
                         "available": lambda self: (_ for _ in ()).throw(ValueError(AWS))}),
])
def test_a_raising_construction_read_refuses_by_type(attr, what, over, caplog):
    cls = type("Plugin", (_Raising,), {"raising": attr, **over})
    with pytest.raises(RuntimeError) as exc:
        PluginDetector.build("zebra", lambda cfg, sev, h: cls(), {}, "block", HASHER,
                             scrub=lambda s: s)
    _assert_by_type(exc.value, f"detectors.zebra: {what} raised ValueError", caplog)


def test_a_detector_factory_that_raises_refuses_by_type(caplog):
    def factory(cfg, sev, hasher):
        raise ValueError(AWS)

    with pytest.raises(RuntimeError) as exc:
        PluginDetector.build("zebra", factory, {}, "block", HASHER)
    _assert_by_type(exc.value, "detectors.zebra: the plugin factory raised ValueError", caplog)


def test_an_available_that_raises_refuses_at_build(tmp_path, install, caplog):
    install(name="zebra", attr="make", source=DETECTOR_SOURCE + textwrap.dedent(f"""
        def _available(self):
            raise ValueError({AWS!r})
        Zebra.available = _available
        Zebra.phrases = lambda self: {{}}
    """))
    with pytest.raises(RuntimeError) as exc:
        _policy(tmp_path, cfg={"enabled": "auto"}).build_detectors(profile="server")
    _assert_by_type(exc.value, "detectors.zebra: available() raised ValueError", caplog)


def test_a_store_factory_that_raises_refuses_by_type(tmp_path, install, monkeypatch, caplog):
    from forgd_verdict.store import open_store

    install(group="stores", name="acme", attr="make", source=STORE_SOURCE.replace(
        "raise ValueError(spec)", f"raise ValueError({AWS!r})"))
    with pytest.raises(RuntimeError) as exc:
        open_store("acme://boom", "east", plugins=_store_allow(), profile="server")
    _assert_by_type(exc.value, "stores.acme: the plugin factory raised ValueError", caplog)


def test_a_sink_factory_that_raises_refuses_by_type(install, caplog):
    from forgd_verdict.sink.base import SinkConfig
    from forgd_verdict.sink.otlp import build_sink

    install(group="sinks", name="acme", attr="make",
            source=SINK_SOURCE + f"\ndef make(config, **kw):\n    raise ValueError({AWS!r})\n")
    with pytest.raises(RuntimeError) as exc:
        build_sink(SinkConfig(name="s", type="acme", endpoint="https://x"),
                   plugins=_sink_allow(), profile="collector")
    _assert_by_type(exc.value, "sinks.acme: the plugin factory raised ValueError", caplog)


def test_a_sink_member_that_raises_refuses_by_type(install, caplog):
    from forgd_verdict.sink.base import SinkConfig
    from forgd_verdict.sink.otlp import build_sink

    install(group="sinks", name="acme", attr="make", source=SINK_SOURCE + textwrap.dedent(f"""
        def _limit(self):
            raise ValueError({AWS!r})
        AcmeSink.max_batch_bytes = property(_limit)
    """))
    with pytest.raises(RuntimeError) as exc:
        build_sink(SinkConfig(name="s", type="acme", endpoint="https://x"),
                   plugins=_sink_allow(), profile="collector")
    _assert_by_type(exc.value, "sinks.acme: max_batch_bytes raised ValueError", caplog)


@pytest.mark.parametrize("source,what", [
    (f"raise ValueError({AWS!r})\n", "importing {module}"),
    (f"def __getattr__(name):\n    raise ValueError({AWS!r})\n", "{module}.PLUGIN_API"),
])
def test_a_module_that_raises_while_loading_refuses_by_type(install, caplog, source, what):
    module = install(api=None if "PLUGIN_API" in what else PLUGIN_API, source=source)
    with pytest.raises(RuntimeError) as exc:
        load_plugins(_allow(), "detectors", "server", set())
    expected = "detectors.acme_ids: " + what.format(module=module) + " raised ValueError"
    assert expected in str(exc.value)
    assert exc.value.__cause__ is None and exc.value.__context__ is None
    assert AWS not in str(exc.value) and AWS not in caplog.text


def test_an_entry_point_that_raises_on_load_refuses_by_type(install, caplog):
    install(attr="Missing", source=f"def __getattr__(name):\n    raise ValueError({AWS!r})\n")
    with pytest.raises(RuntimeError) as exc:
        load_plugins(_allow(), "detectors", "server", set())
    assert "detectors.acme_ids: loading the entry point raised ValueError" in str(exc.value)
    assert exc.value.__cause__ is None and exc.value.__context__ is None
    assert AWS not in str(exc.value)


# -- deny reasons ------------------------------------------------------------


def test_the_deny_reason_uses_the_plugin_phrase_and_never_calls_describe(tmp_path, zebra):
    from forgd_verdict.core import build_deny_reason, decide, scan

    pol = _policy(tmp_path)
    dets = pol.build_detectors(profile="server")
    res = scan([ScanUnit("m", None, "zebra-123456")], dets)
    verdict = decide(res.findings, pol)
    assert verdict.action == "deny"
    assert "a zebra code" in verdict.deny_reason
    assert "restricted content" in build_deny_reason(["unregistered:x"])
    assert sys.modules[zebra].DESCRIBED == []


def test_the_phrase_is_normalized(tmp_path, zebra):
    from forgd_verdict.core import describe

    pol = _policy(tmp_path, cfg={"phrase_for_test": "a zebra\ncode\x00"})
    (z,) = _zebras(pol.build_detectors(profile="server"))
    assert z.phrases() == {"zebra:stripe": "a zebra code"}
    assert describe("zebra:stripe", pol.plugin_phrases()) == "a zebra code"


def test_a_phrase_of_exactly_the_cap_is_accepted(tmp_path, zebra):
    from forgd_verdict.core import describe

    phrase = "z" * PHRASE_MAX
    pol = _policy(tmp_path, cfg={"phrase_for_test": phrase})
    pol.build_detectors(profile="server")
    assert describe("zebra:stripe", pol.plugin_phrases()) == phrase


@pytest.mark.parametrize("phrase,match", [
    ("z" * (PHRASE_MAX + 1), "at most 60 characters"),
    ("", "non-empty str"),
    (" \n\x00 ", "non-empty str"),
    (42, "non-empty str"),
    (f"a key like {AWS}", "matches a built-in detector"),
    ("a code like zebra-123456", "own scan matches one of its phrases"),
])
def test_a_bad_phrase_refuses_to_start(tmp_path, zebra, phrase, match):
    with pytest.raises(RuntimeError, match=match) as exc:
        _policy(tmp_path, cfg={"phrase_for_test": phrase}).build_detectors(profile="server")
    assert AWS not in str(exc.value) and "zebra-123456" not in str(exc.value)


class _Phrases(_Inner):
    def __init__(self, phrases, found=()):
        super().__init__(found)
        self._p = phrases

    def phrases(self):
        if isinstance(self._p, Exception):
            raise self._p
        return self._p


@pytest.mark.parametrize("phrases,match", [
    ({"zebra:other": "a zebra code"}, "not one of finding_ids"),
    ({42: "a zebra code"}, "not one of finding_ids"),
    ([("zebra:stripe", "a zebra code")], "must return a mapping"),
    ("a zebra code", "must return a mapping"),
])
def test_malformed_phrases_refuse_to_start(phrases, match):
    with pytest.raises(RuntimeError, match=match):
        PluginDetector("zebra", _Phrases(phrases), "block", HASHER, scrub=lambda s: s)


def test_phrases_that_raise_refuse_by_type():
    with pytest.raises(RuntimeError) as exc:
        PluginDetector("zebra", _Phrases(KeyError(AWS)), "block", HASHER, scrub=lambda s: s)
    assert str(exc.value) == "detectors.zebra: phrases() raised KeyError"
    assert exc.value.__cause__ is None and exc.value.__context__ is None


def test_a_self_scan_that_raises_refuses_by_type():
    inner = _Phrases({"zebra:stripe": "a zebra code"})
    inner.exc = ValueError(AWS)
    with pytest.raises(RuntimeError) as exc:
        PluginDetector("zebra", inner, "block", HASHER, scrub=lambda s: s)
    assert str(exc.value) == "detectors.zebra: scanning its phrases raised ValueError"
    assert exc.value.__cause__ is None and exc.value.__context__ is None


def test_an_unavailable_plugin_is_not_self_scanned_and_has_no_phrases():
    class Unavailable(_Phrases):
        def available(self):
            return False

    f = Finding(**GOOD)
    det = PluginDetector("zebra", Unavailable({"zebra:stripe": "a zebra code"}, [f]),
                         "block", HASHER, scrub=lambda s: s)
    assert det.phrases() == {}


def test_phrases_are_a_snapshot_taken_at_build():
    from forgd_verdict.core import describe

    inner = _Phrases({"zebra:stripe": "a zebra code"})
    det = PluginDetector("zebra", inner, "block", HASHER, scrub=lambda s: s)
    inner._p["zebra:stripe"] = f"a key like {AWS}"
    registry = plugins_mod.PluginRegistry()
    registry.register(det)
    assert describe("zebra:stripe", registry.phrases) == "a zebra code"


ACME_SOURCE = """
import re


class Acme:
    tier = 2
    finding_prefix = "acme"

    def __init__(self, cfg, severity, hasher):
        self.cfg, self.severity, self.hasher = cfg, severity, hasher

    def available(self):
        return True

    def finding_ids(self):
        return ["acme:id"]

    def phrases(self):
        return {"acme:id": "an acme customer id"}

    def scan(self, units):
        from forgd_verdict.models import Finding
        units = list(units)
        if self.cfg.get("raise_on_probe_for_test") and any(u.locator == "_" for u in units):
            raise ValueError("acme-123456")
        out = []
        for u in units:
            for m in re.finditer(r"acme-[0-9]{6}", u.text):
                out.append(Finding("acme:id", self.severity, u.locator,
                                   self.hasher(m.group()), u.tool_name,
                                   m.start(), m.end()))
        return out


def make(cfg, severity, hasher):
    return Acme(cfg, severity, hasher)
"""


def _two_plugins(tmp_path, install, *, acme_first, zebra_cfg=None, acme_cfg=None):
    from forgd_verdict.policy import load_policy

    install(name="zebra", attr="make", source=DETECTOR_SOURCE)
    install(name="acme", attr="make", source=ACME_SOURCE, dist="acme_two")
    entries = {
        "zebra": "{name: zebra, group: detectors, dist: acme-forgd, version: 1.4.2, "
                 "profiles: [server]}",
        "acme": "{name: acme, group: detectors, dist: acme-two, version: 1.4.2, "
                "profiles: [server]}",
    }
    order = ["acme", "zebra"] if acme_first else ["zebra", "acme"]
    cfgs = {"zebra": {"enabled": True, "severity": "block", **(zebra_cfg or {})},
            "acme": {"enabled": True, "severity": "block", **(acme_cfg or {})}}
    p = tmp_path / "policy.yaml"
    p.write_text(
        f"privacy: {{hash_salt: {SALT}}}\nplugins:\n  allow:\n"
        + "".join(f"    - {entries[n]}\n" for n in order)
        + "detectors:\n"
        + "".join(f"  {n}: {json.dumps(cfgs[n])}\n" for n in order))
    return load_policy(p)


@pytest.mark.parametrize("acme_first", [False, True])
def test_a_phrase_another_plugin_matches_refuses_to_start(tmp_path, install, acme_first):
    policy = _two_plugins(tmp_path, install, acme_first=acme_first,
                          zebra_cfg={"phrase_for_test": "acme-123456"})
    with pytest.raises(RuntimeError) as exc:
        policy.build_detectors(profile="server")
    message = str(exc.value)
    assert message == ("detectors.zebra: the phrase for zebra:stripe is matched "
                       "by detector acme")


def test_two_plugins_with_clean_phrases_build(tmp_path, install):
    dets = _two_plugins(tmp_path, install, acme_first=False).build_detectors(profile="server")
    assert sorted(d.name for d in _zebras(dets)) == ["acme", "zebra"]


def test_a_plugin_raising_in_the_phrase_screen_refuses_by_type(tmp_path, install):
    policy = _two_plugins(tmp_path, install, acme_first=False,
                          acme_cfg={"raise_on_probe_for_test": True})
    with pytest.raises(RuntimeError, match="raised in detectors.acme: ValueError$") as exc:
        policy.build_detectors(profile="server")
    assert "123456" not in str(exc.value)
    assert exc.value.__cause__ is None and exc.value.__suppress_context__


def test_a_missing_phrase_uses_the_generic_wording(tmp_path, zebra):
    from forgd_verdict.core import describe

    pol = _policy(tmp_path, cfg={"ids_for_test": ["zebra:stripe", "zebra:other"]})
    pol.build_detectors(profile="server")
    phrases = pol.plugin_phrases()
    assert describe("zebra:stripe", phrases) == "a zebra code"
    assert describe("zebra:other", phrases) == "restricted content"
    assert describe("regex:aws-access-key", phrases) != "restricted content"


def test_a_plugin_without_phrases_uses_the_generic_wording():
    from forgd_verdict.core import describe

    registry = plugins_mod.PluginRegistry()
    registry.register(PluginDetector("zebra", _Inner(), "block", HASHER))
    assert describe("zebra:stripe", registry.phrases) == "restricted content"


# -- the label scrub -----------------------------------------------------


def test_a_plugin_failing_in_the_scrub_redacts_the_segment(caplog):
    from forgd_verdict.core import _scrub
    from forgd_verdict.detectors import T0RegexDetector

    det = PluginDetector("zebra", _Inner(exc=ValueError(AWS)), "block", HASHER)
    f = Finding(**{**GOOD, "locator": "msg[0].innocuous_name"})
    caplog.set_level(logging.ERROR, logger="forgd_verdict.core")
    (g,) = _scrub([f], [T0RegexDetector("block", ""), det])
    assert g.locator.startswith("msg[0].<redacted>")
    (rec,) = [r for r in caplog.records if "locator scrub" in r.getMessage()]
    assert rec.levelno == logging.ERROR
    assert rec.fields == {"detector": "zebra", "reason": "zebra: ValueError"}
    assert AWS not in caplog.text


def test_a_builtin_failing_in_the_scrub_redacts_the_segment(caplog):
    """The scrub runs after detection and before the decision, so a
    built-in's failure there raised out of `scan` and a deny became an
    error."""
    from forgd_verdict.core import _scrub

    class Builtin(_Inner):
        name = "gitleaks"

    f = Finding(**{**GOOD, "locator": "msg[0].innocuous_name"})
    caplog.set_level(logging.ERROR, logger="forgd_verdict.core")
    (g,) = _scrub([f], [Builtin(exc=DetectorFailed("daemon down"))])
    assert g.locator == "msg[0].<redacted>"
    (rec,) = [r for r in caplog.records if "locator scrub" in r.getMessage()]
    assert rec.fields == {"detector": "gitleaks", "reason": "daemon down"}


# -- stores and sinks ------------------------------------------------------

STORE_SOURCE = """
from forgd_verdict.store import LocalFileStore

CALLS = []


class AcmeStore(LocalFileStore):
    pass


class Partial:
    def write_verdicts(self, records):
        return 0


def make(spec, instance):
    CALLS.append((spec, instance))
    if "partial" in spec:
        return Partial()
    if "boom" in spec:
        raise ValueError(spec)
    return AcmeStore("./acme-store-unused", instance=instance)
"""

SINK_SOURCE = """
CALLS = []


class AcmeSink:
    max_batch_bytes = 1_000_000
    max_batch_events = 500
    requires_ordering = False

    def __init__(self, config, **kw):
        self.config, self.kw = config, kw

    def send(self, events):
        return len(events)

    def describe(self):
        return {"name": self.config.name, "type": "acme"}

    def close(self):
        return None


class NoLimits:
    def send(self, events):
        return 0

    def describe(self):
        return {}

    def close(self):
        return None


def make(config, **kw):
    CALLS.append((config, kw))
    return NoLimits() if config.name == "partial" else AcmeSink(config, **kw)
"""


def _store_allow(**over):
    return _allow(**{"name": "acme", "group": "stores", **over})


def _sink_allow(**over):
    return _allow(**{"name": "acme", "group": "sinks", "profiles": ["collector"], **over})


@pytest.fixture
def acme_store(install):
    return install(group="stores", name="acme", attr="make", source=STORE_SOURCE)


@pytest.fixture
def acme_sink(install):
    return install(group="sinks", name="acme", attr="make", source=SINK_SOURCE)


@pytest.mark.parametrize("spec", ["acme://bucket/prefix?sig=" + AWS, "acme:/bucket"])
def test_an_installed_but_unlisted_store_scheme_refuses(acme_store, tmp_path, monkeypatch, spec):
    from forgd_verdict.store import open_store

    monkeypatch.chdir(tmp_path)
    with pytest.raises(RuntimeError) as exc:
        open_store(spec, "east", plugins=(), profile="server")
    msg = str(exc.value)
    assert "name: acme, group: stores, dist: acme_forgd, version: 1.4.2" in msg
    assert AWS not in msg
    assert sys.modules.get(acme_store) is None
    assert not [p for p in tmp_path.iterdir() if p.name.startswith("acme")]


def test_an_unknown_scheme_with_no_publisher_is_a_local_path(tmp_path, monkeypatch):
    from forgd_verdict.store import LocalFileStore, open_store

    monkeypatch.chdir(tmp_path)
    assert isinstance(open_store("nope://x", plugins=(), profile="server"), LocalFileStore)


@pytest.mark.parametrize("spec", ["./findings", "findings", "{tmp}/abs", "C:\\findings",
                                  "c:/findings", "file://{tmp}/viafile"])
def test_a_path_reads_no_entry_points(tmp_path, monkeypatch, lookups, spec):
    from forgd_verdict.store import LocalFileStore, open_store

    monkeypatch.chdir(tmp_path)
    spec = spec.format(tmp=tmp_path)
    assert isinstance(open_store(spec, plugins=(), profile="server"), LocalFileStore)
    assert lookups == []


def test_a_store_scheme_routes_to_its_plugin(acme_store, tmp_path, monkeypatch):
    from forgd_verdict.store import open_store

    monkeypatch.chdir(tmp_path)
    store = open_store("acme://bucket/prefix", "east", plugins=_store_allow(),
                       profile="server")
    assert type(store._plugin_obj).__name__ == "AcmeStore"
    calls = sys.modules[acme_store].CALLS
    assert calls == [("acme://bucket/prefix", "east")]


@pytest.mark.parametrize("spec", ["acme://bucket", "foo://x", "C:\\\\findings", "./findings",
                                  "HTTPS://x"])
def test_without_a_plugin_every_spec_opens_as_before(spec, tmp_path, monkeypatch):
    from forgd_verdict.store import LocalFileStore, open_store

    monkeypatch.chdir(tmp_path)
    assert type(open_store(spec)) is LocalFileStore
    assert type(open_store(spec, plugins=_store_allow(name="other"),
                           profile="server")) is LocalFileStore


def test_a_builtin_scheme_is_never_routed_to_a_plugin(acme_store, tmp_path, monkeypatch):
    from forgd_verdict.store import LocalFileStore, open_store

    monkeypatch.chdir(tmp_path)
    assert type(open_store("file://./x", plugins=_store_allow(), profile="server")) \
        is LocalFileStore
    assert acme_store not in sys.modules


@pytest.mark.parametrize("scheme", ["s3", "gs", "https", "http", "file"])
def test_a_store_plugin_named_like_a_builtin_scheme_refuses(scheme, tmp_path, monkeypatch):
    from forgd_verdict.store import open_store

    monkeypatch.chdir(tmp_path)
    with pytest.raises(RuntimeError, match="built-in stores"):
        open_store("./findings", plugins=_store_allow(name=scheme), profile="server")


def test_a_store_plugin_outside_its_profiles_refuses(acme_store):
    from forgd_verdict.store import open_store

    for profile in ("compliance", None):
        with pytest.raises(RuntimeError, match="does not list"):
            open_store("acme://bucket", plugins=_store_allow(), profile=profile)
    assert acme_store not in sys.modules


def test_a_store_that_does_not_satisfy_the_protocol_refuses(acme_store):
    from forgd_verdict.store import open_store

    with pytest.raises(RuntimeError, match=r"does not satisfy Store; missing \[") as exc:
        open_store("acme://partial", plugins=_store_allow(), profile="server")
    assert "list_audit" in str(exc.value) and "write_verdicts" not in str(exc.value)


def test_a_store_factory_that_raises_is_reported_by_type(acme_store):
    from forgd_verdict.store import open_store

    spec = f"acme://boom?sig={AWS}"
    with pytest.raises(RuntimeError, match="raised ValueError") as exc:
        open_store(spec, plugins=_store_allow(), profile="server")
    assert AWS not in str(exc.value) and exc.value.__context__ is None


def test_every_store_protocol_member_is_checked():
    from forgd_verdict.plugins import protocol_members
    from forgd_verdict.store import Store

    methods, props = protocol_members(Store)
    assert {"write_verdicts", "read_control", "list_audit", "describe"} <= set(methods)
    assert props == []


def test_a_sink_type_routes_to_its_plugin(acme_sink):
    from forgd_verdict.sink.base import SinkConfig
    from forgd_verdict.sink.otlp import build_sink

    cfg = SinkConfig(name="s", type="acme", endpoint="https://x")
    sink = build_sink(cfg, plugins=_sink_allow(), profile="collector", opener="o")
    assert type(sink._plugin_obj).__name__ == "AcmeSink"
    calls = sys.modules[acme_sink].CALLS
    assert calls == [(cfg, {"opener": "o"})]


def test_build_forwarders_routes_a_plugin_sink(acme_sink):
    from forgd_verdict.sink.factory import build_forwarders

    (fw,) = build_forwarders([{"name": "s", "type": "acme", "endpoint": "https://x"}], [],
                             background=False, plugins=_sink_allow(), profile="collector")
    assert type(fw.pipeline.sink._plugin_obj).__name__ == "AcmeSink"
    fw.close()


LEAKY_SOURCE = f"""
from forgd_verdict.store import LocalFileStore
from forgd_verdict.store.base import StoreConflict

SECRET = {AWS!r}


class AcmeError(ValueError):
    pass


class LeakyStore(LocalFileStore):
    def write_verdicts(self, records):
        raise AcmeError("wrote " + SECRET)

    def write_control(self, body, if_etag):
        raise StoreConflict("etag mismatch for " + SECRET)

    def read_verdicts(self, *a, **kw):
        yield from ()
        raise OSError("disk full at " + SECRET)

    def describe(self):
        return {{"kind": "acme", "url": "acme://bucket?sig=" + SECRET}}


def make(spec, instance):
    return LeakyStore("./leaky-store", instance=instance)


class LeakySink:
    max_batch_bytes = 1_000_000
    max_batch_events = 500
    requires_ordering = False

    def __init__(self, config, **kw):
        self.config = config

    def send(self, events):
        raise ValueError("rejected " + SECRET)

    def describe(self):
        return {{"name": self.config.name, "endpoint": "https://x?token=" + SECRET}}

    def close(self):
        return None


def make_sink(config, **kw):
    return LeakySink(config, **kw)
"""


@pytest.fixture
def leaky_store(install, tmp_path, monkeypatch):
    from forgd_verdict.store import open_store

    install(group="stores", name="acme", attr="make", source=LEAKY_SOURCE)
    monkeypatch.chdir(tmp_path)
    return open_store("acme://bucket", "east", plugins=_store_allow(), profile="server")


def _no_chain(exc):
    import traceback

    assert exc.__cause__ is None and exc.__context__ is None
    assert AWS not in "".join(traceback.format_exception(exc))


def test_a_plugin_store_exception_keeps_its_core_class_and_loses_its_message(leaky_store):
    from forgd_verdict.store.base import StoreConflict

    with pytest.raises(ValueError) as exc:
        leaky_store.write_verdicts([])
    assert type(exc.value) is ValueError
    assert str(exc.value) == "stores.acme: write_verdicts raised AcmeError"
    _no_chain(exc.value)
    with pytest.raises(StoreConflict) as exc:
        leaky_store.write_control(b"{}", None)
    assert str(exc.value) == "stores.acme: write_control raised StoreConflict"
    _no_chain(exc.value)


def test_a_plugin_store_iterator_that_raises_is_reduced_to_its_type(leaky_store):
    with pytest.raises(OSError) as exc:
        list(leaky_store.read_verdicts())
    assert str(exc.value) == "stores.acme: read_verdicts raised OSError"
    _no_chain(exc.value)


def test_a_plugin_store_description_is_not_logged(leaky_store, tmp_path, caplog):
    from forgd_verdict.dashboard.app import Dashboard
    from forgd_verdict.plugins import describe_for_log

    assert describe_for_log(leaky_store) == {"plugin": "stores.acme"}
    caplog.set_level(logging.INFO)
    Dashboard(leaky_store)
    assert AWS not in caplog.text
    assert leaky_store.describe()["kind"] == "acme"


def _event():
    from forgd_verdict.sink.base import RedactedEvent

    return RedactedEvent(kind="log", name="e", observed_at="2026-09-21T00:00:00Z", surface="s",
                         org="o")


def test_a_plugin_sink_failure_is_logged_by_type(install, caplog):
    from forgd_verdict.sink.factory import build_forwarders

    install(group="sinks", name="acme", attr="make_sink", source=LEAKY_SOURCE)
    caplog.set_level(logging.DEBUG)
    (fw,) = build_forwarders([{"name": "s", "type": "acme", "endpoint": "https://x"}], [],
                             background=False, plugins=_sink_allow(), profile="collector")
    fw.pipeline.max_retries = 0
    fw.pipeline.offer([_event()])
    fw.pipeline.flush()
    stats = fw.pipeline.stats()
    fw.close()
    assert stats["dropped"] == 1 and stats["sink"] == {"plugin": "sinks.acme"}
    (rec,) = [r for r in caplog.records if r.getMessage() == "sink batch dropped"]
    assert rec.fields["error"] == "ValueError"
    assert rec.fields["sink"] == "sinks.acme"
    assert AWS not in caplog.text


def test_a_builtin_sink_failure_is_logged_by_type(caplog):
    from forgd_verdict.sink.fake import FakeSink
    from forgd_verdict.sink.pipeline import SinkPipeline

    class Failing(FakeSink):
        def send(self, events):
            raise ValueError("collector said no")

    pipe = SinkPipeline(Failing(max_events=10, max_bytes=10_000), background=False)
    pipe.max_retries = 0
    caplog.set_level(logging.WARNING)
    pipe.offer([_event()])
    pipe.flush()
    (rec,) = [r for r in caplog.records if r.getMessage() == "sink batch dropped"]
    assert rec.fields["error"] == "ValueError"
    assert "collector said no" not in caplog.text
    assert "collector said no" not in json.dumps(rec.fields)


def test_an_unknown_plugin_sink_key_refuses_naming_it(acme_sink):
    from forgd_verdict.sink.base import SinkUnavailable
    from forgd_verdict.sink.factory import build_forwarders

    entry = {"name": "s", "type": "acme", "endpoint": "https://x", "hec_channel": "c"}
    with pytest.raises(SinkUnavailable, match=r"unknown keys \['hec_channel'\]"):
        build_forwarders([entry], [], background=False, plugins=_sink_allow(),
                         profile="collector")
    assert acme_sink not in sys.modules


def _ignored_sink_keys(caplog):
    return [r for r in caplog.records
            if r.getMessage() == "sink keys ignored; a built-in sink does not read them"]


@pytest.mark.parametrize("sink_type", [None, "otlp", "azure-monitor"])
@pytest.mark.parametrize("extra,keys", [
    ({"hec_channel": AWS}, ["hec_channel"]),
    ({"options": {"k": AWS}}, ["options"]),
    ({"options": AWS, "zz": AWS, "aa": AWS}, ["aa", "options", "zz"]),
])
def test_a_builtin_sink_ignores_unknown_keys_and_options_with_one_warning(
        caplog, sink_type, extra, keys):
    from forgd_verdict.sink.factory import build_forwarders

    endpoint = ("https://x.ingest.monitor.azure.com/dataCollectionRules/dcr-1/streams/Custom-X"
                if sink_type == "azure-monitor" else "https://x")
    entry = {"name": "s", "endpoint": endpoint, **extra}
    if sink_type is not None:
        entry["type"] = sink_type
    caplog.set_level(logging.DEBUG)
    (fw,) = build_forwarders([entry], [], background=False)
    fw.close()
    assert dict(fw.config.options) == {}
    (rec,) = _ignored_sink_keys(caplog)
    assert rec.levelno == logging.WARNING
    assert rec.fields == {"sink": "s", "keys": keys}
    assert AWS not in caplog.text


def test_a_builtin_sink_with_only_known_keys_warns_nothing(caplog):
    from forgd_verdict.sink.factory import build_forwarders

    caplog.set_level(logging.DEBUG)
    (fw,) = build_forwarders([{"name": "s", "type": "otlp", "endpoint": "https://x"}], [],
                             background=False)
    fw.close()
    assert _ignored_sink_keys(caplog) == []


def test_sink_options_reach_the_plugin_factory_read_only(acme_sink):
    from types import MappingProxyType

    from forgd_verdict.sink.factory import build_forwarders

    options = {"hec_channel": "c-1", "index": {"name": "main", "tags": ["a", "b"]}}
    (fw,) = build_forwarders([{"name": "s", "type": "acme", "endpoint": "https://x",
                               "options": options}],
                             [], background=False, plugins=_sink_allow(), profile="collector")
    fw.close()
    ((config, _kw),) = sys.modules[acme_sink].CALLS
    got = config.options
    assert isinstance(got, MappingProxyType) and isinstance(got["index"], MappingProxyType)
    assert got["index"]["tags"] == ("a", "b")
    with pytest.raises(TypeError):
        got["hec_channel"] = "x"
    with pytest.raises(TypeError):
        got["index"]["name"] = "x"
    options["index"]["name"] = "changed"
    assert got["index"]["name"] == "main"


@pytest.mark.parametrize("sink_type", ["otlp", "azure-monitor"])
def test_a_builtin_sink_built_directly_refuses_options(sink_type):
    from types import MappingProxyType

    from forgd_verdict.sink.base import SinkConfig, SinkUnavailable
    from forgd_verdict.sink.otlp import build_sink

    with pytest.raises(SinkUnavailable, match="takes no `options`"):
        build_sink(SinkConfig(name="s", type=sink_type, endpoint="https://x",
                              options=MappingProxyType({"k": 1})))


def test_a_plugin_sink_options_that_are_not_a_mapping_refuse(acme_sink):
    from forgd_verdict.sink.base import SinkUnavailable
    from forgd_verdict.sink.factory import build_forwarders

    entry = {"name": "s", "type": "acme", "endpoint": "https://x", "options": "c"}
    with pytest.raises(SinkUnavailable, match="`options` must be a mapping"):
        build_forwarders([entry], [], background=False, plugins=_sink_allow(),
                         profile="collector")


def test_a_dollar_reference_in_sink_options_refuses(acme_sink):
    from forgd_verdict.sink.base import SinkUnavailable
    from forgd_verdict.sink.factory import build_forwarders

    entry = {"name": "s", "type": "acme", "endpoint": "https://x",
             "options": {"auth": {"key": "$ACME_KEY"}}}
    with pytest.raises(SinkUnavailable, match=r"sinks\.s\.options\.auth\.key is a `\$`"):
        build_forwarders([entry], [], background=False, plugins=_sink_allow(),
                         profile="collector")


def test_sink_options_are_redacted_on_the_policy_tab(tmp_path):
    from forgd_verdict.policy import load_policy, redacted

    p = tmp_path / "policy.yaml"
    p.write_text(textwrap.dedent(f"""
        sinks:
          - {{name: hec, type: acme, endpoint: 'https://hec.example',
             options: {{hec_channel: {AWS}, index: {{name: {AWS}}}}}}}
          - {{name: odd, type: acme, endpoint: 'https://x', options: {AWS}}}
          - {{name: otel, type: otlp, endpoint: 'https://otel.example', stale: {AWS},
             options: {{k: {AWS}}}}}
    """))
    hec, odd, otel = redacted(load_policy(p))["sinks"]
    assert otel["stale"] == "<redacted>"
    assert otel["options"] == {"k": "<redacted>"}
    assert otel["endpoint"] == "https://otel.example"
    assert hec["options"] == {"hec_channel": "<redacted>", "index": "<redacted>"}
    assert odd["options"] == "<redacted>"
    assert hec["endpoint"] == "https://hec.example"


def test_an_unknown_sink_type_without_a_plugin_raises_as_before(acme_sink):
    from forgd_verdict.sink.base import SinkConfig, SinkUnavailable
    from forgd_verdict.sink.otlp import build_sink

    expected = (
        "sink 's' has type 'splunk'; built types are 'otlp' and 'azure-monitor'. "
        "Splunk HEC, CloudWatch, Datadog and Cribl each need a new Sink implementation "
        "registered in build_sink; nothing else changes."
    )
    cfg = SinkConfig(name="s", type="splunk", endpoint="https://x")
    for kw in ({}, {"plugins": _sink_allow(), "profile": "collector"}):
        with pytest.raises(SinkUnavailable) as exc:
            build_sink(cfg, **kw)
        assert str(exc.value) == expected
    assert acme_sink not in sys.modules


@pytest.mark.parametrize("name", ["otlp", "azure-monitor"])
def test_a_sink_plugin_named_like_a_builtin_type_refuses(name):
    from forgd_verdict.sink.base import SinkConfig
    from forgd_verdict.sink.otlp import build_sink

    cfg = SinkConfig(name="s", type="otlp", endpoint="https://x")
    with pytest.raises(RuntimeError, match="built-in sinks"):
        build_sink(cfg, plugins=_sink_allow(name=name), profile="collector")


def test_a_sink_that_does_not_satisfy_the_protocol_refuses(acme_sink):
    from forgd_verdict.sink.base import SinkConfig
    from forgd_verdict.sink.otlp import build_sink

    cfg = SinkConfig(name="partial", type="acme", endpoint="https://x")
    with pytest.raises(RuntimeError, match="does not satisfy Sink") as exc:
        build_sink(cfg, plugins=_sink_allow(), profile="collector")
    assert "max_batch_bytes" in str(exc.value) and "requires_ordering" in str(exc.value)


def test_a_sink_plugin_outside_its_profiles_refuses(acme_sink):
    from forgd_verdict.sink.base import SinkConfig
    from forgd_verdict.sink.otlp import build_sink

    cfg = SinkConfig(name="s", type="acme", endpoint="https://x")
    with pytest.raises(RuntimeError, match="does not list"):
        build_sink(cfg, plugins=_sink_allow(), profile="server")


# -- invariants ------------------------------------------------------------


def test_env_overrides_is_read_only():
    from types import MappingProxyType

    from forgd_verdict.policy import ENV_OVERRIDES

    assert isinstance(ENV_OVERRIDES, MappingProxyType)
    with pytest.raises(TypeError):
        ENV_OVERRIDES["FORGD_EVIL"] = (("detectors", "t0_regex", "severity"), str)


REBIND_SOURCE = """
from types import MappingProxyType
import forgd_verdict.policy as _p
_p.ENV_OVERRIDES = MappingProxyType(
    {**_p.ENV_OVERRIDES, "FORGD_EVIL": (("detectors", "t0_regex", "severity"), str)})
"""

MUTATE_SOURCE = """
import gc
import forgd_verdict.policy as _p
gc.get_referents(_p.ENV_OVERRIDES)[0]["FORGD_EVIL"] = (("privacy", "hash_salt"), str)
"""


def test_a_plugin_that_rebinds_env_overrides_refuses(install, monkeypatch):
    from forgd_verdict import policy

    monkeypatch.setattr(policy, "ENV_OVERRIDES", policy.ENV_OVERRIDES)
    install(source=REBIND_SOURCE)
    with pytest.raises(RuntimeError, match="ENV_OVERRIDES changed"):
        load_plugins(_allow(), "detectors", "server", set())


def test_a_plugin_that_mutates_env_overrides_refuses(install):
    import gc

    from forgd_verdict import policy

    install(source=MUTATE_SOURCE)
    try:
        with pytest.raises(RuntimeError, match="ENV_OVERRIDES changed"):
            load_plugins(_allow(), "detectors", "server", set())
    finally:
        gc.get_referents(policy.ENV_OVERRIDES)[0].pop("FORGD_EVIL", None)


EVIL_SOURCE = """
EVIL = None


def _evil():
    import gc
    from types import MappingProxyType

    import forgd_verdict.policy as _p

    spec = (("detectors", "t0_regex", "severity"), str)
    if EVIL == "rebind":
        _p.ENV_OVERRIDES = MappingProxyType({**_p.ENV_OVERRIDES, "FORGD_EVIL": spec})
    elif EVIL == "mutate":
        gc.get_referents(_p.ENV_OVERRIDES)[0]["FORGD_EVIL"] = spec
    elif EVIL == "unfreeze":
        _p.ENV_OVERRIDES = dict(_p.ENV_OVERRIDES)
"""


@pytest.fixture
def scratch_overrides(monkeypatch):
    """`policy.ENV_OVERRIDES` as a fresh proxy over a copy, so a plugin that
    mutates it does not touch the real one."""
    from types import MappingProxyType

    from forgd_verdict import policy

    monkeypatch.setattr(policy, "ENV_OVERRIDES", MappingProxyType(dict(policy.ENV_OVERRIDES)))
    monkeypatch.setenv("FORGD_EVIL", "warn")
    return policy


def _overrides_still_apply_as_shipped(policy, tmp_path):
    p = tmp_path / "plain.yaml"
    p.write_text("{}\n")
    assert policy.load_policy(p).raw["detectors"]["t0_regex"]["severity"] == "block"


@pytest.mark.parametrize("kind", ["rebind", "mutate", "unfreeze"])
def test_a_detector_factory_that_changes_env_overrides_refuses(
        tmp_path, install, scratch_overrides, kind):
    mod = install(name="zebra", attr="make", source=DETECTOR_SOURCE + EVIL_SOURCE + """
_make = make
def make(cfg, severity, hasher):
    _evil()
    return _make(cfg, severity, hasher)
""")
    pol = _policy(tmp_path)
    importlib_mod = __import__("importlib").import_module(mod)
    importlib_mod.EVIL = kind
    with pytest.raises(RuntimeError, match=r"^detectors\.zebra: ENV_OVERRIDES changed while"):
        pol.build_detectors(profile="server")
    _overrides_still_apply_as_shipped(scratch_overrides, tmp_path)


@pytest.mark.parametrize("kind", ["rebind", "mutate"])
def test_a_store_factory_that_changes_env_overrides_refuses(
        tmp_path, install, monkeypatch, scratch_overrides, kind):
    from forgd_verdict.store import open_store

    mod = install(group="stores", name="acme", attr="make", source=STORE_SOURCE + EVIL_SOURCE
                  + "\n_make = make\ndef make(spec, instance):\n    _evil()\n"
                    "    return _make(spec, instance)\n")
    monkeypatch.chdir(tmp_path)
    __import__("importlib").import_module(mod).EVIL = kind
    with pytest.raises(RuntimeError, match=r"^stores\.acme: ENV_OVERRIDES changed while"):
        open_store("acme://bucket", "east", plugins=_store_allow(), profile="server")
    _overrides_still_apply_as_shipped(scratch_overrides, tmp_path)


@pytest.mark.parametrize("kind", ["rebind", "mutate"])
def test_a_sink_factory_that_changes_env_overrides_refuses(
        tmp_path, install, scratch_overrides, kind):
    from forgd_verdict.sink.base import SinkConfig
    from forgd_verdict.sink.otlp import build_sink

    mod = install(group="sinks", name="acme", attr="make", source=SINK_SOURCE + EVIL_SOURCE
                  + "\n_make = make\ndef make(config, **kw):\n    _evil()\n"
                    "    return _make(config, **kw)\n")
    __import__("importlib").import_module(mod).EVIL = kind
    with pytest.raises(RuntimeError, match=r"^sinks\.acme: ENV_OVERRIDES changed while"):
        build_sink(SinkConfig(name="s", type="acme", endpoint="https://x"),
                   plugins=_sink_allow(), profile="collector")
    _overrides_still_apply_as_shipped(scratch_overrides, tmp_path)


@pytest.mark.parametrize("kind", ["rebind", "mutate"])
def test_a_dashboard_rebuild_that_changes_env_overrides_refuses(
        tmp_path, install, monkeypatch, scratch_overrides, kind):
    from forgd_verdict.dashboard.app import POLICY_CACHE

    mod = install(name="zebra", attr="make", source=DETECTOR_SOURCE + EVIL_SOURCE + """
_make = make
def make(cfg, severity, hasher):
    _evil()
    return _make(cfg, severity, hasher)
""")
    _tab_policy(tmp_path, monkeypatch)
    first, _ = POLICY_CACHE.detectors()
    plugin = __import__("importlib").import_module(mod)
    plugin.EVIL = kind
    assert POLICY_CACHE.detectors()[0] is first
    assert POLICY_CACHE.detectors()[0] is first
    path = tmp_path / "policy.yaml"
    path.write_text(path.read_text().replace("0.875", "0.5"))
    with pytest.raises(RuntimeError, match="ENV_OVERRIDES changed while"):
        POLICY_CACHE.detectors()
    with pytest.raises(RuntimeError, match="ENV_OVERRIDES (changed while|differs from)"):
        POLICY_CACHE.detectors()
    _overrides_still_apply_as_shipped(scratch_overrides, tmp_path)


def test_env_overrides_is_unchanged_after_plugins_load(tmp_path, zebra):
    from forgd_verdict import policy

    before = dict(policy.ENV_OVERRIDES)
    _policy(tmp_path).build_detectors(profile="server")
    assert dict(policy.ENV_OVERRIDES) == before


@pytest.mark.parametrize("cfg,where", [
    ({"api_key": "$ZEBRA_KEY"}, "detectors.zebra.api_key"),
    ({"hosts": ["a", "$ZEBRA_HOST"]}, r"detectors.zebra.hosts\[1\]"),
    ({"auth": {"inner": [{"k": "$Z"}]}}, r"detectors.zebra.auth.inner\[0\].k"),
])
def test_a_dollar_value_in_plugin_config_refuses(tmp_path, cfg, where):
    pol = _policy(tmp_path, cfg=cfg)
    for profile in (None, "server"):
        with pytest.raises(RuntimeError, match=rf"^{where} is a `\$` reference"):
            pol.build_detectors(profile=profile)


def test_a_dollar_value_in_a_profile_section_refuses(tmp_path):
    pol = _policy(tmp_path, extra="compliance:\n  detectors:\n    zebra: {token: $Z}\n")
    with pytest.raises(RuntimeError, match=r"compliance.detectors.zebra.token"):
        pol.build_detectors()


def test_the_builtin_gitleaks_daemon_keeps_its_dollar(tmp_path, monkeypatch):
    from forgd_verdict.policy import load_policy

    monkeypatch.delenv("FORGD_GITLEAKSD", raising=False)
    p = tmp_path / "policy.yaml"
    p.write_text("detectors: {gitleaks: {enabled: auto, daemon: $FORGD_GITLEAKSD}}\n")
    load_policy(p).build_detectors()


def test_the_runtime_override_allowlist_never_reaches_detectors_or_plugins():
    from forgd_verdict.overrides import ALLOWLIST

    for key, (path, _validator) in ALLOWLIST.items():
        assert isinstance(key, str)
        assert not key.startswith(("detectors.", "plugins.")), key
        assert path[0] not in ("detectors", "privacy", "plugins"), (key, path)


# -- the Policy tab --------------------------------------------------------

PUBLIC_SOURCE = DETECTOR_SOURCE + "\nZebra.public_keys = ('threshold',)\n"
PLUGIN_SECRET = "zebra-api-SUPERSECRET"


def _tab_policy(tmp_path, monkeypatch, profiles=("dashboard",)):
    pol = _policy(tmp_path, profiles=profiles,
                  cfg={"api_key": PLUGIN_SECRET, "threshold": 0.875,
                       "nested": {"k": "nested-SUPERSECRET"}},
                  extra=textwrap.dedent("""
                      sinks:
                        - {name: hec, type: acme, endpoint: 'https://hec.example',
                           options: {hec_channel: channel-SUPERSECRET},
                           token: token-SUPERSECRET}
                        - {name: std, type: otlp, endpoint: 'https://otlp.example',
                           token: otlp-SUPERSECRET}
                  """))
    monkeypatch.setenv("FORGD_VERDICT_POLICY", str(tmp_path / "policy.yaml"))
    return pol


def _tab(tmp_path):
    from forgd_verdict.dashboard.app import Dashboard
    from forgd_verdict.store import LocalFileStore

    return Dashboard(LocalFileStore(tmp_path / "p", instance="t"))._policy()


def test_the_policy_tab_redacts_plugin_config_and_shows_public_keys(
        tmp_path, monkeypatch, install):
    install(name="zebra", attr="make", source=PUBLIC_SOURCE)
    _tab_policy(tmp_path, monkeypatch)
    html = _tab(tmp_path)
    assert "SUPERSECRET" not in html
    assert "0.875" in html  # declared public, and loaded by this render
    assert "hec.example" in html and "otlp.example" in html
    assert '<span class="k">plugins</span>:' in html and "acme-forgd" in html
    assert "zebra" in html


def test_an_unloaded_plugin_shows_only_enabled_and_severity(tmp_path, monkeypatch, install):
    from forgd_verdict.policy import redacted

    mod = install(name="zebra", attr="make", source=PUBLIC_SOURCE)
    pol = _tab_policy(tmp_path, monkeypatch, profiles=("server",))
    html = _tab(tmp_path)
    assert mod not in sys.modules
    assert "SUPERSECRET" not in html and "0.875" not in html
    cfg = redacted(pol)["detectors"]["zebra"]
    assert cfg == {"enabled": True, "severity": "block", "api_key": "<redacted>",
                   "threshold": "<redacted>", "nested": "<redacted>"}


def test_redaction_covers_the_profile_sections(tmp_path):
    from forgd_verdict.policy import redacted

    pol = _policy(tmp_path, extra="server:\n  detectors:\n    zebra: {api_key: s3kr1t}\n")
    assert redacted(pol)["server"]["detectors"]["zebra"]["api_key"] == "<redacted>"


def _store_policy(tmp_path, specs):
    from forgd_verdict.policy import load_policy

    p = tmp_path / "policy.yaml"
    p.write_text(textwrap.dedent(f"""
        plugins:
          allow:
            - {{name: acme, group: stores, dist: acme-forgd, version: 1.4.2,
               profiles: [server]}}
        server: {{store: {json.dumps(specs[0])}}}
        otel: {{store: {json.dumps(specs[1])}}}
        intake: {{store: {json.dumps(specs[2])}}}
        hook: {{ship_store: {json.dumps(specs[3])}}}
    """))
    return load_policy(p)


def test_a_plugin_store_spec_shows_only_its_scheme():
    import tempfile
    from pathlib import Path

    from forgd_verdict.policy import redacted

    secret = f"acme://bucket/prefix?sig={AWS}"
    pol = _store_policy(Path(tempfile.mkdtemp()), [secret, "acme:/other", secret, secret])
    out = redacted(pol)
    assert out["server"]["store"] == "acme:<redacted>"
    assert out["otel"]["store"] == "acme:<redacted>"
    assert out["intake"]["store"] == "acme:<redacted>"
    assert out["hook"]["ship_store"] == "acme:<redacted>"
    assert AWS not in json.dumps(out)


def test_builtin_store_specs_show_as_before(tmp_path):
    from forgd_verdict.policy import redacted

    specs = ["./findings", "https://acct.blob.core.windows.net/c/p", "s3://bucket/p",
             "nope://not-a-plugin"]
    out = redacted(_store_policy(tmp_path, specs))
    assert [out["server"]["store"], out["otel"]["store"], out["intake"]["store"],
            out["hook"]["ship_store"]] == specs


def test_plugin_sink_entries_show_only_sinkconfig_fields(tmp_path, monkeypatch):
    from forgd_verdict.policy import redacted

    pol = _tab_policy(tmp_path, monkeypatch)
    hec, std = redacted(pol)["sinks"]
    assert hec == {"name": "hec", "type": "acme", "endpoint": "https://hec.example",
                   "options": {"hec_channel": "<redacted>"}, "token": "<redacted>"}
    assert std == {"name": "std", "type": "otlp", "endpoint": "https://otlp.example",
                   "token": "<redacted>"}


def test_the_sink_key_lists_match_the_sink_package():
    import dataclasses

    from forgd_verdict.policy import BUILTIN_SINK_TYPES, SINK_STANDARD_KEYS
    from forgd_verdict.sink import otlp
    from forgd_verdict.sink.base import SinkConfig

    fields = {f.name for f in dataclasses.fields(SinkConfig)}
    assert fields == SINK_STANDARD_KEYS
    assert BUILTIN_SINK_TYPES == otlp.BUILTIN_SINK_TYPES


def test_public_keys_are_recorded_at_build_without_loading_in_redacted(
        tmp_path, install, monkeypatch):
    from forgd_verdict.policy import redacted

    install(name="zebra", attr="make", source=PUBLIC_SOURCE)
    pol = _policy(tmp_path, cfg={"threshold": 3})
    with monkeypatch.context() as m:
        m.setattr(plugins_mod.importlib.metadata, "entry_points",
                  lambda **kw: (_ for _ in ()).throw(AssertionError("loaded")))
        assert redacted(pol)["detectors"]["zebra"]["threshold"] == "<redacted>"
    pol.build_detectors(profile="server")
    assert redacted(pol)["detectors"]["zebra"]["threshold"] == 3


API_KEY_PUBLIC = DETECTOR_SOURCE + "\nZebra.public_keys = ('api_key',)\n"


@pytest.mark.parametrize("second", [
    {"profiles": ("server",)},
    {"version": "1.4.3"},
])
def test_public_keys_belong_to_the_policy_that_loaded_the_plugin(
        tmp_path, install, second):
    """A second policy whose allow entry excludes this profile, or names
    another version, shows nothing the first policy's build recorded."""
    from forgd_verdict.policy import load_policy, redacted

    install(name="zebra", attr="make", source=API_KEY_PUBLIC)
    first = _policy(tmp_path, profiles=("dashboard",), cfg={"api_key": "shown-v1"})
    first.build_detectors(profile="dashboard")
    assert redacted(first)["detectors"]["zebra"]["api_key"] == "shown-v1"

    (tmp_path / "two").mkdir()
    text = (tmp_path / "policy.yaml").read_text()
    text = text.replace('["dashboard"]', json.dumps(list(second.get("profiles", ["dashboard"]))))
    text = text.replace("version: 1.4.2", f"version: {second.get('version', '1.4.2')}")
    (tmp_path / "two" / "policy.yaml").write_text(text)
    other = load_policy(tmp_path / "two" / "policy.yaml")
    try:
        assert not _zebras(other.build_detectors(profile="dashboard"))
    except RuntimeError as exc:
        assert "pins 1.4.3" in str(exc)
    assert redacted(other)["detectors"]["zebra"]["api_key"] == "<redacted>"
    assert redacted(first)["detectors"]["zebra"]["api_key"] == "shown-v1"


def test_public_keys_need_the_same_distribution_and_version(tmp_path, install):
    """Defence in depth: a registry is consulted by (name, dist, version)."""
    from forgd_verdict.policy import load_policy, redacted

    install(name="zebra", attr="make", source=API_KEY_PUBLIC)
    first = _policy(tmp_path, profiles=("dashboard",), cfg={"api_key": "shown-v1"})
    first.build_detectors(profile="dashboard")
    text = (tmp_path / "policy.yaml").read_text().replace("version: 1.4.2", "version: 9.9.9")
    (tmp_path / "policy.yaml").write_text(text)
    other = load_policy(tmp_path / "policy.yaml")
    other._plugins = first._plugins
    assert redacted(other)["detectors"]["zebra"]["api_key"] == "<redacted>"


def test_a_policy_that_does_not_load_the_plugin_has_none_of_its_phrases(tmp_path, zebra):
    from forgd_verdict.core import build_deny_reason, decide, scan

    first = _policy(tmp_path, profiles=("server",))
    dets = first.build_detectors(profile="server")
    res = scan([ScanUnit("m", None, "zebra-123456")], dets)
    assert "a zebra code" in decide(res.findings, first).deny_reason

    other = _policy(tmp_path, profiles=("hook",))
    assert not _zebras(other.build_detectors(profile="server"))
    assert other.plugin_phrases().get("zebra:stripe") is None
    assert "restricted content" in decide(res.findings, other).deny_reason
    assert "a zebra code" not in build_deny_reason(["zebra:stripe"])


def test_for_profile_shares_the_registry(tmp_path, zebra):
    pol = _policy(tmp_path, extra="server:\n  detectors:\n    entropy: {enabled: false}\n")
    server = pol.for_profile("server")
    assert server is not pol
    server.build_detectors(profile="server")
    assert pol.plugin_phrases() == {"zebra:stripe": "a zebra code"}


def test_a_new_load_starts_with_an_empty_registry(tmp_path, zebra):
    from forgd_verdict.policy import load_policy

    pol = _policy(tmp_path)
    pol.build_detectors(profile="server")
    again = load_policy(tmp_path / "policy.yaml")
    assert again.plugin_phrases() == {}
    assert again._plugins is not pol._plugins
    again.build_detectors(profile="hook")
    assert again.plugin_phrases() == {}


def test_the_collector_sink_detectors_register_on_the_collector_policy(
        tmp_path, install, base_build):
    """`otel.sink_detectors` are built from a policy `derive`d from the
    collector's, so what they register is visible through the collector's."""
    import forgd_verdict
    from forgd_verdict.otel.app import Collector
    from forgd_verdict.policy import redacted

    install(name="zebra", attr="make",
            source=API_KEY_PUBLIC + "\nZebra.tier = 2\n")
    pol = _policy(tmp_path, profiles=("collector",), cfg={"enabled": False},
                  extra="otel:\n  sink_detectors:\n"
                        "    zebra: {enabled: true, severity: block, api_key: k-1}\n")
    collector = Collector(pol, logger=_test_logger())
    assert forgd_verdict.build_id() == base_build
    (late,) = _zebras(collector._late_detectors())
    assert late.tier == 2
    assert collector.policy.plugin_phrases() == {"zebra:stripe": "a zebra code"}
    shown = redacted(collector.policy)["otel"]["sink_detectors"]["zebra"]
    assert shown["api_key"] == "k-1"
    assert forgd_verdict.build_id() == base_build + "+acme-forgd=1.4.2"


# -- the dashboard's policy cache --------------------------------------


@pytest.fixture
def lookups(monkeypatch):
    calls = []
    real = plugins_mod.importlib.metadata.entry_points

    def counting(**kw):
        calls.append(kw.get("group"))
        return real(**kw)

    monkeypatch.setattr(plugins_mod.importlib.metadata, "entry_points", counting)
    return calls


def _requests(tmp_path, n):
    from forgd_verdict.dashboard import app as dashboard_app

    for _ in range(n):
        _tab(tmp_path)
        dashboard_app._screened_who("dana", lambda who: who)
        dashboard_app._exclusion_labeler()
        dashboard_app._org_screen()


def test_dashboard_requests_on_one_policy_load_the_plugin_once(
        tmp_path, monkeypatch, zebra, lookups):
    _tab_policy(tmp_path, monkeypatch)
    _requests(tmp_path, 4)
    assert lookups == ["forgd_verdict.detectors"]
    assert len(sys.modules[zebra].SEEN) == 1

    path = tmp_path / "policy.yaml"
    path.write_text(path.read_text().replace("0.875", "0.5"))
    _requests(tmp_path, 3)
    assert len(lookups) == 2 and len(sys.modules[zebra].SEEN) == 2
    assert "0.5" in _tab(tmp_path)


def test_dashboard_requests_without_plugins_read_no_entry_points(
        tmp_path, monkeypatch, lookups):
    path = tmp_path / "policy.yaml"
    path.write_text("detectors: {entropy: {enabled: false}}\n")
    monkeypatch.setenv("FORGD_VERDICT_POLICY", str(path))
    _requests(tmp_path, 3)
    assert lookups == []


@pytest.mark.parametrize("change", ["ref", "override"])
def test_an_environment_change_the_policy_reads_reloads_it(
        tmp_path, monkeypatch, zebra, change):
    from forgd_verdict.dashboard.app import POLICY_CACHE

    _tab_policy(tmp_path, monkeypatch)
    path = tmp_path / "policy.yaml"
    path.write_text(path.read_text().replace(f"hash_salt: {SALT}", "hash_salt: $ZEBRA_SALT"))
    monkeypatch.setenv("ZEBRA_SALT", "one")
    first, _ = POLICY_CACHE.detectors()
    assert POLICY_CACHE.detectors()[0] is first
    if change == "ref":
        monkeypatch.setenv("ZEBRA_SALT", "two")
    else:
        monkeypatch.setenv("FORGD_VERDICT_MODE", "enforce")
    second, _ = POLICY_CACHE.detectors()
    assert second is not first
    assert len(sys.modules[zebra].SEEN) == 2


def test_a_policy_change_drops_the_old_policy_and_its_build_id(
        tmp_path, monkeypatch, zebra, base_build):
    import gc

    import forgd_verdict
    from forgd_verdict.dashboard.app import POLICY_CACHE

    _tab_policy(tmp_path, monkeypatch)
    POLICY_CACHE.detectors()
    assert forgd_verdict.build_id() == base_build + "+acme-forgd=1.4.2"
    path = tmp_path / "policy.yaml"
    path.write_text("detectors: {entropy: {enabled: false}}\n")
    POLICY_CACHE.detectors()
    gc.collect()
    assert forgd_verdict.build_id() == base_build


def test_a_policy_that_stops_loading_clears_the_cache(
        tmp_path, monkeypatch, zebra, base_build):
    import forgd_verdict
    from forgd_verdict.dashboard.app import POLICY_CACHE

    _tab_policy(tmp_path, monkeypatch)
    POLICY_CACHE.detectors()
    (tmp_path / "policy.yaml").write_text("detectors: [unterminated\n")
    import yaml

    with pytest.raises(yaml.YAMLError):
        POLICY_CACHE.policy()
    assert forgd_verdict.build_id() == base_build
    assert "could not be loaded" in _tab(tmp_path)


# -- build_id --------------------------------------------------------------


def test_build_id_is_unchanged_without_plugins(monkeypatch):
    import forgd_verdict

    monkeypatch.setattr(forgd_verdict, "build_commit", "abc123def4567890")
    assert forgd_verdict.build_id() == f"{forgd_verdict.__version__}+abc123def456"


@pytest.fixture
def base_build(monkeypatch):
    import forgd_verdict

    monkeypatch.setattr(forgd_verdict, "build_commit", "abc123def4567890")
    return f"{forgd_verdict.__version__}+abc123def456"


def test_a_plugin_in_use_appends_its_distribution(tmp_path, zebra, base_build):
    import gc

    import forgd_verdict

    pol = _policy(tmp_path)
    load_plugins(pol.plugin_allow, "detectors", "server", set())
    assert forgd_verdict.build_id() == base_build
    assert _zebras(pol.build_detectors(profile="server"))
    assert forgd_verdict.build_id() == base_build + "+acme-forgd=1.4.2"
    del pol
    gc.collect()
    assert forgd_verdict.build_id() == base_build


def test_a_dropped_policy_leaves_build_id_without_the_garbage_collector(
        tmp_path, zebra, base_build):
    """Freed by reference counting alone: nothing a policy builds refers back
    to it, even when its detectors outlive it."""
    import gc

    import forgd_verdict
    from forgd_verdict.core import decide, scan
    from forgd_verdict.policy import redacted

    def use():
        pol = _policy(tmp_path, profiles=("server", "dashboard"),
                      extra="server:\n  detectors:\n    entropy: {enabled: false}\n")
        dets = pol.build_detectors(profile="dashboard")
        server = pol.for_profile("server")
        server.build_detectors(profile="server")
        redacted(pol)
        res = scan([ScanUnit("m", None, "zebra-123456")], dets)
        assert "a zebra code" in decide(res.findings, server).deny_reason
        assert forgd_verdict.build_id() == base_build + "+acme-forgd=1.4.2"
        return dets

    was_enabled = gc.isenabled()
    gc.disable()
    try:
        kept = use()
        assert _zebras(kept)
        assert forgd_verdict.build_id() == base_build
    finally:
        if was_enabled:
            gc.enable()


def test_build_id_names_detector_and_sink_distributions_sorted(
        tmp_path, zebra, install, base_build):
    import forgd_verdict
    from forgd_verdict.sink.base import SinkConfig
    from forgd_verdict.sink.otlp import build_sink

    install(group="sinks", name="beta", dist="Beta.Forgd", version="2.0.0", attr="make",
            source=SINK_SOURCE)
    pol = _policy(tmp_path)
    pol.build_detectors(profile="server")
    build_sink(SinkConfig(name="s", type="beta", endpoint="https://x"),
               plugins=_sink_allow(name="beta", dist="beta-forgd", version="2.0.0"),
               profile="collector")
    assert forgd_verdict.build_id() == (
        base_build + "+acme-forgd=1.4.2+beta-forgd=2.0.0")


@pytest.mark.parametrize("cfg,local", [
    ({"enabled": "auto", "unavailable_for_test": True}, False),
    ({"local_only_for_test": True}, False),
])
def test_a_plugin_built_but_not_used_leaves_build_id_unchanged(
        tmp_path, zebra, base_build, cfg, local):
    import forgd_verdict

    pol = _policy(tmp_path, cfg=cfg)
    assert not _zebras(pol.build_detectors(include_local_only=local, profile="server"))
    assert forgd_verdict.build_id() == base_build


def test_a_plugin_whose_factory_raises_leaves_build_id_unchanged(
        tmp_path, install, base_build):
    import forgd_verdict

    install(name="zebra", attr="make",
            source=DETECTOR_SOURCE + "\ndef make(cfg, severity, hasher):\n"
                                     "    raise ValueError('no')\n")
    pol = _policy(tmp_path)
    with pytest.raises(RuntimeError, match="factory raised ValueError"):
        pol.build_detectors(profile="server")
    assert forgd_verdict.build_id() == base_build


def test_a_sink_that_does_not_conform_leaves_build_id_unchanged(acme_sink, base_build):
    import forgd_verdict
    from forgd_verdict.sink.base import SinkConfig
    from forgd_verdict.sink.otlp import build_sink

    with pytest.raises(RuntimeError, match="does not satisfy Sink"):
        build_sink(SinkConfig(name="partial", type="acme", endpoint="https://x"),
                   plugins=_sink_allow(), profile="collector")
    assert forgd_verdict.build_id() == base_build


def _test_logger():
    return logging.getLogger("forgd_verdict_test.server")


def _server_policy(tmp_path):
    from conftest import WHSEC

    return _policy(tmp_path, extra=textwrap.dedent(f"""
        server:
          mode: enforce
          secrets: [{WHSEC}]
          csv_path: null
          store: {tmp_path / "store"}
          store_batch_size: 1
          detectors:
            gitleaks: {{enabled: false}}
        """))


async def test_healthz_the_startup_log_and_records_carry_the_plugin_set(
        tmp_path, zebra, caplog):
    import json as _json

    from conftest import ASGIClient, frame, sign, text_msg

    from forgd_verdict.server.app import VerdictServer
    from forgd_verdict.store import LocalFileStore

    caplog.set_level(logging.INFO)
    server = VerdictServer(_server_policy(tmp_path), logger=_test_logger())
    try:
        client = ASGIClient(server)
        status, body = await client.get("/healthz")
        assert status == 200 and body["build"].endswith("+acme-forgd=1.4.2")
        raw = _json.dumps(frame([text_msg("pay zebra-123456 now")])).encode()
        status, verdict = await client.post("/hook", raw, sign(raw))
        assert verdict["action"] == "deny"
    finally:
        server.close()
    (ready,) = [r for r in caplog.records if r.getMessage() == "verdict server ready"]
    assert ready.fields["build"].endswith("+acme-forgd=1.4.2")
    records = list(LocalFileStore(tmp_path / "store").read_verdicts())
    assert records and all(r.build.endswith("+acme-forgd=1.4.2") for r in records)


async def test_without_plugins_the_startup_log_has_no_build_field(tmp_path, caplog):
    from conftest import WHSEC, make_policy

    from forgd_verdict.server.app import VerdictServer

    caplog.set_level(logging.INFO)
    server = VerdictServer(make_policy(
        detectors={"gitleaks": {"enabled": False, "severity": "block"}},
        server={"mode": "enforce", "secrets": [WHSEC], "csv_path": None}),
        logger=_test_logger())
    server.close()
    (ready,) = [r for r in caplog.records if r.getMessage() == "verdict server ready"]
    assert "build" not in ready.fields


class _Records(logging.Handler):
    def __init__(self):
        super().__init__(logging.DEBUG)
        self.records: list[logging.LogRecord] = []

    def emit(self, record):
        self.records.append(record)


def _ready_fields(logger_name, message, build):
    handler = _Records()
    logger = logging.getLogger(logger_name)
    level = logger.level
    logger.addHandler(handler)
    logger.setLevel(logging.INFO)
    try:
        build()
    finally:
        logger.removeHandler(handler)
        logger.setLevel(level)
    (rec,) = [r for r in handler.records if r.getMessage() == message]
    return rec.fields


def test_the_collector_ready_log_carries_build_only_with_plugins(tmp_path, zebra):
    from forgd_verdict.otel.app import Collector

    def ready(pol):
        return _ready_fields("forgd_verdict_test.server", "otel collector ready",
                             lambda: Collector(pol, logger=_test_logger()))

    assert "build" not in ready(_policy(tmp_path, profiles=["server"]))
    assert ready(_policy(tmp_path, profiles=["collector"]))["build"].endswith(
        "+acme-forgd=1.4.2")


@pytest.mark.parametrize("which", ["intake", "dashboard"])
def test_intake_and_dashboard_ready_logs_carry_build_only_with_plugins(which, tmp_path, zebra):
    from forgd_verdict.dashboard.app import Dashboard
    from forgd_verdict.intake.app import Intake
    from forgd_verdict.policy import Policy
    from forgd_verdict.store import LocalFileStore

    def ready():
        store = LocalFileStore(tmp_path / "s", instance="t")
        if which == "intake":
            return _ready_fields("forgd_verdict", "findings intake ready",
                                 lambda: Intake(Policy(raw={"privacy": {"allow_unsalted": True},
                                                            "intake": {"clients": []}}),
                                                store=store))
        return _ready_fields("forgd_verdict.dashboard", "dashboard ready",
                             lambda: Dashboard(store))

    assert "build" not in ready()
    pol = _policy(tmp_path, profiles=[which])
    assert _zebras(pol.build_detectors(profile=which))
    assert ready()["build"].endswith("+acme-forgd=1.4.2")


# -- the conformance kit ---------------------------------------------------

KIT_PLUGIN = '''
import logging
import os
import re
import warnings

from forgd_verdict.models import Finding

AWS = re.compile(r"AKIA[0-9A-Z]{16}")


class Good:
    tier = 1
    finding_prefix = "kitplug"

    def __init__(self, cfg, severity, hasher):
        self.severity, self.hasher = severity, hasher

    def available(self):
        return True

    def phrases(self):
        return {"kitplug:aws": "an access key found by the kit plugin"}

    def finding_ids(self):
        return ["kitplug:aws"]

    def emit(self, u, m):
        return Finding("kitplug:aws", self.severity, u.locator, self.hasher(m.group()),
                       u.tool_name, m.start(), m.end())

    def scan(self, units):
        return [self.emit(u, m) for u in units for m in AWS.finditer(u.text)]


class LogsText(Good):
    def scan(self, units):
        for u in units:
            logging.getLogger("acme.plugin").debug("scanning %s", u.text)
        return super().scan(units)


class RaisesText(Good):
    def scan(self, units):
        if len(units) < 2:
            return []
        try:
            {}[units[0].text]
        except KeyError as exc:
            raise RuntimeError("lookup failed") from exc


class LocatorText(Good):
    def emit(self, u, m):
        f = super().emit(u, m)
        return Finding(f.detector, f.severity, m.group(), f.excerpt_hash, f.tool_name)


class PhraseText(Good):
    def phrases(self):
        return {"kitplug:aws": "a key such as AKIAIOSFODNN7EXAMPLE"}


class ReadsEnviron(Good):
    def scan(self, units):
        os.environ.get("ACME_API_KEY")
        return super().scan(units)


class ReadsEnvironInFactory(Good):
    def __init__(self, cfg, severity, hasher):
        super().__init__(cfg, severity, hasher)
        self.key = os.getenv("ACME_API_KEY")


class PrintsText(Good):
    def scan(self, units):
        print(units[-1].text)
        return super().scan(units)


class WarnsText(Good):
    def scan(self, units):
        warnings.warn(units[-1].text)
        return super().scan(units)


class LogsTail(Good):
    def scan(self, units):
        found = super().scan(units)
        logging.getLogger("acme.plugin").info("last seen ...%s", units[0].text[-8:])
        return found


class LogsUpper(Good):
    def scan(self, units):
        for u in units:
            for m in re.finditer(r"ghp_[A-Za-z0-9]+", u.text):
                logging.getLogger("acme.plugin").info("token %s", m.group().upper())
        return super().scan(units)


class IdText(Good):
    def finding_ids(self):
        return ["kitplug:aws", "kitplug:7example"]

    def emit(self, u, m):
        f = super().emit(u, m)
        return Finding("kitplug:7example", f.severity, f.locator, f.excerpt_hash,
                       f.tool_name, f.start, f.end)


class ReferenceText(Good):
    def finding_ids(self):
        return ["kitplug:aws", "kitplug:7exa_mple"]

    def emit(self, u, m):
        f = super().emit(u, m)
        return Finding("kitplug:7exa_mple", f.severity, f.locator, f.excerpt_hash,
                       f.tool_name, f.start, f.end)


class PhraseLower(Good):
    def phrases(self):
        return {"kitplug:aws": "a key like akiaiosfodnn7example"}


class FindsNothing(Good):
    def scan(self, units):
        return []


def make(cfg, severity, hasher):
    return Good(cfg, severity, hasher)
'''


@pytest.fixture
def kit_plugin(tmp_path, monkeypatch):
    (tmp_path / "kit_plugin_mod.py").write_text(KIT_PLUGIN)
    monkeypatch.syspath_prepend(str(tmp_path))
    monkeypatch.delitem(sys.modules, "kit_plugin_mod", raising=False)
    import kit_plugin_mod

    return kit_plugin_mod


def test_the_kit_passes_a_well_behaved_plugin(kit_plugin):
    import os

    from forgd_verdict.testing.plugin_conformance import assert_conformant, check_conformance

    env, root_level = os.environ, logging.getLogger().level
    assert check_conformance(kit_plugin.make) == []
    assert_conformant(kit_plugin.make)
    assert os.environ is env and logging.getLogger().level == root_level
    assert plugins_mod.loaded_distributions() == []


@pytest.mark.parametrize("cls,expected", [
    ("LogsText", "log output contains corpus value"),
    ("LogsTail", "log output contains corpus value 'O5p6Q7r8'"),
    ("RaisesText", "an exception raised by scan() contains corpus value"),
    ("LocatorText", "a finding's locator contains corpus value"),
    ("LocatorText", "PluginDetector refused a finding: check 'locator'"),
    ("PhraseText", "the plugin did not build: detectors.conformance: the phrase for "
                   "kitplug:aws matches a built-in detector"),
    ("ReadsEnviron", "scan() read os.environ (ACME_API_KEY)"),
    ("ReadsEnvironInFactory", "the factory read os.environ (ACME_API_KEY)"),
    ("PrintsText", "stdout contains corpus value"),
    ("WarnsText", "warnings contains corpus value"),
    ("FindsNothing", "no corpus unit produced a finding"),
    ("LogsUpper", "log output contains corpus value 'ghp_"),
    ("IdText", "a declared finding id contains corpus value '7EXAMPLE'"),
    ("IdText", "a finding's detector contains corpus value '7EXAMPLE'"),
    ("IdText", "the verdict's reference_id contains corpus value '7EXAMPLE'"),
    ("ReferenceText", "the verdict's reference_id contains corpus value '7EXAMPLE'"),
    ("PhraseLower", "the phrase for 'kitplug:aws' contains corpus value"),
    ("PhraseLower", "the verdict's deny_reason contains corpus value"),
])
def test_the_kit_fails_a_leaky_plugin(kit_plugin, cls, expected):
    import os

    from forgd_verdict.testing.plugin_conformance import assert_conformant, check_conformance

    factory = getattr(kit_plugin, cls)
    env = os.environ
    problems = check_conformance(factory)
    assert any(p.startswith(expected) for p in problems), problems
    assert os.environ is env
    with pytest.raises(AssertionError, match="not conformant"):
        assert_conformant(factory)


def test_a_reference_id_leak_is_caught_where_the_finding_id_is_clean(kit_plugin):
    """short_tag drops `_`, so `7exa_mple` becomes `7example` only in the
    reference_id."""
    from forgd_verdict.testing.plugin_conformance import check_conformance

    problems = check_conformance(kit_plugin.ReferenceText)
    assert problems == ["the verdict's reference_id contains corpus value '7EXAMPLE'"]


def test_the_vacuity_check_is_an_opt_out(kit_plugin):
    from forgd_verdict.testing.plugin_conformance import check_conformance

    assert check_conformance(kit_plugin.FindsNothing, expect_findings=False) == []


def test_the_kit_corpus_includes_everything_test_privacy_uses():
    import test_privacy

    from forgd_verdict.testing import plugin_conformance as kit

    assert set(test_privacy.SECRETS) | {test_privacy.PEM} <= set(kit.CORPUS_VALUES)
    locators = [u.locator for u in kit.CORPUS_UNITS]
    tools = [u.tool_name for u in kit.CORPUS_UNITS]
    assert any(test_privacy.AWS in loc for loc in locators)  # a secret as a JSON key
    assert test_privacy.AWS in tools  # a secret as a tool name
    text = "\n".join(u.text for u in kit.CORPUS_UNITS)
    assert all(v in text for v in kit.CORPUS_VALUES)


def test_the_kit_imports_without_pytest():
    import subprocess

    code = ("import sys; sys.modules['pytest'] = None; "
            "import forgd_verdict.testing.plugin_conformance as k; print(k.assert_conformant)")
    r = subprocess.run([sys.executable, "-c", code], capture_output=True, text=True,
                       timeout=60)
    assert r.returncode == 0, r.stderr
    assert "assert_conformant" in r.stdout


@pytest.mark.parametrize("target,rc", [("kit_plugin_mod:make", 0),
                                       ("kit_plugin_mod:LogsText", 1)])
def test_the_kit_runs_from_the_command_line(tmp_path, target, rc):
    import os
    import subprocess

    (tmp_path / "kit_plugin_mod.py").write_text(KIT_PLUGIN)
    env = {**os.environ, "PYTHONPATH": str(tmp_path)}
    r = subprocess.run([sys.executable, "-m", "forgd_verdict.testing.plugin_conformance",
                        target], capture_output=True, text=True, timeout=60, env=env)
    assert r.returncode == rc, r.stdout + r.stderr
    assert ("conformant" if rc == 0 else "problem(s)") in r.stdout
