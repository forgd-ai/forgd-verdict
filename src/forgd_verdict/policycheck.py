"""`forgd-verdict policy --check`: would each role start on this policy?

Each role is built the way its entry point builds it, with the policy as
loaded here and this process's environment, and is then closed without
serving. Three things are swapped so the check runs anywhere, CI included:

- the findings store is a local store in a temporary directory. The spec
  the policy names is checked with `check_store_spec`, which refuses what
  `open_store` refuses without opening it;
- detectors are built with `probe=False`: no gitleaks binary or daemon,
  no model, and no comparison with the config a daemon loaded. Every tier
  above T0 answers to its name and finding ids but scans to nothing, so
  the collector's sink metadata is vetted by the T0 tiers alone;
- the verdict server's timing CSV and frame archive are off.

What it cannot see is what only the running environment decides: whether
a required detector is reachable, whether the store accepts the role's
identity, and whatever a `$VAR` unset here is set to there. A reference
unset here is checked as unset, which is how the role treats it.
"""

from __future__ import annotations

import contextlib
import logging
import os
import tempfile
from collections.abc import Callable, Iterator, Sequence
from dataclasses import dataclass
from pathlib import Path

from .policy import Policy, PolicyInvalid, load_policy, policy_error, policy_path

# The top-level sections some role reads; docs/POLICY.md § Sections lists
# the same names. The roles ignore any other key, so a misspelt section is
# silently absent from every one of them.
KNOWN_SECTIONS = frozenset({
    "detectors", "scan", "privacy", "deny", "server", "hook", "compliance",
    "dashboard", "orgs", "intake", "otel", "sinks", "plugins", "connector",
    "overrides", "managed_agents",
})

ROLES = ("server", "collector", "intake", "dashboard", "connector", "compliance")
ALWAYS = ("server", "collector", "intake", "dashboard")


@dataclass(frozen=True)
class Refusal:
    role: str
    message: str


def _quiet() -> logging.Logger:
    log = logging.getLogger("forgd_verdict.policycheck.role")
    log.propagate = False
    if not log.handlers:
        log.addHandler(logging.NullHandler())
    return log


class _NotRun:
    """A detector the check builds but does not run."""

    def __init__(self, detector) -> None:
        self._detector = detector

    def __getattr__(self, name: str):
        return getattr(self._detector, name)

    def available(self) -> bool:
        return True

    def scan(self, units) -> list:
        return []


def _detectors(policy: Policy, profile: str, plugin_profile: str | None = None) -> list:
    from .detectors.base import TIER_T0

    built = policy.for_profile(profile).build_detectors(
        profile=plugin_profile or profile, probe=False)
    return [d if getattr(d, "tier", TIER_T0) == TIER_T0 else _NotRun(d) for d in built]


def _local_store(root: Path, role: str):
    from .store.local import LocalFileStore

    return LocalFileStore(str(root / role))


def _check_spec(policy: Policy, spec) -> None:
    from .store import check_store_spec

    if spec:
        check_store_spec(str(spec), plugins=policy.plugin_allow)


def _server(policy: Policy, root: Path) -> None:
    from .applog import TimingCSV
    from .server.app import VerdictServer
    from .server.archive import FrameArchive

    # Read by `serve` before the app is built (server/__main__.py).
    _ = policy.limit_concurrency
    int(policy.server.get("port", 8000))
    _check_spec(policy, policy.server.get("store"))
    detectors = _detectors(policy, "server")
    VerdictServer(policy, logger=_quiet(), detectors=detectors,
                  store=_local_store(root, "server"), csv=TimingCSV(None),
                  archive=FrameArchive(None)).close()


def _collector(policy: Policy, root: Path) -> None:
    from .otel.app import Collector
    from .policy import _deep_merge
    from .sink.factory import sinks_may_need_late

    otel = policy.for_profile("otel")
    # Read by `collect` before the app is built (otel/__main__.py).
    int(otel.otel.get("port", 8100))
    _check_spec(policy, otel.otel.get("store") or otel.server.get("store"))
    detectors = _detectors(policy, "otel", "collector")
    late = []
    extra = (otel.raw.get("otel") or {}).get("sink_detectors") or {}
    if extra and sinks_may_need_late(otel.sinks):
        from .detectors.base import TIER_T2

        merged = otel.derive(_deep_merge(otel.raw, {"detectors": extra}))
        late = [_NotRun(d) for d in merged.build_detectors(profile="collector", probe=False)
                if getattr(d, "tier", 0) >= TIER_T2]
    Collector(policy, logger=_quiet(), detectors=detectors,
              store=_local_store(root, "collector"), late_detectors=late).close()


def _intake(policy: Policy, root: Path) -> None:
    """Intake builds its detectors on the first scan, not at start; they are
    built here too, so a profile that would fail every scan is refused."""
    from .intake.app import Intake

    config = policy.raw.get("intake") or {}
    # Read by `intake` before the app is built (intake/__main__.py).
    int(config.get("port", 8200))
    _check_spec(policy, config.get("store") or (policy.raw.get("server") or {}).get("store"))
    for profile in ("server", "hook"):
        _detectors(policy, profile)
    Intake(policy, store=_local_store(root, "intake")).close()


def _dashboard(policy: Policy, root: Path, path: Path, serve_open: bool) -> None:
    from .dashboard.app import create_app
    from .entitlements import MODE_NONE

    # The dashboard loads the policy itself, from $FORGD_VERDICT_POLICY.
    with _env("FORGD_VERDICT_POLICY", str(path)):
        app = create_app(str(root / "dashboard"))
    # dashboard/__main__.py refuses this bind; the image binds 0.0.0.0.
    if app.auth.mode == MODE_NONE and not serve_open:
        raise ValueError(
            "dashboard.auth.mode is 'none', so `forgd-verdict dashboard` refuses to "
            "bind a public interface without --serve-open; set dashboard.auth, or pass "
            "--serve-open to the check if the network in front of the dashboard is "
            "the control")


def _connector(policy: Policy, root: Path) -> None:
    """The connector's store comes from --store or $FORGD_VERDICT_STORE, not
    the policy; it is given a local one here, like the other roles."""
    from .connector import config

    cfg = config.load(policy)
    if cfg is None:
        raise ValueError("connector.enabled is not true, so the connector does not start")
    try:
        import mcp  # noqa: F401
    except ImportError as exc:
        raise RuntimeError(
            "the connector needs its extra: pip install 'forgd-verdict[connector]'") from exc
    from .connector.app import create_app
    from .connector.tools import reader_from_policy

    create_app(cfg, reader_from_policy(policy, cfg, _local_store(root, "connector")))


def _compliance(policy: Policy, root: Path) -> None:
    policy.refuse_unsalted("compliance scanner")
    policy.compliance_orgs()
    _detectors(policy, "compliance")


@contextlib.contextmanager
def _env(name: str, value: str) -> Iterator[None]:
    before = os.environ.get(name)
    os.environ[name] = value
    try:
        yield
    finally:
        if before is None:
            os.environ.pop(name, None)
        else:
            os.environ[name] = before


def configured_roles(policy: Policy) -> tuple[str, ...]:
    """The roles checked when none is named: the four every deployment of
    the chart runs, the connector when enabled, and the scanner when the
    policy names an org for it. The defaults carry an access key reference,
    so the key alone says nothing."""
    roles = list(ALWAYS)
    if (policy.raw.get("connector") or {}).get("enabled") is True:
        roles.append("connector")
    compliance = policy.raw.get("compliance") or {}
    if compliance.get("orgs") or compliance.get("org_id"):
        roles.append("compliance")
    return tuple(roles)


def check(path: str | None, roles: Sequence[str] = (), *,
          serve_open: bool = False) -> tuple[Path, tuple[str, ...], list[Refusal]]:
    """(the file checked, the roles checked, every refusal). A refusal with
    role "policy" is the file itself: missing, unparseable, or carrying a
    top-level key no role reads. `serve_open` is the dashboard's
    --serve-open."""
    file = policy_path(path)
    if not file.is_file():
        return file, (), [Refusal("policy", f"{file} does not exist; pass --policy")]
    try:
        policy = load_policy(str(file))
    except PolicyInvalid as exc:
        return file, (), [Refusal("policy", _describe(exc))]
    except Exception as exc:  # noqa: BLE001 - YAML, JSON and OS errors alike
        # A parser error quotes the line it failed on; see policy_error.
        return file, (), [Refusal("policy", policy_error(exc))]

    refusals = [Refusal("policy", f"{key!r} is not a section any role reads")
                for key in sorted(set(policy.raw) - KNOWN_SECTIONS)]
    chosen = tuple(roles) or configured_roles(policy)
    steps: dict[str, Callable[[Policy, Path], None]] = {
        "server": _server, "collector": _collector, "intake": _intake,
        "dashboard": lambda p, r: _dashboard(p, r, file.resolve(), serve_open),
        "connector": _connector, "compliance": _compliance,
    }
    with tempfile.TemporaryDirectory(prefix="forgd-policy-check-") as tmp:
        for role in chosen:
            try:
                steps[role](load_policy(str(file)), Path(tmp))
            except Exception as exc:  # noqa: BLE001 - whatever stops the role
                refusals.append(Refusal(role, _describe(exc)))
    return file, chosen, refusals


def _describe(exc: BaseException) -> str:
    # The role prints the same text when it refuses to start.
    text = str(exc).strip()
    return f"{type(exc).__name__}: {text}" if text else type(exc).__name__
