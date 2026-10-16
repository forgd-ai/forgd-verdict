from __future__ import annotations

import base64
import contextlib
import hashlib
import hmac
import json
import os
import sys
import time
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey  # noqa: E402
from cryptography.hazmat.primitives.serialization import (  # noqa: E402
    Encoding,
    NoEncryption,
    PrivateFormat,
    PublicFormat,
)

from forgd_verdict import overrides_signing  # noqa: E402
from forgd_verdict.detectors.gitleaks import GitleaksDetector  # noqa: E402
from forgd_verdict.detectors.t0_regex import T0RegexDetector  # noqa: E402
from forgd_verdict.policy import DEFAULT_POLICY, Policy, _deep_merge  # noqa: E402

# A gitleaks subprocess built with the 2 s default gets 60 s under test. The
# metadata guards run one per request; on a 2-CPU runner with xdist workers
# several passed 2 s, the guard failed closed, and tests about something
# else failed. A test that sets its own timeout keeps it.
GITLEAKS_TEST_TIMEOUT_S = 60.0
_gitleaks_init = GitleaksDetector.__init__


def _gitleaks_init_under_test(self, *args, **kwargs):
    _gitleaks_init(self, *args, **kwargs)
    if self._timeout_s == 2.0:
        self._timeout_s = GITLEAKS_TEST_TIMEOUT_S


GitleaksDetector.__init__ = _gitleaks_init_under_test


def pytest_addoption(parser):
    parser.addoption("--shard", default=None, metavar="I/N",
                     help="run the I-th of N groups of the selected tests; see tests/shard.py")
    parser.addoption("--record-durations", default=None, metavar="PATH",
                     help="write each test's duration to PATH as JSON")


@pytest.hookimpl(trylast=True)
def pytest_collection_modifyitems(config, items):
    """`--shard`, applied after `-m` and `-k` have deselected."""
    value = config.getoption("--shard")
    if not value:
        return
    from shard import load_durations, parse_shard, plan, shard_of

    index, count = parse_shard(value)
    groups = plan(load_durations(), count)
    keep = [item for item in items if shard_of(item.nodeid, groups, count) == index]
    if len(keep) < len(items):
        kept = set(map(id, keep))
        config.hook.pytest_deselected(items=[i for i in items if id(i) not in kept])
        items[:] = keep


_DURATIONS: dict[str, float] = {}


def pytest_runtest_logreport(report):
    _DURATIONS[report.nodeid] = _DURATIONS.get(report.nodeid, 0.0) + report.duration


def pytest_sessionfinish(session):
    path = session.config.getoption("--record-durations")
    if path and not hasattr(session.config, "workerinput"):
        Path(path).write_text(json.dumps(
            {k: round(v, 2) for k, v in sorted(_DURATIONS.items())}, indent=0) + "\n",
            encoding="utf-8")


@pytest.fixture(autouse=True)
def _fresh_dashboard_policy_cache():
    """Tests patch `load_policy` or rewrite the policy between requests; a
    policy cached by an earlier test would hide both."""
    from forgd_verdict.dashboard.app import POLICY_CACHE

    POLICY_CACHE.clear()
    yield
    POLICY_CACHE.clear()


@pytest.fixture(autouse=True)
def _restore_logging():
    """Put the `forgd_verdict` logger back after each test.

    `configure_logging`, which every VerdictServer and Collector runs,
    replaces its handlers with one bound to the `sys.stdout` of that
    moment and turns propagation off. Under `capsys` that stream is closed
    when the test ends, so a later test's log line raised "I/O operation
    on closed file" and printed the record's exception chain to stderr.
    The root logger is pytest's: it attaches a capture handler per phase.
    """
    import logging

    lg = logging.getLogger("forgd_verdict")
    handlers, propagate, level = list(lg.handlers), lg.propagate, lg.level
    yield
    lg.handlers[:] = handlers
    lg.propagate = propagate
    lg.setLevel(level)


@pytest.fixture(autouse=True)
def _caplog_sees_forgd_verdict(request):
    """`configure_logging` turns propagation off on the `forgd_verdict` logger,
    so pytest's capture handler on the root never saw its records and every
    `caplog` assertion on a server path checked an empty log. A test that
    asks for `caplog` gets its handler on that logger directly."""
    if "caplog" not in request.fixturenames:
        yield
        return
    import logging

    caplog = request.getfixturevalue("caplog")
    lg = logging.getLogger("forgd_verdict")

    class _WhenNotPropagating(logging.Handler):
        # With propagation on, the root's capture handler already has the
        # record; a test that attached caplog's handler itself has it too.
        def emit(self, record):
            if (not lg.propagate and caplog.handler not in lg.handlers
                    and record.levelno >= caplog.handler.level):
                caplog.handler.handle(record)

    forward = _WhenNotPropagating()
    lg.addHandler(forward)
    yield
    lg.removeHandler(forward)


@pytest.fixture(autouse=True, scope="session")
def _timings_csv_in_tmp(tmp_path_factory):
    # A VerdictServer's relative server.csv_path (policy.yaml's ./timings.csv) goes to tmp.
    from forgd_verdict.applog import TimingCSV
    from forgd_verdict.server import app

    root = tmp_path_factory.mktemp("timings")

    class TmpTimingCSV(TimingCSV):
        def __init__(self, path):
            if path and not os.path.isabs(path):
                path = str(root / os.path.basename(path))
            super().__init__(path)

    with pytest.MonkeyPatch.context() as mp:
        mp.setattr(app, "TimingCSV", TmpTimingCSV)
        yield


@pytest.fixture(autouse=True, scope="session")
def _isolate_the_spool(tmp_path_factory):
    """Never write to the developer's real spool.

    `hook.spool` defaults to `~/.local/state/forgd-verdict/spool`, so any
    test that exercises the hook decision path would append a fixture
    record there. On a machine with shipping enabled, the next ship would
    send those fixture records to a real findings store and count them as
    usage on its dashboard. Tests must not be able to reach the machine's
    own state, let alone an org's.
    """
    from forgd_verdict.store.spool import default_spool_root

    root = tmp_path_factory.mktemp("spool")
    previous = os.environ.get("FORGD_VERDICT_SPOOL")

    # Snapshot the real spool so leakage is caught rather than assumed. The
    # env var alone is not enough: a subprocess test that passes an explicit
    # `env=` drops it, and the fixture leaks while looking correct.
    real = os.path.join(
        os.environ.get("XDG_STATE_HOME")
        or os.path.join(os.path.expanduser("~"), ".local", "state"),
        "forgd-verdict",
        "spool",
    )

    def snapshot() -> dict[str, tuple[int, float]]:
        state = os.path.dirname(real)
        if not os.path.isdir(state):
            return {}
        return {
            os.path.relpath(os.path.join(d, name), state):
                (os.path.getsize(os.path.join(d, name)),
                 os.path.getmtime(os.path.join(d, name)))
            for d, _dirs, names in os.walk(state) for name in names
        }

    before = snapshot()
    os.environ["FORGD_VERDICT_SPOOL"] = str(root)
    assert default_spool_root() == str(root)
    yield root
    after = snapshot()
    if previous is None:
        os.environ.pop("FORGD_VERDICT_SPOOL", None)
    else:
        os.environ["FORGD_VERDICT_SPOOL"] = previous
    assert after == before, (
        "the test run wrote to the real spool at "
        f"{real}: {before} -> {after}. Some code path is not honouring "
        "FORGD_VERDICT_SPOOL -- check for a subprocess with an explicit env."
    )


@pytest.fixture(autouse=True)
def trusted_home(tmp_path_factory, monkeypatch):
    """The home directory the hook trusts, fresh per test.

    hook/trust.py reads it from the password database, which no environment
    variable redirects, so `FORGD_VERDICT_SPOOL` above does not isolate the
    hook's default spool or device salt. A subprocess test passes `--spool`.
    """
    home = tmp_path_factory.mktemp("home")
    monkeypatch.setattr("forgd_verdict.hook.trust.home", lambda: home)
    return home


# Test fixtures. Structurally valid, never real credentials.
FAKE_AWS_KEY = "AKIAIOSFODNN7EXAMPLE"  # gitleaks:allow
FAKE_GITHUB_TOKEN = "ghp_" + "A1b2C3d4E5f6G7h8I9j0K1l2M3n4O5p6Q7r8"  # gitleaks:allow
FAKE_SSN = "123-45-6789"
FAKE_PAN = "4539578763621486"  # Luhn-valid; the all-1s test card is
                               # deliberately suppressed by the detector
# {gitleaks rule id: value}, one per default rule family. See the file's
# `_comment` for which T0 detectors match which.
GITLEAKS_FIXTURES = {
    rule: "".join(parts) for rule, parts in json.loads(
        (Path(__file__).parent / "data" / "gitleaks-t1.json").read_text()).items()
    if not rule.startswith("_")}
GITLEAKS_T1_ONLY = {rule: v for rule, v in GITLEAKS_FIXTURES.items() if rule != "github-pat"}
# Contains `abcdefghijklmnopqrstuvwxyz` once lowercased, which is a global
# stopword in gitleaks' default config, so gitleaks drops it.
GITLEAKS_STOPWORD_GHP = "ghp_" + "aBcDeFgHiJkLmNoPqRsTuVwXyZ0123456789"  # gitleaks:allow
FAKE_SECRET_B64 = base64.b64encode(b"forgd-verdict-test-secret-0123456789").decode()
WHSEC = "whsec_" + FAKE_SECRET_B64
WHSEC_PREVIOUS = "whsec_" + base64.b64encode(b"previous-secret-9876543210abcdef").decode()

# Past what `json.loads` will parse on any supported interpreter.
UNPARSEABLE_DEPTH = 100_000


def max_json_depth() -> int:
    """The deepest array nesting `json.loads` parses from this frame."""
    lo, hi = 1, UNPARSEABLE_DEPTH
    while lo < hi:
        mid = (lo + hi + 1) // 2
        try:
            json.loads("[" * mid + "]" * mid)
            lo = mid
        except RecursionError:
            hi = mid - 1
    return lo


def nested_json(inner: str, depth: int) -> str:
    """`inner` (JSON text) inside `depth` arrays, built without recursion."""
    return "[" * depth + inner + "]" * depth


# The detectors a test hands `apply_change`.
DETECTORS = (T0RegexDetector(),)


# The built-in defaults have no salt, and a service with a store refuses to
# start without one. Fixtures built on them opt out explicitly.
UNSALTED_OK = {"privacy": {"allow_unsalted": True}}

# What a managed hook runs before its interpreter: `/usr/bin/env -i` on POSIX.
MANAGED_LAUNCHERS = (["/usr/bin/env", "-i"],)


def managed_interpreter_argv(hook: dict) -> list[str]:
    """A managed hook's argv from the interpreter on, without its launcher."""
    argv = [hook["command"], *hook.get("args", [])]
    for launcher in MANAGED_LAUNCHERS:
        if argv[:len(launcher)] == launcher:
            return argv[len(launcher):]
    return argv


def make_policy(**overrides) -> Policy:
    raw = _deep_merge(_deep_merge(DEFAULT_POLICY, UNSALTED_OK), overrides)
    return Policy(raw=raw)


# One Ed25519 key pair per test run for runtime-override records. Never a
# committed value.
OVERRIDES_KEY = Ed25519PrivateKey.generate()
OVERRIDES_PUBLIC = OVERRIDES_KEY.public_key()
OVERRIDES_KEY_TEXT = overrides_signing.encode(
    OVERRIDES_KEY.private_bytes(Encoding.Raw, PrivateFormat.Raw, NoEncryption()))
OVERRIDES_PUBLIC_TEXT = overrides_signing.encode(
    OVERRIDES_PUBLIC.public_bytes(Encoding.Raw, PublicFormat.Raw))


@pytest.fixture
def control_identity(monkeypatch):
    """The deployment has enabled the control identity, so a service honours
    runtime overrides when `dashboard.admins` lists groups. A local store
    counts as proving the writer lockout (`lockout.allow_unprovable_stores_for_tests`).
    FORGD_OVERRIDES_VERIFY_KEY holds this run's OVERRIDES_KEY public key; the
    signing key is `signing_env`'s, since only the dashboard and the CLI may
    hold it."""
    from forgd_verdict import lockout
    from forgd_verdict.overrides import ENV_ENABLED

    monkeypatch.setenv(ENV_ENABLED, "true")
    monkeypatch.setattr(lockout, "_unprovable_allowed", True)
    monkeypatch.setenv(overrides_signing.ENV_VERIFY_KEY, OVERRIDES_PUBLIC_TEXT)


@contextlib.contextmanager
def without_signing_key():
    """FORGD_OVERRIDES_SIGNING_KEY unset while a service other than the
    dashboard is built, as each runs in its own process with its own
    environment."""
    saved = os.environ.pop(overrides_signing.ENV_SIGNING_KEY, None)
    try:
        yield
    finally:
        if saved is not None:
            os.environ[overrides_signing.ENV_SIGNING_KEY] = saved


@pytest.fixture
def signing_env(monkeypatch):
    """FORGD_OVERRIDES_SIGNING_KEY holds this run's OVERRIDES_KEY, as on the
    dashboard and a CLI run as the control identity."""
    monkeypatch.setenv(overrides_signing.ENV_SIGNING_KEY, OVERRIDES_KEY_TEXT)


@pytest.fixture
def policy(tmp_path) -> Policy:
    """Enforce mode, T0 only, no external sinks. gitleaks stays `auto` off."""
    return make_policy(
        detectors={"gitleaks": {"enabled": False, "severity": "block"}},
        server={
            "mode": "enforce",
            "secrets": [WHSEC],
            "csv_path": str(tmp_path / "timings.csv"),
            "archive_dir": str(tmp_path / "archive"),
        },
    )


def sign(body: bytes, secret: str = WHSEC, webhook_id: str = "req_test", ts: int | None = None):
    """Build the three signature headers for a body."""
    timestamp = str(int(time.time()) if ts is None else ts)
    key = base64.b64decode(secret.removeprefix("whsec_"))
    payload = f"{webhook_id}.{timestamp}.".encode() + body
    sig = base64.b64encode(hmac.new(key, payload, hashlib.sha256).digest()).decode()
    return {
        "webhook-id": webhook_id,
        "webhook-timestamp": timestamp,
        "webhook-signature": f"v1,{sig}",
        "content-type": "application/json",
        "user-agent": "anthropic-dlp/1",
        "accept-encoding": "identity",
    }


def frame(messages=None, **overrides) -> dict:
    """A minimal valid prompt frame."""
    body = {
        "type": "prompt",
        "request_id": "req_test",
        "tenant_id": "11111111-1111-1111-1111-111111111111",
        "actor": {"type": "user", "id": "user_01Abc", "email_address": "a@example.com"},
        "source": {"application": "claude-ai"},
        "session_id": "22222222-2222-2222-2222-222222222222",
        "model": "claude-opus-5",
        "messages": messages if messages is not None else [
            {"role": "user", "content": [{"type": "text", "text": "hello"}]}
        ],
        "metadata": {},
    }
    body.update(overrides)
    return body


def text_msg(text: str, role: str = "user") -> dict:
    return {"role": role, "content": [{"type": "text", "text": text}]}


class FakeConnect:
    """The `connect` seam of the built-in sinks. Records each request and
    answers it with `status` and `body`, or raises `error`."""

    def __init__(self, status: int = 200, *, body: bytes = b"", error: BaseException | None = None):
        self.status = status
        self.body = body
        self.error = error
        self.opened = 0
        self.requests: list[dict] = []

    def __call__(self, scheme, host, port, timeout):
        self.opened += 1
        return _FakeConnection(self, f"{scheme}://{host}" + (f":{port}" if port else ""), timeout)


class _FakeConnection:
    def __init__(self, fake: FakeConnect, origin: str, timeout):
        self._fake, self._origin, self._timeout = fake, origin, timeout

    def request(self, method, target, body=None, headers=None):
        if self._fake.error is not None:
            raise self._fake.error
        self._fake.requests.append({
            "method": method, "url": self._origin + target, "body": body,
            "headers": {k.lower(): v for k, v in (headers or {}).items()},
            "timeout": self._timeout})

    def getresponse(self):
        return _FakeResponse(self._fake.status, self._fake.body)

    def close(self):
        return None


class _FakeResponse:
    will_close = False

    def __init__(self, status: int, body: bytes):
        self.status, self._body = status, body

    def read(self):
        return self._body


class ASGIClient:
    """Minimal ASGI driver -- no httpx, no server, no network."""

    def __init__(self, app):
        self.app = app

    async def post(self, path: str, body: bytes, headers: dict | None = None):
        return await self._call("POST", path, body, headers or {})

    async def get(self, path: str, headers: dict | None = None):
        return await self._call("GET", path, b"", headers or {})

    async def request(self, method: str, path: str, body: bytes = b"",
                      headers: dict | None = None):
        """(status, body, response_headers).

        Any method, and the RESPONSE HEADERS -- which post()/get() drop.
        A CORS preflight is an OPTIONS whose entire meaning is in its
        headers, so a client that returns only a status and a body cannot
        test one at all.
        """
        return await self._call(method, path, body, headers or {}, with_headers=True)

    async def _call(self, method: str, path: str, body: bytes, headers: dict,
                    with_headers: bool = False):
        # Split the query string. Without this a test calling
        # "/events?org=X" put the whole thing in `path`, the app read no
        # query parameters at all, and a route-level filter test passed by
        # never exercising the filter.
        path, _, query = path.partition("?")
        scope = {
            "type": "http",
            "method": method,
            "path": path,
            "query_string": query.encode("latin-1"),
            "headers": [
                (k.lower().encode("latin-1"), str(v).encode("latin-1"))
                for k, v in headers.items()
            ],
        }
        sent: list[dict] = []
        received = {"done": False}

        async def receive():
            if received["done"]:
                return {"type": "http.disconnect"}
            received["done"] = True
            return {"type": "http.request", "body": body, "more_body": False}

        async def send(message):
            sent.append(message)

        await self.app(scope, receive, send)
        status = next((m["status"] for m in sent if m["type"] == "http.response.start"), None)
        payload = b"".join(
            m.get("body", b"") for m in sent if m["type"] == "http.response.body"
        )
        ctype = next(
            (v.decode("latin-1") for m in sent
             if m["type"] == "http.response.start"
             for k, v in m.get("headers", []) if k.lower() == b"content-type"),
            "",
        )
        try:
            parsed = json.loads(payload) if payload else None
        except ValueError:
            # Text comes back as str so a test can say `in body`; images and
            # anything else stay bytes.
            parsed = (
                payload.decode("utf-8", "replace")
                if ctype.startswith("text/") else payload
            )
        if with_headers:
            resp_headers = {
                k.decode("latin-1").lower(): v.decode("latin-1")
                for m in sent if m["type"] == "http.response.start"
                for k, v in m.get("headers", [])
            }
            return status, parsed, resp_headers
        return status, parsed


# --- the findings connector ----------------------------------------------------
# Shared by test_connector_server.py and test_connector_tools.py. Imports are
# inside the fixtures so a run without the connector extra still collects.

CONNECTOR_JWKS_URL = "https://login.example.com/tenant/discovery/v2.0/keys"


@pytest.fixture(scope="session")
def signing_key():
    """An RSA key the connector's tests sign tokens with."""
    from cryptography.hazmat.primitives.asymmetric import rsa

    return rsa.generate_private_key(public_exponent=65537, key_size=2048)


@pytest.fixture
def jwks(signing_key, monkeypatch):
    """The JWKS the verifier sees, served without a fetch."""
    import jwt

    public = jwt.algorithms.RSAAlgorithm.to_jwk(signing_key.public_key(), as_dict=True)
    doc = {"keys": [dict(public, kid="k1", use="sig", alg="RS256")]}

    def fetch_data(self):
        assert self.uri == CONNECTOR_JWKS_URL, self.uri
        return doc

    monkeypatch.setattr(jwt.PyJWKClient, "fetch_data", fetch_data)
    return doc
