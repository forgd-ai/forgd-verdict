"""The connector's six tools, called through the full HTTP stack.

Every call goes through the token check, the SDK and the tool, the way
Claude's would. Seeded stores hold two orgs; tokens are signed locally.
"""

from __future__ import annotations

import json
import logging
from datetime import UTC, datetime, timedelta

import pytest

pytest.importorskip("mcp", reason="needs forgd-verdict[connector]")

import yaml  # noqa: E402
from test_connector_server import (  # noqa: E402
    API_CLIENT,
    ISSUER,
    JWKS_URL,
    RESOURCE,
    SCOPE_FULL,
    _bearer,
    _call,
    _token,
)

from forgd_verdict.connector import config  # noqa: E402
from forgd_verdict.connector import tools as T  # noqa: E402
from forgd_verdict.connector.app import create_app  # noqa: E402
from forgd_verdict.models import digest, pseudonym  # noqa: E402
from forgd_verdict.policy import load_policy  # noqa: E402
from forgd_verdict.store import FindingRow, LocalFileStore, VerdictRecord  # noqa: E402
from forgd_verdict.store.base import (  # noqa: E402
    SOURCE_CODE_HOOK,
    SOURCE_COMPLIANCE_SCAN,
    SOURCE_INFERENCE_HOOK,
    SOURCE_OTEL_COLLECT,
    DenialRecord,
)
from forgd_verdict.store.views import read_summary, summary_payload, window_to_since  # noqa: E402

SALT = "salt-bait-5c1e9d0a7b"
ORG_A_ID = "org-alpha-raw-id-bait"
ORG_B_ID = "org-bravo-raw-id-bait"
A = pseudonym(ORG_A_ID, SALT, "org")
B = pseudonym(ORG_B_ID, SALT, "org")
LABEL_A, LABEL_B = "Alpha", "Bravo"

# Matched values. The store holds only their salted digests.
BAIT_VALUES = ["AKIAQYLPMN5HGZTHX4UQ", "078-05-1120", "ghp_bait0123456789abcdefghijklmnopqrstu",
               "4111111111111111", "bait-password-hunter2-zz9"]
BAIT_ACTOR = "bait.person@example.org"
# Stored in fields no tool returns.
BAIT_NEAR_MISS = ["model-name-bait-7f2", "reported-as-bait-3d1", "build-bait-0ae"]
BAIT_ALL = (BAIT_VALUES + [BAIT_ACTOR, ORG_A_ID, ORG_B_ID, SALT] + BAIT_NEAR_MISS
            + [digest(v, SALT) for v in BAIT_VALUES])


def _ago(**kw) -> str:
    return (datetime.now(UTC) - timedelta(**kw)).strftime("%Y-%m-%dT%H:%M:%SZ")


def _f(detector, value, locator="msg[0]", severity="block", tool=None):
    return FindingRow(detector, severity, locator, digest(value, SALT), tool)


def _seed_small(root) -> LocalFileStore:
    store = LocalFileStore(root, instance="t")
    actor = pseudonym(BAIT_ACTOR, SALT, "usr")
    store.write_verdicts([
        VerdictRecord(source=SOURCE_INFERENCE_HOOK, observed_at=_ago(hours=2),
                      request_id="req-a1", surface="claude-ai", tenant_hash=A,
                      actor_hash=actor, action="allow", shadow_action="deny",
                      reference_id="fv_awsaccesske_A1", total_ms=400.0, findings_count=2,
                      model=BAIT_NEAR_MISS[0], build=BAIT_NEAR_MISS[2],
                      findings=[_f("regex:aws-access-key", BAIT_VALUES[0], "msg[2].content[0]"),
                                _f("regex:github-pat", BAIT_VALUES[2], "msg[3]")]),
        VerdictRecord(source=SOURCE_COMPLIANCE_SCAN, observed_at=_ago(days=3),
                      session_id="clls_A1", surface="claude_code", tenant_hash=A,
                      actor_hash=actor, findings_count=2,
                      findings=[_f("regex:ssn", BAIT_VALUES[1], "msg[1]"),
                                _f("regex:aws-access-key", BAIT_VALUES[0], "msg[9]")]),
        VerdictRecord(source=SOURCE_CODE_HOOK, observed_at=_ago(hours=5),
                      request_id="PreToolUse:tool-a", surface="claude-code", tenant_hash=A,
                      action="deny", findings_count=1,
                      findings=[_f("regex:password", BAIT_VALUES[4], "tool_input.command",
                                   tool="Bash")]),
        VerdictRecord(source=SOURCE_OTEL_COLLECT, observed_at=_ago(days=20),
                      surface="cowork", tenant_hash=A, reported_as=BAIT_NEAR_MISS[1],
                      findings_count=1,
                      findings=[_f("entropy:assignment", BAIT_VALUES[4], "attr.x", "warn")]),
        VerdictRecord(source=SOURCE_INFERENCE_HOOK, observed_at=_ago(hours=3),
                      request_id="req-b1", surface="cowork", tenant_hash=B,
                      action="deny", reference_id="fv_card_B1", findings_count=1,
                      findings=[_f("checksum:card", BAIT_VALUES[3], "msg[0]")]),
        VerdictRecord(source=SOURCE_COMPLIANCE_SCAN, observed_at=_ago(days=2),
                      session_id="clls_B1", surface="claude-ai", tenant_hash=B,
                      findings_count=1, findings=[_f("regex:ssn", BAIT_VALUES[1])]),
    ])
    store.write_denials([
        DenialRecord(activity_id="act-a1", created_at=_ago(hours=2),
                     reference_id="fv_awsaccesske_A1", tenant_hash=A, actor_hash=actor),
        DenialRecord(activity_id="act-b1", created_at=_ago(hours=3),
                     reference_id="fv_card_B1", tenant_hash=B),
        DenialRecord(activity_id="act-b2", created_at=_ago(hours=4), tenant_hash=B),
    ])
    return store


class LeakyStore:
    """Ignores `orgs` and returns every row, like a backend that prunes wrongly."""

    def __init__(self, store):
        self.store = store

    def read_verdicts(self, since=None, orgs=None):
        return self.store.read_verdicts(since, None)

    def read_verdict_days(self, since=None, orgs=None, until=None):
        return self.store.read_verdict_days(since, None, until)

    def read_denials(self, since=None, orgs=None):
        return self.store.read_denials(since, None)

    def describe(self):
        return self.store.describe()

    def get_excluded(self):
        return self.store.get_excluded()


def _policy(tmp_path):
    path = tmp_path / "policy.yaml"
    path.write_text(yaml.safe_dump({
        "privacy": {"hash_salt": SALT},
        "orgs": [{"id": ORG_A_ID, "label": LABEL_A}, {"id": ORG_B_ID, "label": LABEL_B}],
        "dashboard": {"entitlements": {"map": [
            {"group": "g-a", "orgs": [ORG_A_ID]},
            {"group": "g-all", "orgs": [ORG_A_ID, ORG_B_ID]}]}},
        "connector": {"enabled": True, "resource": RESOURCE, "scopes": [SCOPE_FULL],
                      "required_scope": "findings.read",
                      "auth": {"mode": "oidc_jwt", "issuer": ISSUER, "jwks_url": JWKS_URL,
                               "audience": [RESOURCE, API_CLIENT]}},
    }))
    return load_policy(path)


class _Fresh:
    """A new app per request. The SDK's session manager runs once per app."""

    def __init__(self, make):
        self.make = make
        self.current = None

    def running(self):
        self.current = self.make()
        return self.current.running()

    async def __call__(self, scope, receive, send):
        await self.current(scope, receive, send)


def _app(tmp_path, store, entitled=True):
    policy = _policy(tmp_path)
    cfg = config.load(policy)

    def make():
        reader = T.reader_from_policy(policy, cfg, store)
        if not entitled:
            reader.entitlements = T.Entitlements()
        return create_app(cfg, reader)

    return _Fresh(make)


async def _tool(app, key, name, arguments=None, groups=("g-all",), **token):
    body = {"jsonrpc": "2.0", "id": 7, "method": "tools/call",
            "params": {"name": name, "arguments": arguments or {}}}
    status, _h, raw = await _call(app, "POST", "/mcp", body, {
        **_bearer(_token(key, groups=None if groups is None else list(groups), **token)),
        "mcp-protocol-version": "2025-11-25"})
    assert status == 200, raw
    result = json.loads(raw)["result"]
    return result, raw


def _data(result):
    assert not result.get("isError"), result
    return result["structuredContent"]


def _error(result) -> str:
    """The tool's own message, without the SDK's `Error executing tool x: `."""
    assert result.get("isError"), result
    text = result["content"][0]["text"]
    return text.split(": ", 1)[1] if text.startswith("Error executing tool ") else text


def _calls(ref="fv_awsaccesske_A1", session="clls_A1", org=A):
    """Every tool with every argument shape that returns data."""
    out = []
    for window in ("24h", "7d", "30d"):
        for o in (None, org):
            args = {"window": window, **({"org": o} if o else {})}
            out += [("summary", args), ("coverage", args), ("reconciliation", args),
                    ("findings", args), ("findings", dict(args, action="deny")),
                    ("reconciliation", dict(args, limit=1)), ("findings", dict(args, limit=1))]
    for extra in ({"surface": "claude-ai"}, {"surface": "claude-code"},
                  {"detector": "regex:aws-access-key"}, {"detector": "regex:ssn"},
                  {"source": SOURCE_INFERENCE_HOOK}, {"source": SOURCE_COMPLIANCE_SCAN},
                  {"source": SOURCE_CODE_HOOK}, {"source": SOURCE_OTEL_COLLECT},
                  {"since": _ago(days=10)}, {"limit": 200}):
        out.append(("findings", {"window": "30d", **extra}))
    out += [("record", {"reference_id": ref}), ("record", {"session_id": session}),
            ("record", {"reference_id": "fv_nothing_here"}),
            ("topology", {}), ("topology", {"org": org})]
    return out


# --- privacy -----------------------------------------------------------------

def _leaks(text: str) -> list[str]:
    return [b for b in BAIT_ALL if b in text]


async def test_no_matched_value_reaches_a_response_or_the_log(
        tmp_path, jwks, signing_key, caplog):
    app = _app(tmp_path, _seed_small(tmp_path / "store"))
    caplog.set_level(logging.DEBUG)
    seen_rows = 0
    for name, args in _calls():
        result, raw = await _tool(app, signing_key, name, args)
        _data(result)
        text = raw.decode()
        assert not _leaks(text), (name, args, _leaks(text))
        seen_rows += text.count('"digest"')
    # The digests are there, shortened; the bait is not.
    assert seen_rows > 0
    logged = "\n".join(f"{r.getMessage()} {r.__dict__!r}" for r in caplog.records)
    assert logged and not _leaks(logged), _leaks(logged)


async def test_the_bait_check_sees_a_leak(tmp_path, jwks, signing_key):
    """The check above is only worth something if a leak would trip it."""
    assert _leaks(json.dumps({"x": f"value {BAIT_VALUES[0]} here"})) == [BAIT_VALUES[0]]
    assert _leaks(digest(BAIT_VALUES[1], SALT))
    assert not _leaks(digest(BAIT_VALUES[1], SALT)[:T.DIGEST_CHARS])


# --- entitlements ------------------------------------------------------------

def _strip(data):
    """Drop fields that differ between two calls a moment apart."""
    if isinstance(data, dict):
        return {k: _strip(v) for k, v in data.items()
                if k not in ("generated_at", "overdue")}
    if isinstance(data, list):
        return [_strip(v) for v in data]
    return data


async def test_a_viewer_of_org_a_sees_nothing_of_org_b(tmp_path, jwks, signing_key):
    app = _app(tmp_path, LeakyStore(_seed_small(tmp_path / "store")))
    b_marks = [B, LABEL_B, "fv_card_B1", "clls_B1", "req-b1", "act-b1", "act-b2"]
    for name, args in _calls():
        mine, raw = await _tool(app, signing_key, name, args, groups=("g-a",))
        text = raw.decode()
        assert not [m for m in b_marks if m in text], (name, args)
        # Everything an org-A viewer sees equals what an all-orgs viewer sees
        # of org A alone: no org-B row, count or label is folded in.
        pinned = dict(args, org=A) if name != "record" else args
        theirs, _ = await _tool(app, signing_key, name, pinned, groups=("g-all",))
        assert _strip(_data(mine)) == _strip(_data(theirs)), (name, args)


async def test_org_b_records_are_not_found_by_an_org_a_viewer(tmp_path, jwks, signing_key):
    app = _app(tmp_path, LeakyStore(_seed_small(tmp_path / "store")))
    for args in ({"reference_id": "fv_card_B1"}, {"session_id": "clls_B1"}):
        result, _ = await _tool(app, signing_key, "record", args, groups=("g-a",))
        assert _data(result) == {"found": False, "searched_window": "30d"}
        result, _ = await _tool(app, signing_key, "record", args, groups=("g-all",))
        assert _data(result)["found"] is True


@pytest.mark.parametrize("name,args", [
    ("summary", {}), ("coverage", {}), ("findings", {}), ("reconciliation", {}),
    ("topology", {}),
])
async def test_asking_for_org_b_is_forbidden(tmp_path, jwks, signing_key, name, args):
    app = _app(tmp_path, LeakyStore(_seed_small(tmp_path / "store")))
    result, raw = await _tool(app, signing_key, name, dict(args, org=B), groups=("g-a",))
    assert _error(result).startswith("forbidden")
    assert B not in _error(result) and LABEL_B.encode() not in raw


async def test_a_viewer_in_no_group_sees_no_org(tmp_path, jwks, signing_key):
    app = _app(tmp_path, LeakyStore(_seed_small(tmp_path / "store")))
    result, _ = await _tool(app, signing_key, "summary", {"window": "30d"}, groups=("g-x",))
    assert _data(result)["total_requests"] == 0
    result, _ = await _tool(app, signing_key, "summary", {"org": A}, groups=("g-x",))
    assert _error(result).startswith("forbidden")


async def test_groups_left_out_of_the_token_is_a_tool_error(tmp_path, jwks, signing_key):
    app = _app(tmp_path, _seed_small(tmp_path / "store"))
    result, _ = await _tool(app, signing_key, "summary", {}, groups=None,
                            _claim_names={"groups": "src1"})
    assert _error(result).startswith("groups_unavailable")


async def test_without_entitlements_every_org_is_read(tmp_path, jwks, signing_key):
    app = _app(tmp_path, _seed_small(tmp_path / "store"), entitled=False)
    data = _data((await _tool(app, signing_key, "summary", {"window": "30d"},
                              groups=()))[0])
    assert {o["org"] for o in data["orgs"]} == {A, B}
    assert {o["label"] for o in data["orgs"]} == {LABEL_A, LABEL_B}


# --- consistency ---------------------------------------------------------------

@pytest.mark.parametrize("window", ["24h", "7d", "30d"])
@pytest.mark.parametrize("org", [None, "A", "B"])
async def test_summary_is_the_dashboards_payload(tmp_path, jwks, signing_key, window, org):
    store = _seed_small(tmp_path / "store")
    app = _app(tmp_path, store)
    orgs = {None: None, "A": frozenset({A}), "B": frozenset({B})}[org]
    args = {"window": window, **({"org": next(iter(orgs))} if orgs else {})}
    data = _data((await _tool(app, signing_key, "summary", args))[0])
    since = window_to_since(window)
    expected = summary_payload(read_summary(store, since, orgs), window)
    tool_only = {"truncated", "limit", "orgs", "surfaces_truncated", "orgs_truncated"}
    assert _strip({k: v for k, v in data.items() if k not in tool_only}) == _strip(expected)


# --- caps ----------------------------------------------------------------------

@pytest.fixture(scope="module")
def big_store(tmp_path_factory):
    root = tmp_path_factory.mktemp("big") / "store"
    store = LocalFileStore(root, instance="t")
    rows = [VerdictRecord(source=SOURCE_INFERENCE_HOOK, observed_at=_ago(minutes=5 + i),
                          request_id=f"req-{i}", surface=f"agent:bot{i % 110}",
                          tenant_hash=A, action="allow", findings_count=1,
                          findings=[_f(f"regex:rule-{i % 60}", f"v{i}")])
            for i in range(230)]
    rows.append(VerdictRecord(
        source=SOURCE_INFERENCE_HOOK, observed_at=_ago(minutes=1), request_id="req-wide",
        reference_id="fv_wide_1", surface="claude-ai", tenant_hash=A, findings_count=130,
        findings=[_f("regex:wide", f"w{j}", f"msg[{j}]") for j in range(130)]))
    store.write_verdicts(rows)
    store.write_denials([DenialRecord(activity_id=f"act-{i}", created_at=_ago(minutes=i + 1),
                                      reference_id=f"req-{i}", tenant_hash=A)
                         for i in range(215)])
    return store


async def test_findings_cap(tmp_path, jwks, signing_key, big_store):
    app = _app(tmp_path, big_store)
    data = _data((await _tool(app, signing_key, "findings",
                              {"limit": T.FINDINGS_LIMIT_MAX}))[0])
    assert data["truncated"] is True and data["limit"] == T.FINDINGS_LIMIT_MAX
    assert len(data["rows"]) == T.FINDINGS_LIMIT_MAX
    default = _data((await _tool(app, signing_key, "findings", {}))[0])
    assert len(default["rows"]) == T.FINDINGS_LIMIT_DEFAULT and default["truncated"]


@pytest.mark.parametrize("name,limit", [
    ("findings", T.FINDINGS_LIMIT_MAX + 1), ("findings", 0), ("findings", -5),
    ("reconciliation", T.DENIALS_LIMIT_MAX + 1), ("reconciliation", 0),
])
async def test_a_limit_out_of_range_is_refused(tmp_path, jwks, signing_key, name, limit):
    app = _app(tmp_path, _seed_small(tmp_path / "store"))
    result, _ = await _tool(app, signing_key, name, {"limit": limit})
    assert "limit must be an integer from 1 to" in _error(result)


async def test_row_findings_cap(tmp_path, jwks, signing_key, big_store):
    app = _app(tmp_path, big_store)
    rows = _data((await _tool(app, signing_key, "findings", {"limit": 1}))[0])["rows"]
    assert rows[0]["request_id"] == "req-wide"
    assert len(rows[0]["findings"]) == T.ROW_FINDINGS_MAX
    assert rows[0]["findings_truncated"] is True


async def test_record_findings_cap(tmp_path, jwks, signing_key, big_store):
    app = _app(tmp_path, big_store)
    data = _data((await _tool(app, signing_key, "record", {"reference_id": "fv_wide_1"}))[0])
    assert len(data["record"]["findings"]) == T.RECORD_FINDINGS_MAX
    assert data["record"]["findings_truncated"] is True


async def test_denials_cap(tmp_path, jwks, signing_key, big_store):
    app = _app(tmp_path, big_store)
    data = _data((await _tool(app, signing_key, "reconciliation",
                              {"limit": T.DENIALS_LIMIT_MAX}))[0])["denials"]
    assert len(data["rows"]) == T.DENIALS_LIMIT_MAX and data["truncated"] is True


async def test_detectors_cap(tmp_path, jwks, signing_key, big_store):
    app = _app(tmp_path, big_store)
    data = _data((await _tool(app, signing_key, "summary", {}))[0])
    assert len(data["detectors"]) == T.SUMMARY_DETECTORS_MAX and data["truncated"] is True


async def test_surfaces_cap(tmp_path, jwks, signing_key, big_store):
    app = _app(tmp_path, big_store)
    data = _data((await _tool(app, signing_key, "coverage", {}))[0])["surfaces"]
    assert len(data["rows"]) == T.COVERAGE_SURFACES_MAX and data["truncated"] is True


async def test_summary_surfaces_cap(tmp_path, jwks, signing_key, big_store):
    app = _app(tmp_path, big_store)
    data = _data((await _tool(app, signing_key, "summary", {}))[0])
    assert len(data["surfaces"]) == T.SURFACES_MAX and data["surfaces_truncated"] is True
    assert all(len(d["surfaces"]) <= T.SURFACES_MAX for d in data["detectors"])
    assert data["orgs_truncated"] is False


async def test_topology_surfaces_cap(tmp_path, jwks, signing_key, big_store):
    app = _app(tmp_path, big_store)
    data = _data((await _tool(app, signing_key, "topology", {}))[0])
    assert len(data["surfaces"]) == T.SURFACES_MAX and data["surfaces_truncated"] is True


@pytest.mark.parametrize("entitled,expected",
                         [(True, ["cursor-a"]), (False, ["cursor-a", "cursor-b"])])
async def test_topology_reads_scan_cursors_only_for_a_caller_who_sees_every_org(
        tmp_path, jwks, signing_key, monkeypatch, entitled, expected):
    """A scoped caller's compliance state is decided by the cursors of the
    orgs it can see and no others."""
    from forgd_verdict.dashboard.topology import ComplianceOrg, CompliancePlan

    seen = []
    monkeypatch.setattr("forgd_verdict.dashboard.topology.heartbeats",
                        lambda store, keys: (seen.append(list(keys)) or ({}, {})))
    policy = _policy(tmp_path)
    cfg = config.load(policy)
    store = _seed_small(tmp_path / "store")

    def make():
        reader = T.reader_from_policy(policy, cfg, store)
        reader.compliance = CompliancePlan((ComplianceOrg("cursor-a", A, False),
                                            ComplianceOrg("cursor-b", B, False)))
        if not entitled:
            reader.entitlements = T.Entitlements()
        return create_app(cfg, reader)

    await _tool(_Fresh(make), signing_key, "topology", {}, groups=("g-a",))
    assert seen == [expected]


async def test_uncapped_lists_say_so(tmp_path, jwks, signing_key):
    app = _app(tmp_path, _seed_small(tmp_path / "store"))
    data = _data((await _tool(app, signing_key, "findings", {"window": "30d"}))[0])
    assert data["truncated"] is False and data["limit"] == T.FINDINGS_LIMIT_DEFAULT


# --- arguments -----------------------------------------------------------------

@pytest.mark.parametrize("name,args,message", [
    ("summary", {"window": "all"}, "window"),
    ("findings", {"window": "1y"}, "window"),
    ("topology", {"window": "7d"}, "window"),
    ("summary", {"windw": "7d"}, "windw"),
    ("record", {"reference_id": "fv_x", "org": A}, "org"),
    ("findings", {"source": "bogus"}, "source must be one of"),
    ("findings", {"action": "maybe"}, "action"),
    ("findings", {"since": "yesterday"}, "since must be a UTC timestamp"),
    ("findings", {"window": "24h", "since": "2000-01-01T00:00:00Z"}, "before the start"),
    ("findings", {"surface": "x" * 200}, "surface must be printable"),
    ("findings", {"detector": "a\nb"}, "detector must be printable"),
    ("summary", {"org": "Alpha"}, "org must be an org or workspace pseudonym"),
    ("record", {}, "exactly one of"),
    ("record", {"reference_id": "a", "session_id": "b"}, "exactly one of"),
    ("record", {"reference_id": "fv bad id"}, "reference_id must be"),
    ("findings", {"limit": "10"}, "limit"),
])
async def test_a_bad_argument_is_a_tool_error(tmp_path, jwks, signing_key, name, args,
                                              message):
    app = _app(tmp_path, _seed_small(tmp_path / "store"))
    result, _ = await _tool(app, signing_key, name, args)
    assert message in _error(result), _error(result)


@pytest.mark.parametrize("window", ["all", "1y", "", None, "7D"])
def test_the_window_allowlist(window):
    from mcp.server.mcpserver.exceptions import ToolError

    with pytest.raises(ToolError, match="window must be one of"):
        T.check_window(window)


async def test_findings_since_includes_rows_at_that_second(tmp_path, jwks, signing_key):
    """A row written later with the same second as next_since is not skipped."""
    store = _seed_small(tmp_path / "store")
    app = _app(tmp_path, store)
    first = _data((await _tool(app, signing_key, "findings", {"window": "30d"}))[0])
    cursor = first["next_since"]
    store.write_verdicts([VerdictRecord(
        source=SOURCE_INFERENCE_HOOK, observed_at=cursor, request_id="req-same-second",
        surface="claude-ai", tenant_hash=A, action="allow")])
    again = _data((await _tool(app, signing_key, "findings",
                               {"window": "30d", "since": cursor}))[0])
    assert "req-same-second" in {r["request_id"] for r in again["rows"]}


# --- a connector without the salt --------------------------------------------


def _unsalted_app(tmp_path, store):
    """The writer publishes the org registry; the connector's own policy has
    an explicitly empty salt and no labels, so both come from the registry."""
    from forgd_verdict.orgregistry import REGISTRY_STATE_NAMES
    from forgd_verdict.policy import Policy
    from forgd_verdict.server.app import VerdictServer

    writer = Policy(raw=dict(_policy(tmp_path).raw))
    VerdictServer(writer, store=store, detectors=[]).close()
    assert store.get_state(REGISTRY_STATE_NAMES["verdict"]) is not None

    path = tmp_path / "reader.yaml"
    raw = yaml.safe_load((tmp_path / "policy.yaml").read_text())
    raw["privacy"] = {"hash_salt": ""}
    raw["orgs"] = [{"id": ORG_A_ID}, {"id": ORG_B_ID}]
    path.write_text(yaml.safe_dump(raw))
    policy = load_policy(path)
    assert policy.hash_salt == ""
    cfg = config.load(policy)
    return _Fresh(lambda: create_app(cfg, T.reader_from_policy(policy, cfg, store)))


async def test_an_unsalted_connector_scopes_and_labels_through_the_registry(
        tmp_path, jwks, signing_key):
    store = _seed_small(tmp_path / "store")
    app = _unsalted_app(tmp_path, store)

    summary, raw_summary = await _tool(app, signing_key, "summary", {"window": "30d"},
                                       groups=("g-a",))
    assert [(o["org"], o["label"]) for o in _data(summary)["orgs"]] == [(A, LABEL_A)]
    findings, raw_findings = await _tool(app, signing_key, "findings", {"window": "30d"},
                                         groups=("g-a",))
    rows = _data(findings)["rows"]
    assert rows and {(r["org"], r["label"]) for r in rows} == {(A, LABEL_A)}
    recon, raw_denials = await _tool(app, signing_key, "reconciliation", {"window": "30d"},
                                     groups=("g-a",))
    denials = _data(recon)["denials"]["rows"]
    assert denials and {(d["org"], d["label"]) for d in denials} == {(A, LABEL_A)}

    for raw in (raw_summary, raw_findings, raw_denials):
        text = raw.decode()
        for leak in (ORG_A_ID, ORG_B_ID, B, LABEL_B):
            assert leak not in text


async def test_an_unsalted_connector_with_no_registry_shows_nothing(
        tmp_path, jwks, signing_key):
    store = _seed_small(tmp_path / "store")
    app = _unsalted_app(tmp_path, store)
    from forgd_verdict.orgregistry import REGISTRY_STATE_NAMES

    (tmp_path / "store" / "state" / REGISTRY_STATE_NAMES["verdict"]).unlink()
    findings, raw = await _tool(app, signing_key, "findings", {"window": "30d"},
                                groups=("g-a",))
    assert _data(findings)["rows"] == []
    assert ORG_A_ID.encode() not in raw


# --- intake client partitions ------------------------------------------------

CLIENT = "developer"


def _client_policy(tmp_path, entries):
    _policy(tmp_path)
    raw = yaml.safe_load((tmp_path / "policy.yaml").read_text())
    path = tmp_path / "policy-clients.yaml"
    raw["intake"] = {"clients": [{"name": CLIENT, "token": "$FORGD_INTAKE_TOKEN_DEVELOPER"}]}
    raw["dashboard"]["entitlements"]["map"] = entries
    path.write_text(yaml.safe_dump(raw))
    return load_policy(path)


def _client_app(tmp_path, store, entries, entitled=True):
    policy = _client_policy(tmp_path, entries)
    cfg = config.load(policy)

    def make():
        reader = T.reader_from_policy(policy, cfg, store)
        if not entitled:
            reader.entitlements = T.Entitlements()
        return create_app(cfg, reader)

    return _Fresh(make)


def _seed_client(root) -> LocalFileStore:
    store = _seed_small(root)
    store.write_verdicts([
        VerdictRecord(source=SOURCE_CODE_HOOK, observed_at=_ago(hours=1),
                      request_id="PreToolUse:tool-dev", surface="claude-code",
                      tenant_hash=CLIENT, action="deny", findings_count=1,
                      findings=[_f("regex:password", BAIT_VALUES[4], "tool_input.command",
                                   tool="Bash")]),
    ])
    return store


CLIENT_MAP = [{"group": "g-dev", "orgs": [ORG_A_ID], "clients": [CLIENT]},
              {"group": "g-a", "orgs": [ORG_A_ID]}]


async def test_a_viewer_granted_a_client_reads_its_partition(tmp_path, jwks, signing_key):
    app = _client_app(tmp_path, LeakyStore(_seed_client(tmp_path / "store")), CLIENT_MAP)
    result, raw = await _tool(app, signing_key, "findings",
                              {"window": "30d", "org": CLIENT}, groups=("g-dev",))
    _data(result)
    assert "PreToolUse:tool-dev" in raw.decode()
    assert "req-a1" not in raw.decode()
    summary = _data((await _tool(app, signing_key, "summary", {"window": "30d"},
                                 groups=("g-dev",)))[0])
    kinds = {o["org"]: o["kind"] for o in summary["orgs"]}
    assert kinds.get(CLIENT) == "client" and kinds.get(A) == "org"
    assert B not in kinds


async def test_a_viewer_not_granted_the_client_cannot_read_it(tmp_path, jwks, signing_key):
    app = _client_app(tmp_path, LeakyStore(_seed_client(tmp_path / "store")), CLIENT_MAP)
    result, _ = await _tool(app, signing_key, "findings",
                            {"window": "30d", "org": CLIENT}, groups=("g-a",))
    assert _error(result).startswith("forbidden")
    result, raw = await _tool(app, signing_key, "findings", {"window": "30d"},
                              groups=("g-a",))
    _data(result)
    assert "PreToolUse:tool-dev" not in raw.decode()


async def test_without_entitlements_a_client_partition_can_be_asked_for(
        tmp_path, jwks, signing_key):
    app = _client_app(tmp_path, _seed_client(tmp_path / "store"), CLIENT_MAP,
                      entitled=False)
    result, raw = await _tool(app, signing_key, "findings",
                              {"window": "30d", "org": CLIENT}, groups=())
    _data(result)
    assert "PreToolUse:tool-dev" in raw.decode() and "req-a1" not in raw.decode()


def test_the_connector_starts_on_a_map_that_grants_no_client(tmp_path):
    """Intake records file under orgs, so an org grant reads them."""
    policy = _client_policy(tmp_path, [{"group": "g-a", "orgs": [ORG_A_ID]}])
    config.load(policy)
