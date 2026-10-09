"""Adapter 2's receiving end.

Without it, every laptop running the hook needs data-plane WRITE access to
the findings container, and Storage Blob Data Contributor includes DELETE --
so a developer machine could alter or remove findings in a tool whose output
is evidence. A bearer token can only append, and can be revoked per
developer.
"""

from __future__ import annotations

import json

import pytest
from conftest import (
    FAKE_AWS_KEY,
    UNPARSEABLE_DEPTH,
    ASGIClient,
    max_json_depth,
    nested_json,
)

from forgd_verdict.intake.app import Intake
from forgd_verdict.policy import Policy
from forgd_verdict.store import LocalFileStore
from forgd_verdict.store.base import (
    ORG_UNATTRIBUTED,
    SOURCE_CODE_HOOK,
    SOURCE_INFERENCE_HOOK,
    FindingRow,
    VerdictRecord,
)

TOKEN = "intake-token-for-alice-0123456789"


def _policy(**intake) -> Policy:
    cfg = {"clients": [{"name": "alice-laptop", "token": TOKEN}]}
    cfg.update(intake)
    # Merged over DEFAULT_POLICY, because `load_policy` always is and the
    # app has a real detector set in every deployment. A bare Policy has
    # no `detectors` section, which `/scan` needs and which no running
    # service is ever without.
    from forgd_verdict.policy import DEFAULT_POLICY, _deep_merge

    return Policy(raw=_deep_merge(DEFAULT_POLICY, {
        "intake": cfg, "privacy": {"hash_salt": "s"}}))


@pytest.fixture
def intake(tmp_path):
    app = Intake(_policy(), store=LocalFileStore(tmp_path, instance="t"))
    yield app
    app.close()


def _rec(source=SOURCE_CODE_HOOK, **kw) -> VerdictRecord:
    return VerdictRecord(
        source=source,
        observed_at="2026-09-20T10:00:00Z",
        surface="claude-code-local",
        action="deny",
        findings=[FindingRow("regex:aws-access-key", "block", "cmd", "h1")],
        findings_count=1,
        **kw,
    )


def _ndjson(*records) -> bytes:
    return ("\n".join(r.to_json() for r in records) + "\n").encode()


def _read(app, *args) -> list[VerdictRecord]:
    """What the app has written, once its sink has flushed."""
    app.flush()
    return list(app.store.read_verdicts(*args))


def auth(token=TOKEN) -> dict:
    return {"authorization": f"Bearer {token}", "content-type": "application/x-ndjson"}


# -- the happy path ------------------------------------------------------


async def test_a_batch_is_accepted_and_stored(intake):
    status, body = await ASGIClient(intake).post(
        "/intake", _ndjson(_rec(), _rec()), auth()
    )
    assert status == 200
    assert body["accepted"] == 2
    assert len(_read(intake)) == 2


async def test_submissions_are_attributed_to_a_client(intake):
    """A shared token nobody can attribute is a token nobody will rotate."""
    await ASGIClient(intake).post("/intake", _ndjson(_rec()), auth())
    assert intake.stats()["by_client"] == {"alice-laptop": 1}


# -- the credential ------------------------------------------------------


async def test_an_unauthenticated_submission_is_refused(intake):
    status, _ = await ASGIClient(intake).post("/intake", _ndjson(_rec()), {})
    assert status == 401
    assert not _read(intake)


async def test_a_wrong_token_is_refused(intake):
    status, _ = await ASGIClient(intake).post(
        "/intake", _ndjson(_rec()), auth("not-the-token-0123456789abcdef")
    )
    assert status == 401


async def test_the_placeholder_token_is_not_a_credential(tmp_path):
    """The example in this repository must not be a working key.

    A bearer token has no format to fail and a placeholder is non-empty, so
    without this the value committed here would authenticate anyone who read
    it. Same reasoning as adapter 4's org tokens.
    """
    app = Intake(
        Policy(raw={"privacy": {"allow_unsalted": True}, "intake": {"clients": [
            {"name": "example", "token": "placeholder-not-yet-issued"},
        ]}}),
        store=LocalFileStore(tmp_path, instance="t"),
    )
    try:
        assert app.configured() == 0
        status, _ = await ASGIClient(app).post(
            "/intake", _ndjson(_rec()),
            {"authorization": "Bearer " + "placeholder-not-yet-issued"},
        )
        assert status == 401
    finally:
        app.close()


async def test_with_no_clients_configured_everything_is_refused(tmp_path):
    app = Intake(Policy(raw={"privacy": {"allow_unsalted": True},
                             "intake": {"clients": []}}),
                 store=LocalFileStore(tmp_path, instance="t"))
    try:
        status, _ = await ASGIClient(app).post("/intake", _ndjson(_rec()), auth())
        assert status == 401
    finally:
        app.close()


# -- forgery -------------------------------------------------------------


async def test_a_laptop_token_cannot_forge_an_inference_hook_record(intake):
    """The reason `source` is checked rather than trusted.

    Otherwise a laptop token can write rows that claim to be adapter 1 and
    move the numbers this whole project is about: coverage, would-deny
    rates, the reconciliation between live and post-hoc detection.
    """
    status, body = await ASGIClient(intake).post(
        "/intake", _ndjson(_rec(source=SOURCE_INFERENCE_HOOK)), auth()
    )
    assert status == 400
    assert body["rejected"] == 1
    assert not _read(intake)


async def test_a_mixed_batch_keeps_only_the_hook_records(intake):
    status, body = await ASGIClient(intake).post(
        "/intake",
        _ndjson(_rec(), _rec(source=SOURCE_INFERENCE_HOOK), _rec()),
        auth(),
    )
    assert status == 200
    assert body == {"accepted": 2, "rejected": 1}
    stored = _read(intake)
    assert {r.source for r in stored} == {SOURCE_CODE_HOOK}


async def test_one_unparseable_line_does_not_lose_the_batch(intake):
    body = b"not json\n" + _ndjson(_rec())
    status, payload = await ASGIClient(intake).post("/intake", body, auth())
    assert status == 200
    assert payload == {"accepted": 1, "rejected": 1}


# -- write-only ----------------------------------------------------------


async def test_there_is_no_read_path(intake):
    """A stolen token must not be able to enumerate findings.

    Not "reads are refused" -- there is no endpoint to find, so a token
    cannot probe for one.
    """
    client = ASGIClient(intake)
    for path in ("/", "/intake", "/events", "/api/summary", "/findings"):
        status, _ = await client.get(path, auth())
        assert status == 404, path


async def test_health_is_open_for_probes(intake):
    status, body = await ASGIClient(intake).get("/healthz")
    assert status == 200
    assert body["status"] == "ok"
    assert body["clients_configured"] == 1


async def test_health_reveals_no_token(intake):
    _, body = await ASGIClient(intake).get("/healthz")
    assert TOKEN not in json.dumps(body)


# -- failure modes the hook depends on -----------------------------------


async def test_a_store_failure_is_a_5xx_so_the_hook_parks_the_batch(tmp_path):
    """A 4xx would make the hook discard findings it had already scanned,
    and a 2xx would make it delete them.

    ship.py parks a batch on anything that is not 2xx, and retries it.
    """
    class Broken:
        def write_verdicts(self, records):
            raise RuntimeError("storage unreachable")

    app = Intake(_policy(), store=Broken())
    try:
        status, body, headers = await ASGIClient(app).request(
            "POST", "/intake", _ndjson(_rec()), auth())
        assert status == 503
        assert body == {"error": "unavailable"}
        assert headers.get("retry-after")
        assert app.stats()["counts"]["store_error"] == 1
    finally:
        app.close()


async def test_no_store_configured_is_also_a_5xx(tmp_path):
    app = Intake(_policy(), store=None)
    try:
        status, _ = await ASGIClient(app).post("/intake", _ndjson(_rec()), auth())
        assert status == 503
    finally:
        app.close()


async def test_an_oversized_batch_is_refused(tmp_path):
    app = Intake(_policy(max_body_bytes=200),
                 store=LocalFileStore(tmp_path, instance="t"))
    try:
        status, _ = await ASGIClient(app).post(
            "/intake", _ndjson(*[_rec() for _ in range(20)]), auth()
        )
        assert status == 413
    finally:
        app.close()


# -- lifespan ------------------------------------------------------------


async def test_shutdown_closes_the_store(tmp_path):
    """The collector closes its store on shutdown and this did not.

    The omission hid behind an unreachable `return` after the lifespan
    loop: read as an exit path, it made the loop look like it fell through
    to cleanup that was never there.
    """
    closed = []

    class Watched:
        def write_verdicts(self, records):
            return len(records)

        def close(self):
            closed.append(True)

    app = Intake(_policy(), store=Watched())
    sent = []
    messages = iter([
        {"type": "lifespan.startup"},
        {"type": "lifespan.shutdown"},
    ])

    async def receive():
        return next(messages)

    async def send(message):
        sent.append(message["type"])

    await app({"type": "lifespan"}, receive, send)
    assert sent == ["lifespan.startup.complete", "lifespan.shutdown.complete"]
    assert closed == [True], "the store was never closed"


# -- a record must belong to the writer ----------------------------------


async def test_a_forged_tenant_and_date_are_overwritten(intake, tmp_path):
    """The token authenticated the writer and nothing bound the RECORD to
    them. `from_json` accepts every dataclass field off the wire, and the
    store partitions by `tenant_hash` and `observed_at`, so one POST with
    a valid token wrote:

        verdicts/source=code_hook/org=MADE-UP-ORG/date=1999-01-01/...
          {"tenant_hash": "MADE-UP-ORG",
           "actor_hash": "ceo@victim.example",
           "salt_namespace": "attacker-salt"}

    -- an invented org as a real partition on disk, and a chosen window
    for the evidence.
    """
    from dataclasses import replace

    forged = replace(_rec(tenant_hash="MADE-UP-ORG",
                          actor_hash="ceo@victim.example",
                          salt_namespace="attacker-salt"),
                     observed_at="1999-01-01T00:00:00Z")
    status, payload = await ASGIClient(intake).post(
        "/intake", _ndjson(forged), auth())
    assert status == 200 and payload["accepted"] == 1

    written = _read(intake, "1990-01-01T00:00:00Z", None)
    assert len(written) == 1
    rec = written[0]
    assert rec.tenant_hash == ORG_UNATTRIBUTED, rec.tenant_hash
    assert rec.client == "alice-laptop", rec.client
    assert not rec.observed_at.startswith("1999"), rec.observed_at
    assert rec.salt_namespace.startswith("alice-laptop:"), rec.salt_namespace


async def test_an_honest_record_survives_the_binding(intake):
    """The findings and the verdict are the writer's to assert; only the
    fields that decide attribution and partitioning are overwritten."""
    status, payload = await ASGIClient(intake).post(
        "/intake", _ndjson(_rec(request_id="r1")), auth())
    assert status == 200 and payload["accepted"] == 1

    rec = _read(intake, "1990-01-01T00:00:00Z", None)[0]
    assert rec.action == "deny"
    assert rec.request_id == "r1"
    assert rec.findings_count == 1


# -- /scan: adapter 2's verdict, decided where the tiers are -------------


def _scan_payload(**kw):
    import json as _json
    return _json.dumps(kw).encode()


def _scan_auth(token=TOKEN):
    return {"authorization": f"Bearer {token}", "content-type": "application/json"}


async def test_a_clean_prompt_is_allowed(intake):
    status, body = await ASGIClient(intake).post(
        "/scan", _scan_payload(hook_event_name="UserPromptSubmit",
                               user_input="refactor the parser"), _scan_auth())
    assert status == 200
    assert body["action"] == "allow" and body["detectors"] == []


async def test_a_prompt_with_a_key_is_denied(intake):
    status, body = await ASGIClient(intake).post(
        "/scan", _scan_payload(hook_event_name="UserPromptSubmit",
                               user_input=f"deploy {FAKE_AWS_KEY}"), _scan_auth())
    assert status == 200
    assert body["action"] == "deny"
    assert "regex:aws-access-key" in body["detectors"]
    assert body["deny_reason"]


async def test_a_tool_input_key_holding_a_key_is_denied(intake):
    key = "AKIAQYLPMN5HGZTHX4UQ"  # gitleaks:allow
    status, body = await ASGIClient(intake).post(
        "/scan", _scan_payload(hook_event_name="PreToolUse", tool_name="mcp__x__y",
                               tool_input={key: 1}), _scan_auth())
    assert status == 200
    assert body["action"] == "deny"
    assert "regex:aws-access-key" in body["detectors"]


async def test_the_scan_route_needs_a_token(intake):
    status, _ = await ASGIClient(intake).post(
        "/scan", _scan_payload(hook_event_name="UserPromptSubmit",
                               user_input="hello"),
        {"content-type": "application/json"})
    assert status == 401


async def test_a_wrong_token_is_refused_on_scan(intake):
    status, _ = await ASGIClient(intake).post(
        "/scan", _scan_payload(hook_event_name="UserPromptSubmit", user_input="x"),
        _scan_auth("not-the-token-0123456789abcdef"))
    assert status == 401


async def test_the_scan_returns_no_matched_content(intake):
    """The laptop already has the content and the store has the evidence.
    The response carries a decision and detector names -- no locators, no
    excerpt hashes, and never the value."""
    import json as _json

    _, body = await ASGIClient(intake).post(
        "/scan", _scan_payload(hook_event_name="UserPromptSubmit",
                               user_input=f"deploy {FAKE_AWS_KEY}"), _scan_auth())
    blob = _json.dumps(body)
    assert FAKE_AWS_KEY not in blob
    assert "excerpt_hash" not in blob and "locator" not in blob


async def test_the_scan_records_the_finding_against_the_writer(intake):
    await ASGIClient(intake).post(
        "/scan", _scan_payload(hook_event_name="UserPromptSubmit",
                               user_input=f"deploy {FAKE_AWS_KEY}"), _scan_auth())
    written = _read(intake, "1990-01-01T00:00:00Z", None)
    assert len(written) == 1
    assert written[0].source == SOURCE_CODE_HOOK
    assert written[0].tenant_hash == ORG_UNATTRIBUTED
    assert written[0].client == "alice-laptop"
    assert written[0].findings_count == 1


async def test_a_scan_record_stays_in_the_deployment_salt_namespace(intake):
    """Nothing arrived hashed, so there is no device namespace to keep.

    /scan matched the content in this process with the deployment salt,
    which is what an empty `salt_namespace` means. Stamping the writer's
    device namespace on it anyway tells a reader these hashes are not
    comparable with any other server-side writer's -- and a reader that
    believes it counts one leaked key as two.
    """
    await ASGIClient(intake).post(
        "/scan", _scan_payload(hook_event_name="UserPromptSubmit",
                               user_input=f"deploy {FAKE_AWS_KEY}"), _scan_auth())
    written = _read(intake, "1990-01-01T00:00:00Z", None)
    assert written[0].salt_namespace is None, written[0].salt_namespace


async def test_a_card_number_held_as_a_json_number_denies(intake):
    status, body = await ASGIClient(intake).post(
        "/scan", _scan_payload(hook_event_name="PreToolUse", tool_name="mcp__db__insert",
                               tool_input={"card": 4539148803436467}), _scan_auth())
    assert status == 200
    assert body["action"] == "deny"
    assert "4539148803436467" not in json.dumps(body)


async def test_an_integer_over_the_digit_limit_is_scanned_not_400(intake):
    raw = _scan_payload(hook_event_name="PreToolUse", tool_name="mcp__db__insert",
                        tool_input={"n": "BIG", "note": f"deploy {FAKE_AWS_KEY}"})
    raw = raw.replace(b'"BIG"', b"4" * 5000)
    status, body = await ASGIClient(intake).post("/scan", raw, _scan_auth())
    assert status == 200
    assert body["action"] == "deny"


async def test_an_undecodable_body_is_400(intake):
    status, _ = await ASGIClient(intake).post("/scan", b"{not json", _scan_auth())
    assert status == 400


async def test_a_body_nested_too_deeply_is_400(intake, caplog):
    inner = _scan_payload(hook_event_name="UserPromptSubmit",
                          user_input=f"deploy {FAKE_AWS_KEY}").decode()
    raw = nested_json(inner, UNPARSEABLE_DEPTH).encode()
    status, body = await ASGIClient(intake).post("/scan", raw, _scan_auth())
    assert status == 400
    assert body == {"error": "undecodable"}
    assert FAKE_AWS_KEY not in caplog.text


@pytest.mark.parametrize("margin", [None, 20])
async def test_a_secret_at_the_bottom_of_a_parseable_nesting_denies(intake, margin):
    depth = 900 if margin is None else max_json_depth() - margin
    raw = ('{"hook_event_name": "PreToolUse", "session_id": "s", '
           '"tool_name": "mcp__x__run", "tool_input": {"q": '
           + nested_json(json.dumps(f"deploy {FAKE_AWS_KEY}"), depth) + "}}").encode()
    status, body = await ASGIClient(intake).post("/scan", raw, _scan_auth())
    assert status == 200
    assert body["action"] == "deny"
    assert FAKE_AWS_KEY not in json.dumps(body)


async def test_there_is_still_no_read_path(intake):
    """`/scan` takes what it is given. A stolen token buys a scan, not
    anyone else's findings."""
    for path in ("/scan", "/findings", "/intake"):
        status, _ = await ASGIClient(intake).get(path, _scan_auth())
        assert status == 404, path


# -- route scopes ---------------------------------------------------------

SCAN_ONLY = "scan-only-token-for-bob-0123456789"
SHIP_ONLY = "ship-only-token-for-cat-0123456789"


@pytest.fixture
def scoped(tmp_path):
    app = Intake(_policy(clients=[
        {"name": "alice-laptop", "token": TOKEN},
        {"name": "bob-laptop", "token": SCAN_ONLY, "routes": ["scan"]},
        {"name": "cat-laptop", "token": SHIP_ONLY, "routes": ["intake"]},
    ]), store=LocalFileStore(tmp_path, instance="t"))
    yield app
    app.close()


async def test_a_client_with_no_routes_key_keeps_both(scoped):
    """Every client configured before scopes existed must keep working."""
    c = ASGIClient(scoped)
    status, _ = await c.post("/scan", _scan_payload(
        hook_event_name="UserPromptSubmit", user_input="hi"), _scan_auth(TOKEN))
    assert status == 200
    status, _ = await c.post("/intake", _rec().to_json().encode(), auth(TOKEN))
    assert status == 200


async def test_a_scan_only_token_cannot_write_records(scoped):
    """The reason scopes exist: a token that asks for verdicts should not
    also be able to add evidence attributed to its holder."""
    c = ASGIClient(scoped)
    status, _ = await c.post("/scan", _scan_payload(
        hook_event_name="UserPromptSubmit", user_input="hi"), _scan_auth(SCAN_ONLY))
    assert status == 200
    before = len(_read(scoped, "1990-01-01T00:00:00Z", None))
    status, body = await c.post("/intake", _rec().to_json().encode(), auth(SCAN_ONLY))
    assert status == 403 and body == {"error": "forbidden", "route": "intake"}
    after = len(_read(scoped, "1990-01-01T00:00:00Z", None))
    assert after == before
    assert scoped.stats()["counts"]["forbidden_route"] == 1


async def test_an_intake_only_token_cannot_scan(scoped):
    status, body = await ASGIClient(scoped).post("/scan", _scan_payload(
        hook_event_name="UserPromptSubmit", user_input="hi"), _scan_auth(SHIP_ONLY))
    assert status == 403 and body["route"] == "scan"


async def test_a_wrong_token_is_still_401_not_403(scoped):
    status, _ = await ASGIClient(scoped).post("/scan", _scan_payload(
        hook_event_name="UserPromptSubmit", user_input="hi"),
        _scan_auth("not-a-configured-token-0123456789"))
    assert status == 401


@pytest.mark.parametrize("routes", [[], ["scna"], "scan", ["scan", "admin"]])
def test_a_malformed_scope_refuses_to_start(tmp_path, routes):
    """A typo in a scope is a token that has none, or one an operator
    believes is narrower than it is. Neither should start quietly."""
    with pytest.raises(ValueError, match="routes"):
        Intake(_policy(clients=[
            {"name": "bob-laptop", "token": SCAN_ONLY, "routes": routes}]),
            store=LocalFileStore(tmp_path, instance="t"))


def test_a_malformed_scope_is_refused_even_before_its_token_is_set(tmp_path, monkeypatch):
    """A client whose variable is unset is skipped. Its scope must still be
    checked, or the mistake surfaces on the deploy that sets the token."""
    monkeypatch.delenv("FORGD_INTAKE_TOKEN_LATER", raising=False)
    with pytest.raises(ValueError, match="routes"):
        Intake(_policy(clients=[
            {"name": "alice-laptop", "token": TOKEN},
            {"name": "later-laptop", "token": "$FORGD_INTAKE_TOKEN_LATER",
             "routes": ["scna"]}]),
            store=LocalFileStore(tmp_path, instance="t"))


@pytest.mark.parametrize("name", [
    "x/../../escaped", "..", ".", "a\\b", "name\n", " pad", "pad ", "Alice", "alice_laptop",
    "1laptop", "-laptop", "a" * 41, 7, ["alice"],
])
def test_a_client_name_that_is_not_a_label_refuses_to_start(tmp_path, name):
    """The name is the client's org partition in the store, so it is held
    to the label form rather than escaped."""
    with pytest.raises(ValueError, match=r"intake\.clients\[0\]\.name"):
        Intake(_policy(clients=[{"name": name, "token": TOKEN}]),
               store=LocalFileStore(tmp_path, instance="t"))
    assert list(tmp_path.parent.glob("escaped")) == []


def test_a_client_named_like_the_unattributed_partition_refuses_to_start(tmp_path):
    """Its records would pool with every record that has no org."""
    with pytest.raises(ValueError, match=r"intake\.clients\[0\]\.name.*no org"):
        Intake(_policy(clients=[{"name": ORG_UNATTRIBUTED, "token": TOKEN}]),
               store=LocalFileStore(tmp_path, instance="t"))


@pytest.mark.parametrize("client", [{"token": TOKEN}, {"name": "", "token": TOKEN},
                                    {"name": None, "token": TOKEN}])
def test_a_client_without_a_name_refuses_to_start(tmp_path, client):
    with pytest.raises(ValueError, match=r"intake\.clients\[0\]\.name is required"):
        Intake(_policy(clients=[client]), store=LocalFileStore(tmp_path, instance="t"))


def test_a_bad_client_name_is_refused_even_before_its_token_is_set(tmp_path, monkeypatch):
    monkeypatch.delenv("FORGD_INTAKE_TOKEN_LATER", raising=False)
    with pytest.raises(ValueError, match=r"intake\.clients\[1\]\.name"):
        Intake(_policy(clients=[
            {"name": "alice-laptop", "token": TOKEN},
            {"name": "../later", "token": "$FORGD_INTAKE_TOKEN_LATER"}]),
            store=LocalFileStore(tmp_path, instance="t"))


@pytest.mark.parametrize("name", ["a", "alice-laptop", "invoice-bot", "a" * 40])
def test_a_label_form_client_name_starts(tmp_path, name):
    app = Intake(_policy(clients=[{"name": name, "token": TOKEN}]),
                 store=LocalFileStore(tmp_path, instance="t"))
    assert [c.name for v in app.verifiers for c in v.credentials()] == [name]


OTHER = "intake-token-for-bob-9876543210"


@pytest.mark.parametrize("via_env", [False, True])
def test_two_clients_with_one_token_refuse_to_start(tmp_path, monkeypatch, via_env):
    """The map is token -> client, so the second would silently take the
    first's identity and scope. Named by index and name, never the token."""
    if via_env:
        monkeypatch.setenv("FORGD_INTAKE_TOKEN_A", TOKEN)
        monkeypatch.setenv("FORGD_INTAKE_TOKEN_B", TOKEN)
        first, second = "$FORGD_INTAKE_TOKEN_A", "$FORGD_INTAKE_TOKEN_B"
    else:
        first = second = TOKEN
    with pytest.raises(ValueError, match="same token") as exc:
        Intake(_policy(clients=[
            {"name": "alice-laptop", "token": first},
            {"name": "bob-laptop", "token": second, "routes": ["scan"]}]),
            store=LocalFileStore(tmp_path, instance="t"))
    message = str(exc.value)
    assert "intake.clients[0] ('alice-laptop')" in message
    assert "intake.clients[1] ('bob-laptop')" in message
    assert TOKEN not in message


def test_two_clients_with_one_name_refuse_to_start(tmp_path, monkeypatch):
    """Even with different tokens, and even when one token is not set yet:
    the name is the partition, so two clients would write as one."""
    monkeypatch.delenv("FORGD_INTAKE_TOKEN_LATER", raising=False)
    for second in (OTHER, "$FORGD_INTAKE_TOKEN_LATER"):
        with pytest.raises(ValueError, match="both named 'alice-laptop'") as exc:
            Intake(_policy(clients=[
                {"name": "alice-laptop", "token": TOKEN},
                {"name": "alice-laptop", "token": second}]),
                store=LocalFileStore(tmp_path, instance="t"))
        assert "intake.clients[0] and intake.clients[1]" in str(exc.value)
        assert TOKEN not in str(exc.value) and OTHER not in str(exc.value)


def test_two_clients_with_their_own_names_and_tokens_start(tmp_path):
    app = Intake(_policy(clients=[{"name": "alice-laptop", "token": TOKEN},
                                  {"name": "bob-laptop", "token": OTHER}]),
                 store=LocalFileStore(tmp_path, instance="t"))
    assert sorted(c.name for v in app.verifiers for c in v.credentials()) == [
        "alice-laptop", "bob-laptop"]


# -- field types -----------------------------------------------------------


@pytest.mark.parametrize("field,value", [
    ("scan_ms", "boom"),
    ("messages_scanned", "<script>x</script>"),
    ("messages_total", True),
    ("body_bytes", 1.5),
    ("cache_hit", 1),
    ("surface", 7),
    ("tiers_dropped", "regex"),
    ("scan_ms", float("nan")),
])
async def test_a_wrongly_typed_field_is_refused(intake, field, value):
    from dataclasses import replace

    body = _ndjson(replace(_rec(), **{field: value}), _rec())
    status, payload = await ASGIClient(intake).post("/intake", body, auth())
    assert status == 200
    assert payload == {"accepted": 1, "rejected": 1}
    assert intake.stats()["counts"]["rejected_records"] == 1


async def test_a_wrongly_typed_finding_is_refused(intake):
    rec = _rec()
    rec.findings = [FindingRow("regex:aws-access-key", "block", 3, "h1")]
    status, payload = await ASGIClient(intake).post("/intake", _ndjson(rec), auth())
    assert status == 400
    assert payload == {"error": "no_usable_records", "rejected": 1}


async def test_a_shipped_string_scan_ms_does_not_break_the_event_log(intake):
    from forgd_verdict.dashboard.app import Dashboard

    await ASGIClient(intake).post("/intake", _ndjson(_rec(scan_ms="boom")), auth())
    status, _ = await ASGIClient(Dashboard(intake.store)).get("/events?window=all")
    assert status == 200


async def test_shipped_markup_in_a_count_is_not_rendered(intake):
    from forgd_verdict.dashboard.app import Dashboard

    await ASGIClient(intake).post(
        "/intake", _ndjson(_rec(messages_scanned="<script>x</script>")), auth())
    status, html = await ASGIClient(Dashboard(intake.store)).get("/events?window=all")
    assert status == 200
    assert "<script>x</script>" not in html
