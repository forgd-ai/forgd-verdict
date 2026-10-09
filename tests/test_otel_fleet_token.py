"""One OTel exporter token valid for a set of organizations.

An `otel.orgs[]` entry with `ids:` holds a token that a fleet of machines
shares. Each batch is filed under the org it claims, when that org is in
the set; a batch with no claim, a claim outside the set, or claims of two
orgs is refused whole. An entry with `id:` keeps the single-org check.
"""

from __future__ import annotations

import asyncio
import re
import textwrap

import pytest
from conftest import ASGIClient
from test_otel_payload import logs_json

from forgd_verdict.otel.app import Collector
from forgd_verdict.policy import load_policy
from forgd_verdict.sink.fake import FakeSink
from forgd_verdict.store.base import pseudonym
from forgd_verdict.store.local import LocalFileStore

# Fixture ids, not real organizations.
PROD = "00000000-0000-0000-0000-00000000000a"
DEV = "00000000-0000-0000-0000-00000000000b"
OTHER = "00000000-0000-0000-0000-00000000000c"
SALT = "test-salt"
FLEET = "fleet-token-long-enough-to-be-one"
SINGLE = "prod-token-long-enough-to-be-one"


def _policy(tmp_path, orgs: str, sinks: bool = False):
    pol = tmp_path / "policy.yaml"
    sink = textwrap.dedent("""
        sinks:
          - name: siem
            type: otlp
            endpoint: https://collector.test
    """) if sinks else ""
    pol.write_text(textwrap.dedent(f"""
        privacy: {{hash_salt: {SALT}}}
        server: {{store: ""}}
        detectors: {{gitleaks: {{timeout_ms: 60000}}}}
        otel:
          orgs:
    """) + textwrap.indent(textwrap.dedent(orgs), "    ") + sink, encoding="utf-8")
    return load_policy(str(pol))


FLEET_ORGS = f"""
- {{label: laptops, ids: ["{PROD}", "{DEV}"], token: {FLEET}}}
- {{label: prod, id: "{PROD}", token: {SINGLE}}}
"""


@pytest.fixture
def fleet(tmp_path):
    app = Collector(_policy(tmp_path, FLEET_ORGS, sinks=True),
                    store=LocalFileStore(tmp_path / "s", instance="t"), late_detectors=[])
    for fwd in app.forwarders:
        fwd.pipeline.sink = FakeSink(max_events=100, max_bytes=10_000_000)
    yield app
    app.close()


def _batch(*claims, turn="t1"):
    records = []
    for i, claim in enumerate(claims):
        attributes = {"event.name": "claude_code.user_prompt", "prompt": "plain words",
                      "session.id": f"s-{turn}", "prompt.id": f"{turn}-{i}"}
        if claim is not None:
            attributes["organization.id"] = claim
        records.append({"attributes": attributes, "body": ""})
    return logs_json(records, {"service.name": "claude-code"})


def _auth(token=FLEET):
    return {"authorization": f"Bearer {token}", "content-type": "application/json"}


def _stored(app):
    app.sink.close()
    return list(app.sink.store.read_verdicts())


def _forwarded(app):
    fwd = app.forwarders[0]
    fwd.pipeline.flush()
    return [e.org for b in fwd.pipeline.sink.batches for e in b]


async def test_each_org_in_the_set_is_filed_under_itself(fleet):
    client = ASGIClient(fleet)
    assert (await client.post("/v1/logs", _batch(PROD, turn="a"), _auth()))[0] == 200
    assert (await client.post("/v1/logs", _batch(DEV, DEV, turn="b"), _auth()))[0] == 200
    orgs = sorted(r.tenant_hash for r in _stored(fleet))
    assert orgs == sorted([pseudonym(PROD, SALT, "org"), pseudonym(DEV, SALT, "org"),
                           pseudonym(DEV, SALT, "org")])
    assert sorted(_forwarded(fleet)) == sorted([PROD, DEV, DEV])


@pytest.mark.parametrize("claims, error, counter", [
    ((OTHER,), "organization_mismatch", "org_mismatch"),
    ((PROD, OTHER), "organization_mismatch", "org_mismatch"),
    ((None,), "organization_missing", "org_missing"),
    ((PROD, None), "organization_missing", "org_missing"),
    ((PROD, DEV), "organization_mixed", "org_mixed"),
], ids=["outside", "one-outside", "missing", "one-missing", "mixed"])
async def test_a_batch_the_set_cannot_attribute_to_one_org_is_refused(fleet, claims,
                                                                     error, counter):
    status, body = await ASGIClient(fleet).post("/v1/logs", _batch(*claims), _auth())
    assert (status, body) == (403, {"error": error})
    assert fleet._counts.get(counter) == 1
    assert _stored(fleet) == []


async def test_a_single_org_token_keeps_its_check(fleet):
    client = ASGIClient(fleet)
    status, body = await client.post("/v1/logs", _batch(DEV), _auth(SINGLE))
    assert (status, body) == (403, {"error": "organization_mismatch"})
    # A missing claim is still filed under the token's org.
    assert (await client.post("/v1/logs", _batch(None), _auth(SINGLE)))[0] == 200
    assert [r.tenant_hash for r in _stored(fleet)] == [pseudonym(PROD, SALT, "org")]


async def test_concurrent_requests_on_one_fleet_token_do_not_cross_file(fleet):
    client = ASGIClient(fleet)
    batches = [(PROD if i % 2 else DEV, f"turn{i}") for i in range(8)]
    # Every batch in flight at once, past the default `otel.export_workers`.
    fleet._exporting = asyncio.Semaphore(len(batches))
    results = await asyncio.gather(*(client.post("/v1/logs", _batch(org, turn=turn), _auth())
                                     for org, turn in batches))
    assert [s for s, _ in results] == [200] * len(batches)
    want = {f"s-{turn}": pseudonym(org, SALT, "org") for org, turn in batches}
    got = {r.session_id: r.tenant_hash for r in _stored(fleet)}
    assert got == want


@pytest.mark.parametrize("orgs, message", [
    (f'- {{label: x, id: "{PROD}", ids: ["{DEV}"], token: {FLEET}}}', "both id and ids"),
    (f"- {{label: x, ids: [], token: {FLEET}}}", "ids must be a non-empty list"),
    (f'- {{label: x, ids: "{PROD}", token: {FLEET}}}', "ids must be a non-empty list"),
    (f'- {{label: x, ids: ["{PROD}", ""], token: {FLEET}}}', "ids[1] resolves to nothing"),
    (f'- {{label: x, ids: ["{PROD}", "$FORGD_ORG_ID_UNSET_X"], token: {FLEET}}}',
     "ids[1] resolves to nothing"),
    (f'- {{label: x, ids: ["{PROD}", "{PROD}"], token: {FLEET}}}', "ids[1] repeats"),
    (f'- {{label: x, ids: ["{PROD}"], token: {FLEET}}}\n'
     f'- {{label: y, id: "{DEV}", token: {FLEET}}}', "have the same token"),
])
def test_an_unusable_ids_entry_refuses_to_start(tmp_path, monkeypatch, orgs, message):
    monkeypatch.delenv("FORGD_ORG_ID_UNSET_X", raising=False)
    with pytest.raises(ValueError, match=re.escape(message)):
        Collector(_policy(tmp_path, orgs), store=None)


def test_an_ids_element_may_come_from_the_environment(tmp_path, monkeypatch):
    monkeypatch.setenv("FORGD_ORG_ID_DEV", DEV)
    app = Collector(_policy(tmp_path, f'- {{label: x, ids: ["{PROD}", "$FORGD_ORG_ID_DEV"], '
                                      f"token: {FLEET}}}"), store=None)
    try:
        assert app.tokens[FLEET]["ids"] == frozenset({PROD, DEV})
    finally:
        app.close()


async def test_a_fleet_token_rotates_with_two_entries_for_one_set(tmp_path):
    new = "fleet-token-new-long-enough-to-be-one"
    orgs = (f'- {{label: laptops, ids: ["{PROD}", "{DEV}"], token: {FLEET}}}\n'
            f'- {{label: laptops, ids: ["{PROD}", "{DEV}"], token: {new}}}')
    app = Collector(_policy(tmp_path, orgs), store=LocalFileStore(tmp_path / "s", instance="t"))
    try:
        client = ASGIClient(app)
        assert (await client.post("/v1/logs", _batch(PROD, turn="a"), _auth()))[0] == 200
        assert (await client.post("/v1/logs", _batch(DEV, turn="b"), _auth(new)))[0] == 200
    finally:
        app.close()


async def test_an_empty_batch_on_a_fleet_token_files_nothing(fleet, monkeypatch):
    def no_collect(*a, **kw):
        raise AssertionError("collect ran for an empty batch")

    monkeypatch.setattr("forgd_verdict.otel.app.collect", no_collect)
    status, body = await ASGIClient(fleet).post("/v1/logs", logs_json([], {}), _auth())
    assert (status, body) == (200, {"partialSuccess": {}})
    assert _stored(fleet) == []
