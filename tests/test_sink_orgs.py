"""A sink forwards for some organizations and not others."""

from __future__ import annotations

import textwrap

import pytest
from conftest import ASGIClient

from forgd_verdict.budget import Budget
from forgd_verdict.core import scan
from forgd_verdict.otel.app import Collector
from forgd_verdict.otel.extract import record_units_by_key
from forgd_verdict.otel.payload import OtelRecord
from forgd_verdict.policy import load_policy
from forgd_verdict.sink.base import SinkUnavailable
from forgd_verdict.sink.fake import FakeSink

PROD = "00000000-0000-0000-0000-00000000000a"
DEV = "00000000-0000-0000-0000-00000000000b"


def _app(tmp_path, sink_orgs: str = "", extra_orgs: str = ""):
    orgs_line = f"orgs: {sink_orgs}" if sink_orgs else ""
    pol = tmp_path / "policy.yaml"
    pol.write_text(textwrap.dedent(f"""
        privacy: {{hash_salt: test-salt}}
        server: {{store: ""}}
        otel:
          orgs:
            - {{label: prod, id: "{PROD}", token: prod-token-long-enough-to-be-one}}
            - {{label: dev, id: "{DEV}", token: dev-token-long-enough-to-be-one}}
            {extra_orgs}
        sinks:
          - name: siem
            type: otlp
            endpoint: https://collector.test
            {orgs_line}
    """), encoding="utf-8")
    app = Collector(load_policy(str(pol)), store=None, late_detectors=[])
    for fwd in app.forwarders:
        fwd.pipeline.sink = FakeSink(max_events=100, max_bytes=10_000_000)
    return app


def _send(app, org_id):
    rec = OtelRecord(kind="span", name="agent.query",
                     attributes={"service.name": "office-agent",
                                 "prompt.id": "p1", "user.message": "hello there"})
    units = [u for _, u in record_units_by_key(rec, 0)]
    r = scan(units, app.detectors, Budget(5000))
    forward = app._forward_group(org_id)
    forward([rec], r.findings, "claude-for-m365", r.detectors_skipped)
    forward.finish()


def _forwarded_orgs(app):
    fwd = app.forwarders[0]
    fwd.pipeline.flush()
    return [e.org for b in fwd.pipeline.sink.batches for e in b]


def test_no_orgs_key_forwards_every_org(tmp_path):
    """What every sink did before the field existed."""
    app = _app(tmp_path)
    try:
        _send(app, PROD)
        _send(app, DEV)
        assert _forwarded_orgs(app) == [PROD, DEV]
    finally:
        app.close()


def test_a_scoped_sink_forwards_only_its_orgs(tmp_path):
    app = _app(tmp_path, "[prod]")
    try:
        _send(app, PROD)
        _send(app, DEV)
        assert _forwarded_orgs(app) == [PROD]
        s = app.forwarders[0].stats()
        # A scope is a choice, not a loss, so it is not counted as dropped.
        assert s["out_of_scope"] == 1 and s["dropped"] == 0
        assert s["orgs"] == ["prod"]
    finally:
        app.close()


async def test_the_scope_is_checked_through_the_real_request_path(tmp_path):
    """`_forward_group` is called from the export handler with the TOKEN's
    org, so a dev token cannot reach a prod-only sink by claiming prod."""
    import json

    app = _app(tmp_path, "[prod]")
    body = json.dumps({"resourceLogs": [{"scopeLogs": [{"logRecords": [{
        "attributes": [
            {"key": "event.name", "value": {"stringValue": "claude_code.user_prompt"}},
            {"key": "prompt", "value": {"stringValue": "hello from dev"}},
        ]}]}]}]}).encode()
    try:
        status, _ = await ASGIClient(app).post(
            "/v1/logs", body, {"authorization": "Bearer " + "dev-token-long-enough-to-be-one",
                               "content-type": "application/json"})
        assert status == 200
        assert _forwarded_orgs(app) == []
        assert app.forwarders[0].out_of_scope == 1
    finally:
        app.close()


@pytest.mark.parametrize("orgs, match", [
    ("[prdo]", "not an otel.orgs label"),
    ("[]", "non-empty list"),
    ("prod", "non-empty list"),
])
def test_a_scope_nobody_can_match_refuses_to_start(tmp_path, orgs, match):
    with pytest.raises(SinkUnavailable, match=match):
        _app(tmp_path, orgs)


def test_an_ambiguous_label_refuses_to_start(tmp_path):
    with pytest.raises(SinkUnavailable, match="ambiguous"):
        _app(tmp_path, "[prod]", extra_orgs=(
            '- {label: prod, id: "00000000-0000-0000-0000-00000000000c", '
            'token: other-token-long-enough-to-be-one}'))


def test_an_org_whose_token_is_unset_can_still_be_named(tmp_path, monkeypatch):
    """Labels are checked against the whole policy, not only orgs that
    authenticate here -- or a sink scoped to an org that is not live yet
    fails on the deploy that sets its token instead of this one."""
    monkeypatch.delenv("FORGD_OTEL_TOKEN_LATER", raising=False)
    app = _app(tmp_path, "[later]", extra_orgs=(
        '- {label: later, id: "00000000-0000-0000-0000-00000000000d", '
        'token: $FORGD_OTEL_TOKEN_LATER}'))
    app.close()


def _two_sinks(tmp_path):
    pol = tmp_path / "policy.yaml"
    pol.write_text(textwrap.dedent(f"""
        privacy: {{hash_salt: test-salt}}
        server: {{store: ""}}
        otel:
          orgs:
            - {{label: prod, id: "{PROD}", token: prod-token-long-enough-to-be-one}}
        sinks:
          - name: first
            type: otlp
            endpoint: https://first.test
          - name: second
            type: otlp
            endpoint: https://second.test
    """), encoding="utf-8")
    app = Collector(load_policy(str(pol)), store=None, late_detectors=[])
    for fwd in app.forwarders:
        fwd.pipeline.sink = FakeSink(max_events=100, max_bytes=10_000_000)
    return app


@pytest.mark.parametrize("where", ["redaction", "offer"])
async def test_a_failing_sink_does_not_stop_the_next_one(tmp_path, monkeypatch, caplog,
                                                         where):
    import json
    import logging

    from conftest import FAKE_AWS_KEY

    from forgd_verdict.sink import redact

    app = _two_sinks(tmp_path)
    first, second = app.forwarders
    logger = logging.getLogger("forgd_verdict")
    logger.addHandler(caplog.handler)
    caplog.set_level(logging.WARNING)

    def boom(*a, **kw):
        raise RuntimeError(f"failed on {FAKE_AWS_KEY}")

    if where == "offer":
        monkeypatch.setattr(first.pipeline, "offer", boom)
    else:
        real = redact.redact_groups

        def redact_groups(groups, plan, *a, **kw):
            if plan is first.plan:
                boom()
            return real(groups, plan, *a, **kw)

        monkeypatch.setattr(redact, "redact_groups", redact_groups)
    body = json.dumps({"resourceLogs": [{"scopeLogs": [{"logRecords": [{
        "attributes": [
            {"key": "event.name", "value": {"stringValue": "claude_code.user_prompt"}},
            {"key": "prompt.id", "value": {"stringValue": f"p{i}"}},
            {"key": "prompt", "value": {"stringValue": f"use {FAKE_AWS_KEY} for turn {i}"}},
        ]} for i in range(3)]}]}]}).encode()
    try:
        status, _ = await ASGIClient(app).post(
            "/v1/logs", body, {"authorization": "Bearer " + "prod-token-long-enough-to-be-one",
                               "content-type": "application/json"})
        assert status == 200
        second.pipeline.flush()
        first.pipeline.flush()
    finally:
        logger.removeHandler(caplog.handler)
        app.close()
    assert len(second.pipeline.sink.events) == 3
    assert first.pipeline.sink.events == []
    (failed,) = [r for r in caplog.records if r.getMessage() == "sink hook failed"]
    assert failed.fields["sink"] == "first"
    logged = "\n".join(f"{r.getMessage()} {json.dumps(getattr(r, 'fields', None))}"
                       for r in caplog.records)
    assert FAKE_AWS_KEY not in logged
    assert FAKE_AWS_KEY not in repr(second.pipeline.sink.events)


# -- a fleet token: the scope follows the org a batch is filed under ---------

FLEET = "fleet-token-long-enough-to-be-one"


def _fleet_app(tmp_path, sink_orgs: str):
    return _app(tmp_path, sink_orgs, extra_orgs=(
        f'- {{label: laptops, ids: ["{PROD}", "{DEV}"], token: {FLEET}}}'))


async def _post(app, org_id, token=FLEET):
    import json

    body = json.dumps({"resourceLogs": [{"scopeLogs": [{"logRecords": [{
        "attributes": [
            {"key": "event.name", "value": {"stringValue": "claude_code.user_prompt"}},
            {"key": "prompt", "value": {"stringValue": "hello there"}},
            {"key": "organization.id", "value": {"stringValue": org_id}},
        ]}]}]}]}).encode()
    status, _ = await ASGIClient(app).post(
        "/v1/logs", body, {"authorization": f"Bearer {token}",
                           "content-type": "application/json"})
    assert status == 200


async def test_an_org_scope_forwards_that_org_from_a_fleet_token(tmp_path):
    app = _fleet_app(tmp_path, "[prod]")
    try:
        await _post(app, PROD)
        await _post(app, DEV)
        assert _forwarded_orgs(app) == [PROD]
        assert app.forwarders[0].out_of_scope == 1
        assert app.forwarders[0].stats()["orgs"] == ["prod"]
    finally:
        app.close()


async def test_a_fleet_label_scope_forwards_every_org_in_its_set(tmp_path):
    app = _fleet_app(tmp_path, "[laptops]")
    try:
        await _post(app, PROD)
        await _post(app, DEV)
        await _post(app, PROD, token="prod-token-long-enough-to-be-one")
        assert _forwarded_orgs(app) == [PROD, DEV, PROD]
    finally:
        app.close()


async def test_a_single_org_scope_through_its_own_token_is_unchanged(tmp_path):
    app = _fleet_app(tmp_path, "[dev]")
    try:
        await _post(app, PROD, token="prod-token-long-enough-to-be-one")
        await _post(app, DEV, token="dev-token-long-enough-to-be-one")
        assert _forwarded_orgs(app) == [DEV]
        assert app.forwarders[0].out_of_scope == 1
    finally:
        app.close()
