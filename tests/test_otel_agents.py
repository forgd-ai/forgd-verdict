"""`otel.agents`: Agent SDK agents get their own coverage row."""

from __future__ import annotations

import pytest
from conftest import ASGIClient
from test_otel_collector import ORG, SEEDED, auth, make_policy, stored
from test_otel_payload import logs_json

from forgd_verdict.otel import SURFACE_CODE, SURFACE_OUTLOOK
from forgd_verdict.otel.app import Collector
from forgd_verdict.otel.extract import agent_services, surface_of
from forgd_verdict.otel.payload import OtelRecord
from forgd_verdict.store.local import LocalFileStore


@pytest.fixture(autouse=True)
def _store_in_tmp(tmp_path, monkeypatch):
    monkeypatch.setenv("FORGD_VERDICT_STORE", str(tmp_path / "findings"))
    monkeypatch.setenv("FORGD_HASH_SALT", "test-deployment-salt")


def rec(service: str) -> OtelRecord:
    return OtelRecord(kind="log", name="claude_code.user_prompt", attributes={},
                      resource={"service.name": service})


def batch(service: str):
    return logs_json([{"attributes": {"event.name": "claude_code.user_prompt",
                                      "prompt": f"deploy with {SEEDED}",
                                      "session.id": f"s-{service}", "prompt.id": "t"},
                       "body": ""}],
                     {"service.name": service, "organization.id": ORG})


@pytest.mark.parametrize("service, agents, surface", [
    ("support-triage-agent", {"support-triage-agent"}, "agent:support-triage-agent"),
    ("Support-Triage-Agent", {"support-triage-agent"}, "agent:support-triage-agent"),
    # Undeclared, the substring match files it as a product, which is the
    # misattribution the declaration exists to prevent.
    ("email-triage", set(), SURFACE_OUTLOOK),
    ("email-triage", {"email-triage"}, "agent:email-triage"),
    # Undeclared and matching no product, the `claude_code.` event prefix
    # files it with developers' laptops.
    ("invoice-bot", set(), SURFACE_CODE),
    # Exact match only: a declared name does not claim its neighbours.
    ("invoice-bot-2", {"invoice-bot"}, SURFACE_CODE),
    ("claude-code", {"invoice-bot"}, SURFACE_CODE),
])
def test_a_declared_service_name_is_an_agent_surface(service, agents, surface):
    assert surface_of(rec(service), frozenset(agents)) == surface


def test_the_default_is_no_agents():
    assert agent_services({}) == frozenset()


@pytest.mark.parametrize("bad", ["claude-code", "outlook", "office-agent", "sheet_agent", "Has Space", "../x", "", "a" * 65])
def test_a_bad_declaration_refuses_to_start(bad):
    with pytest.raises(ValueError):
        agent_services({"agents": [bad]})


def test_agents_must_be_a_list():
    with pytest.raises(ValueError):
        agent_services({"agents": "invoice-bot"})


async def test_an_agents_export_lands_in_its_own_row(tmp_path):
    c = Collector(make_policy(agents=["invoice-bot"]),
                  store=LocalFileStore(tmp_path / "findings", instance="t"))
    try:
        client = ASGIClient(c)
        status, _ = await client.post("/v1/logs", batch("invoice-bot"), auth())
        assert status == 200
        await client.post("/v1/logs", batch("claude-code"), auth())
        records = stored(c)
    finally:
        c.close()
    assert sorted(r.surface for r in records) == ["agent:invoice-bot", SURFACE_CODE]
    assert all(r.findings for r in records)


def test_the_collector_refuses_a_bad_declaration():
    with pytest.raises(ValueError):
        Collector(make_policy(agents=["claude-code"]))
