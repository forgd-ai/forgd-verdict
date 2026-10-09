"""`forgd-verdict intake` warns at startup only when nothing can authenticate."""

from __future__ import annotations

import pytest
from test_intake_fleet import FLEET_TOKEN, _policy, org_env  # noqa: F401

from forgd_verdict.intake import __main__ as intake_main

ALICE = "intake-token-for-alice-0123456789"


@pytest.fixture
def started(monkeypatch, capsys):
    """Runs `main` up to uvicorn and returns what it wrote to stderr."""
    import uvicorn

    monkeypatch.setattr(uvicorn, "run", lambda *a, **k: None)

    def run(policy):
        monkeypatch.setattr("forgd_verdict.policy.load_policy", lambda *a, **k: policy)
        assert intake_main.main([]) == 0
        return capsys.readouterr().err
    return run


def test_a_fleet_alone_does_not_warn(started):
    assert "refused with 401" not in started(_policy(clients=[]))


def test_a_client_alone_does_not_warn(started):
    assert "refused with 401" not in started(
        _policy(fleet=[], clients=[{"name": "alice-laptop", "token": ALICE}]))


def test_nothing_configured_warns(started):
    assert "refused with 401" in started(_policy(fleet=[], clients=[]))


def test_a_fleet_whose_token_variable_is_unset_warns(started, monkeypatch):
    monkeypatch.delenv("FORGD_INTAKE_FLEET_TOKEN", raising=False)
    monkeypatch.delenv("FORGD_INTAKE_FLEET_TOKEN_PREVIOUS", raising=False)
    err = started(_policy(clients=[]))
    assert "refused with 401" in err
    assert FLEET_TOKEN not in err
