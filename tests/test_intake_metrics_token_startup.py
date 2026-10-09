"""The intake refuses a weak metrics token at startup, as the verdict
server and the collector do."""

from __future__ import annotations

import pytest
from test_intake_fleet import _policy

from forgd_verdict.intake.app import Intake


def test_a_short_metrics_token_stops_the_intake(tmp_path):
    policy = _policy()
    policy.raw["server"]["metrics_token"] = "short-token"
    with pytest.raises(ValueError, match="metrics_token"):
        Intake(policy, store=None)


def test_a_strong_metrics_token_starts_the_intake():
    policy = _policy()
    policy.raw["server"]["metrics_token"] = "m" * 32
    app = Intake(policy, store=None)
    try:
        assert app._metrics_token == "m" * 32
    finally:
        app.close()
