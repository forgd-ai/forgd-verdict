"""docs/PLATFORM.md's intake paragraphs name the counters and bounds the
intake has, and policy.yaml's `intake:` comment names its refusals."""

from __future__ import annotations

import inspect
from pathlib import Path

import pytest

from forgd_verdict.hook import ship
from forgd_verdict.intake import app as intake_app

ROOT = Path(__file__).resolve().parent.parent
COUNTERS = ["store_timeout", "write_busy", "write_in_flight", "duplicate_batch",
            "late_landed", "too_many_records", "store_error"]


def _intake_section() -> str:
    text = (ROOT / "docs" / "PLATFORM.md").read_text(encoding="utf-8")
    start = text.index("The intake (adapter 2)")
    end = text.index("A batch over 10,000 records", start)
    return " ".join(text[start:end].split())


@pytest.mark.parametrize("name", COUNTERS)
def test_each_counter_is_documented_and_emitted(name):
    assert f"`{name}`" in _intake_section()
    src = inspect.getsource(intake_app)
    reason = name.removeprefix("write_")
    assert f'"{name}"' in src or (name != reason and f'"{reason}"' in src)


def test_the_intake_writes_stats_are_documented():
    section = _intake_section()
    assert "`intake_writes`" in section
    assert "`inflight`" in section and "`workers`" in section


def test_the_documented_bounds_are_the_code_bounds():
    section = _intake_section()
    shipper = inspect.signature(ship.ship_to_endpoint).parameters["timeout_s"].default
    assert f"{intake_app.WRITE_WORKERS} threads" in section
    assert f"{intake_app.WRITE_TIMEOUT_S:g} s" in section
    assert f"{shipper:g} s" in section
    assert f"{intake_app.MAX_RECORDS:,}" in section
    assert f"{intake_app.WRITTEN_BATCHES_MAX:,}" in section
    assert "at-least-once" in section


def test_the_scan_drop_is_documented():
    section = _intake_section()
    assert "`store.dropped`" in section
    assert "`intake.store_max_queue`" in section
    assert "after two retries" in section


def test_policy_yaml_names_the_intakes_refusals():
    text = (ROOT / "policy.yaml").read_text(encoding="utf-8")
    start = text.index("\nintake:\n")
    comment = " ".join(text[start:text.index("# store_batch_size", start)].split())
    assert "413" in comment and f"{intake_app.MAX_RECORDS:,}" in comment
    assert "503" in comment and "timeout" in comment
