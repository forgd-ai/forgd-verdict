"""The intake's metadata guard runs gitleaks as a subprocess, as the scan
does, so a credential only gitleaks recognises does not reach the store
through any string a sender chose.

Each case plants the token in one field: every string field of a record
shipped to /intake, and every string in a /scan hook payload and agent
frame."""

from __future__ import annotations

import dataclasses
import json
import shutil
import typing

import pytest
from conftest import ASGIClient

from forgd_verdict.intake.app import Intake
from forgd_verdict.metadata import MetadataGuard
from forgd_verdict.policy import DEFAULT_POLICY, Policy, _deep_merge
from forgd_verdict.store import LocalFileStore
from forgd_verdict.store.base import SOURCE_CODE_HOOK, FindingRow, VerdictRecord

pytestmark = pytest.mark.skipif(not shutil.which("gitleaks"),
                                reason="gitleaks binary not installed")

# A GitLab PAT: gitleaks has a rule for it and T0 does not.
TOKEN = "glpat-" + "x7Kq2mNp9wRt4vZs8bLc"
INTAKE_TOKEN = "intake-token-for-alice-0123456789"
SALT = "intake-guard-gitleaks-salt"


def _policy() -> Policy:
    return Policy(raw=_deep_merge(DEFAULT_POLICY, {
        "detectors": {"gitleaks": {"enabled": True, "binary": shutil.which("gitleaks")}},
        "intake": {"clients": [{"name": "alice-laptop", "token": INTAKE_TOKEN}]},
        "privacy": {"hash_salt": SALT}}))


@pytest.fixture
def app(tmp_path, monkeypatch):
    monkeypatch.delenv("FORGD_GITLEAKS_SOCKET", raising=False)
    a = Intake(_policy(), store=LocalFileStore(tmp_path / "store", instance="t"))
    yield a
    a.close()


def _stored(app) -> str:
    app.flush()
    return "\n".join(r.to_json() for r in app.store.read_verdicts("1990-01-01T00:00:00Z", None))


def test_the_token_is_gitleaks_only_and_gitleaks_is_a_subprocess(app):
    detectors = app._detectors()
    (gitleaks,) = [d for d in detectors if d.name == "gitleaks"]
    assert not gitleaks.uses_daemon
    assert MetadataGuard(detectors).matches({"v": TOKEN}) == set()
    assert MetadataGuard(detectors, allow_subprocess=True).matches({"v": TOKEN}) == {"v"}


# -- /intake: every string field of a shipped record ---------------------------


def _string_fields(cls) -> list[str]:
    hints = typing.get_type_hints(cls)
    return [f.name for f in dataclasses.fields(cls)
            if hints[f.name] in (str, str | None, list[str])]


RECORD_FIELDS = _string_fields(VerdictRecord)
FINDING_FIELDS = _string_fields(FindingRow)
# The intake refuses a record whose source is not the hook's or whose action
# is not allow or deny, so the token planted there never reaches the guard;
# asserted below rather than skipped.
REFUSED = {"source", "action"}


def _shipped(field: str | None = None, finding_field: str | None = None) -> VerdictRecord:
    finding = FindingRow("regex:aws-access-key", "block", "cmd", "h1", tool_name="Bash")
    if finding_field is not None:
        finding = dataclasses.replace(finding, **{finding_field: f"x-{TOKEN}"})
    record = VerdictRecord(source=SOURCE_CODE_HOOK, action="deny", findings=[finding],
                           findings_count=1)
    if field is not None:
        value = [f"x-{TOKEN}"] if field == "tiers_dropped" else f"x-{TOKEN}"
        record = dataclasses.replace(record, **{field: value})
    return record


async def _ship(app, record):
    return await ASGIClient(app).post(
        "/intake", (record.to_json() + "\n").encode(),
        {"authorization": f"Bearer {INTAKE_TOKEN}", "content-type": "application/x-ndjson"})


def test_the_field_lists_are_the_schema():
    assert "session_id" in RECORD_FIELDS and "tiers_dropped" in RECORD_FIELDS
    assert set(FINDING_FIELDS) == {"detector", "severity", "locator", "excerpt_hash",
                                   "tool_name"}


@pytest.mark.parametrize("field", RECORD_FIELDS)
async def test_a_shipped_record_field_never_stores_the_token(app, field):
    status, body = await _ship(app, _shipped(field))
    stored = _stored(app)
    assert TOKEN not in json.dumps(body)
    assert TOKEN not in stored
    if field in REFUSED:
        assert status == 400
    else:
        assert status == 200, body
        assert stored.strip(), "the record was stored"


@pytest.mark.parametrize("field", FINDING_FIELDS)
async def test_a_shipped_finding_field_never_stores_the_token(app, field):
    status, body = await _ship(app, _shipped(finding_field=field))
    stored = _stored(app)
    assert TOKEN not in json.dumps(body)
    assert TOKEN not in stored
    if status == 200:
        assert stored.strip()


# -- /scan: every string in a hook payload and an agent frame ---------------------

HOOK_PAYLOAD = {
    "session_id": "550e8400-e29b-41d4-a716-446655440000",
    "prompt_id": "p-1",
    "transcript_path": "/tmp/t.jsonl",
    "cwd": "/repo",
    "permission_mode": "default",
    "hook_event_name": "PreToolUse",
    "tool_name": "Bash",
    "tool_use_id": "toolu_01ABC",
    "tool_input": {"command": "ls", "description": "list"},
}
FRAME = {
    "type": "prompt",
    "session_id": "sess-1",
    "model": "claude-opus-5-5",
    "request_id": "req-1",
    "source": {"application": "triage"},
    "messages": [
        {"role": "user", "content": [{"type": "text", "text": "summarise the notes"}]},
        {"role": "assistant", "content": [
            {"type": "tool_use", "id": "t1", "name": "search", "input": {"q": "notes"}}]},
    ],
}


def _string_paths(value, path=()):
    if isinstance(value, str):
        yield path
    elif isinstance(value, dict):
        for k, v in value.items():
            yield from _string_paths(v, (*path, k))
    elif isinstance(value, list):
        for i, v in enumerate(value):
            yield from _string_paths(v, (*path, i))


def _planted(template, path):
    out = json.loads(json.dumps(template))
    node = out
    for key in path[:-1]:
        node = node[key]
    node[path[-1]] = f"x-{TOKEN}"
    return out


# Values the route matches on rather than carries: planting the token there
# makes the payload a different kind of request, still asserted to store
# nothing raw.
SCAN_CASES = ([("hook", p) for p in _string_paths(HOOK_PAYLOAD)]
              + [("frame", p) for p in _string_paths(FRAME)])


@pytest.mark.parametrize("kind,path", SCAN_CASES,
                         ids=[f"{k}:{'.'.join(map(str, p))}" for k, p in SCAN_CASES])
async def test_a_scan_string_never_stores_the_token(app, kind, path):
    payload = _planted(HOOK_PAYLOAD if kind == "hook" else FRAME, path)
    status, body = await ASGIClient(app).post(
        "/scan", json.dumps(payload).encode(),
        {"authorization": f"Bearer {INTAKE_TOKEN}", "content-type": "application/json"})
    assert TOKEN not in json.dumps(body)
    assert TOKEN not in _stored(app)
    assert status == 200, body
