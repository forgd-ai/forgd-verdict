"""A shipped record keeps only the fields the real hook writes.

A fleet token is shared by every laptop, so a field a shipped record sets
is one any of them can set. `hook/cli.py` `_spool` never writes
`cache_hit`, `budget_exceeded`, `shadow_action`, the timings or the body
counts; a shipped allow carrying any of them moved the summary's cache,
budget, would-deny and latency figures, and `budget_exceeded` or a shadow
deny kept an allow out of its tally row. The intake drops them, so a
shipped allow folds and counts the same whatever the laptop claims.
"""

from __future__ import annotations

import dataclasses

from conftest import FAKE_AWS_KEY
from test_intake_fleet import org_env  # noqa: F401
from test_intake_writer_fields import _hook_rec, _ship
from test_spool import hook_policy

from forgd_verdict.hook.cli import run
from forgd_verdict.store.base import FindingRow, VerdictRecord
from forgd_verdict.store.query import build_summary
from forgd_verdict.store.spool import Spool
from forgd_verdict.store.tally import weight

# Written by the hook only when a tier is dropped, which the probe's runs
# do not do.
HOOK_WHEN_DROPPED = {"tiers_dropped"}
# Set on a shipped record by the intake, whatever the laptop sent.
INTAKE_BOUND = {"observed_at", "tenant_hash", "fleet_orgs", "client", "device",
                "surface", "actor_hash", "salt_namespace"}

_DEFAULTS = {f.name: (f.default if f.default is not dataclasses.MISSING
                      else f.default_factory())  # type: ignore[misc]
             for f in dataclasses.fields(VerdictRecord) if f.name != "source"}

# A value of each field's type, unlike its default.
_SET = {
    "request_id": "PreToolUse:Bash:x1", "session_id": "550e8400-e29b-41d4-a716-446655440000",
    "session_started_at": "2026-10-01T00:00:00Z", "session_updated_at": "2026-10-01T00:00:00Z",
    "deleted_at": "2026-10-01T00:00:00Z",
    "surface": "claude-code-local", "tenant_hash": "org_aaaaaaaaaa", "actor_hash": "user_x",
    "salt_namespace": "d0123456789ab", "client": "c", "device": "d000000000009",
    "fleet_orgs": ["org_aaaaaaaaaa"], "reported_as": "x", "model": "claude-x",
    "body_bytes": 10, "messages_total": 3, "messages_scanned": 2, "action": "allow",
    "shadow_action": "deny", "reference_id": "ABC123", "event": "tool_call",
    "scan_ms": 1.5, "total_ms": 2.5,
    "cache_hit": True, "budget_exceeded": True, "tiers_dropped": ["gitleaks"],
    "build": "0.46.0", "tally": 7, "findings_count": 1,
    "findings": [FindingRow("regex:aws-access-key", "block", "cmd", "h1")],
    "schema_version": 1, "observed_at": "2026-10-01T00:00:00Z",
}


def _hook_fields(tmp_path) -> set[str]:
    """The fields the real hook sets to something other than the default,
    over an allow and a deny."""
    policy = hook_policy(tmp_path)
    run({"hook_event_name": "UserPromptSubmit", "session_id": "s1",
         "prompt": "hello there"}, policy)
    run({"hook_event_name": "PreToolUse", "session_id": "s1", "tool_name": "Bash",
         "tool_use_id": "toolu-1", "tool_input": {"command": f"echo {FAKE_AWS_KEY}"}},
        policy)
    spool = Spool(tmp_path / "spool")
    records = [r for p in spool.claim() for r in Spool.read(p)]
    assert {r.action for r in records} == {"allow", "deny"}
    return {name for r in records for name, default in _DEFAULTS.items()
            if getattr(r, name) != default}


def test_every_field_is_set_in_the_probe():
    assert set(_SET) == set(_DEFAULTS), set(_DEFAULTS) ^ set(_SET)


async def test_a_shipped_record_keeps_only_what_the_hook_writes(tmp_path):
    hook = _hook_fields(tmp_path / "hook")
    assert {"cache_hit", "budget_exceeded", "shadow_action", "scan_ms"}.isdisjoint(hook)
    _, [stored] = await _ship(tmp_path / "intake", _hook_rec(action="deny", **{
        k: v for k, v in _SET.items() if k != "action"}))
    unexpected = {name for name, default in _DEFAULTS.items()
                  if name not in hook | HOOK_WHEN_DROPPED | INTAKE_BOUND and getattr(stored, name) != default}
    # `model` is kept within its pattern, as before; it moves no count.
    assert unexpected <= {"model"}, unexpected


async def test_shipped_allows_fold_into_one_row_whatever_they_claim(tmp_path):
    claims = [{}, {"cache_hit": True}, {"budget_exceeded": True},
              {"shadow_action": "deny"}, {"shadow_action": "allow"},
              {"scan_ms": 40.0, "total_ms": 80.0}, {"cache_hit": False}]
    sent = [_hook_rec(action="allow", findings=[], findings_count=0,
                      request_id=f"PreToolUse:Bash:x{i}", **kw)
            for i, kw in enumerate(claims)]
    _, stored = await _ship(tmp_path, *sent)
    assert len(stored) == 1 and weight(stored[0]) == len(claims)
    s = build_summary(stored)
    assert (s.cache_hits, s.budget_exceeded, s.would_deny) == (0, 0, 0)
