"""Every record class a store writes goes through the metadata guard.

`Store.write_*` names the record classes. Each is in `GUARDED_FIELDS`, and
each of its string fields is either guarded there or set by the writer
itself rather than copied from upstream or sender data.
"""

from __future__ import annotations

import dataclasses
import typing

import pytest
from conftest import FAKE_AWS_KEY, FAKE_GITHUB_TOKEN, make_policy
from test_compliance import DENIAL, StubClient

from forgd_verdict.compliance.scanner import ComplianceScanner
from forgd_verdict.detectors.t0_regex import T0RegexDetector
from forgd_verdict.metadata import GUARDED_FIELDS, UNTRUSTED_RECORD_FIELDS, MetadataGuard
from forgd_verdict.store import LocalFileStore
from forgd_verdict.store.base import DenialRecord, Store, VerdictRecord

# String fields a writer sets itself: pseudonyms, enums, detector names, the
# time of the write, the build, and the partition.
WRITER_SET = {
    VerdictRecord: {"source", "observed_at", "tenant_hash", "actor_hash", "salt_namespace",
                    "action", "shadow_action", "reference_id", "build", "client",
                    "tiers_dropped", "fleet_orgs"},
    DenialRecord: {"actor_hash", "tenant_hash", "observed_at"},
}


def _holds_str(hint) -> bool:
    return hint is str or any(_holds_str(a) for a in typing.get_args(hint))


def _written_classes() -> set[type]:
    out = set()
    for name in dir(Store):
        if not name.startswith("write_"):
            continue
        hints = typing.get_type_hints(getattr(Store, name))
        for arg, hint in hints.items():
            if arg == "return":
                continue
            for inner in typing.get_args(hint):
                if dataclasses.is_dataclass(inner):
                    out.add(inner)
    return out


def test_every_record_class_a_store_writes_is_guarded():
    written = _written_classes()
    assert written == {VerdictRecord, DenialRecord}
    assert written <= set(GUARDED_FIELDS)


@pytest.mark.parametrize("cls", [VerdictRecord, DenialRecord])
def test_every_string_field_is_guarded_or_set_by_the_writer(cls):
    hints = typing.get_type_hints(cls)
    strings = {name for name, hint in hints.items() if _holds_str(hint)}
    guarded = set(GUARDED_FIELDS[cls]) | (set(UNTRUSTED_RECORD_FIELDS)
                                          if cls is VerdictRecord else set())
    assert strings - guarded - WRITER_SET[cls] == set()


def test_records_cleans_a_denial():
    guard = MetadataGuard([T0RegexDetector()], "salt")
    denial = DenialRecord(activity_id=f"act_{FAKE_AWS_KEY}",
                          created_at=f"2026-10-07T00:00:00Z {FAKE_GITHUB_TOKEN}",
                          reference_id=f"fv_{FAKE_AWS_KEY}")
    (clean,) = guard.records([denial])
    text = repr(dataclasses.asdict(clean))
    assert FAKE_AWS_KEY not in text and FAKE_GITHUB_TOKEN not in text


def test_records_refuses_a_class_it_has_no_fields_for():
    guard = MetadataGuard([T0RegexDetector()], "salt")

    @dataclasses.dataclass
    class Other:
        value: str

    with pytest.raises(TypeError):
        guard.records([Other("x")])


def test_the_ingest_writes_denials_through_the_guard(tmp_path, monkeypatch):
    from forgd_verdict.compliance import ingest

    activity = {**DENIAL, "id": f"act_{FAKE_AWS_KEY}",
                "reference_id": f"fv_{FAKE_AWS_KEY}",
                "created_at": f"2026-10-07T00:00:00Z {FAKE_GITHUB_TOKEN}"}
    stub = StubClient(activities=[activity])
    policy = make_policy(
        detectors={"gitleaks": {"enabled": False, "severity": "block"}},
        compliance={"state_path": str(tmp_path / "s.json"), "api_key": "sk-ant-api01-x"})
    store = LocalFileStore(tmp_path / "f", instance="t")
    monkeypatch.setattr(ingest, "ComplianceScanner",
                        lambda policy, org=None, store=None, detectors=None:
                        ComplianceScanner(policy, client=stub, org=org, store=store,
                                          detectors=detectors))
    out = ingest.run_ingest(policy, store, include_chats=False, include_denials=True)
    assert out["denials_written"] == 1
    (denial,) = store.read_denials()
    text = repr(dataclasses.asdict(denial))
    assert FAKE_AWS_KEY not in text and FAKE_GITHUB_TOKEN not in text
