"""A partition component cannot name a path outside its partition.

`org` reaches `partition_path` from an intake client's `name`, which is
config but is copied into the record verbatim. Each backend is driven with
a traversal org and must refuse it without writing anything.
"""

from __future__ import annotations

import pytest
from test_store_conformance import backend, rec  # noqa: F401 - fixture

from forgd_verdict.store import LocalFileStore
from forgd_verdict.store.base import partition_path

TRAVERSE = "x/../../../../escaped"

GOOD = {"prefix": "verdicts", "source": "inference_hook", "day": "2026-09-17",
        "instance": "i-1", "org": "org_abc"}

BAD = ["", ".", "..", "a/b", "a\\b", "a\nb", "a\x00b", "a\x7fb", " pad", "pad ", "\t"]


def _path(**kw) -> str:
    args = {**GOOD, **kw}
    return partition_path(args["prefix"], args["source"], args["day"], args["instance"], 1,
                          args["org"])


def test_a_well_formed_partition_path_is_unchanged():
    assert _path() == ("verdicts/source=inference_hook/org=org_abc/date=2026-09-17/"
                       "i-1-000001.jsonl")
    assert "org=unattributed" in _path(org=None)


@pytest.mark.parametrize("component", sorted(GOOD))
@pytest.mark.parametrize("value", BAD)
def test_partition_path_refuses_a_component_that_is_not_one_segment(component, value):
    if component == "org" and value == "":
        pytest.skip("an empty org is the unattributed partition")
    with pytest.raises(ValueError, match=component):
        _path(**{component: value})


def test_every_backend_refuses_a_traversal_org_and_writes_nothing(backend):  # noqa: F811
    store = backend.make_store("t1")
    with pytest.raises(ValueError, match="org"):
        store.write_verdicts([rec(tenant_hash=TRAVERSE)])
    assert backend.all_objects() == []


def test_the_local_store_creates_nothing_outside_its_root(tmp_path):
    store = LocalFileStore(tmp_path / "store", instance="t")
    with pytest.raises(ValueError):
        store.write_verdicts([rec(tenant_hash=TRAVERSE)])
    assert [p.name for p in tmp_path.iterdir()] == ["store"]
    assert not any(p.is_file() for p in (tmp_path / "store").rglob("*"))


def test_the_local_store_checks_containment_on_its_own(tmp_path, monkeypatch):
    """Independent of `partition_path`: a path that leaves the root is refused
    at the join, before any directory is made."""
    import forgd_verdict.store.local as local

    def unchecked(prefix, source, day, instance, seq, org=None):
        return f"{prefix}/source={source}/org={org}/date={day}/{instance}-{seq:06d}.jsonl"

    monkeypatch.setattr(local, "partition_path", unchecked)
    store = LocalFileStore(tmp_path / "store", instance="t")
    with pytest.raises(ValueError, match="outside the store root"):
        store.write_verdicts([rec(tenant_hash=TRAVERSE)])
    assert [p.name for p in tmp_path.iterdir()] == ["store"]


def test_the_local_store_follows_a_symlink_inside_its_root(tmp_path):
    """Containment is lexical. An operator who links `verdicts` to another
    disk keeps a working store."""
    elsewhere = tmp_path / "elsewhere"
    elsewhere.mkdir()
    root = tmp_path / "store"
    root.mkdir()
    (root / "verdicts").symlink_to(elsewhere)
    store = LocalFileStore(root, instance="t")
    assert store.write_verdicts([rec()]) == 1
    assert list(elsewhere.rglob("*.jsonl"))


class _Scanner:
    def extract_reference_id(self, activity):
        return None


@pytest.mark.parametrize("activity", [
    {"id": "act_1"},
    {"id": "act_2", "created_at": "2026/10/02x"},
    {"id": "act_3", "created_at": "2026-13-45T00:00:00Z"},
    {"id": "act_4", "created_at": "../../escaped"},
])
def test_a_denial_without_a_usable_created_at_still_lands_under_a_date(tmp_path, activity):
    """`created_at` is the Activity Feed's. A missing or malformed one must
    not refuse the whole denial batch."""
    from forgd_verdict.compliance.ingest import activity_to_denial
    from forgd_verdict.store.base import utcnow

    store = LocalFileStore(tmp_path / "store", instance="t")
    denial = activity_to_denial(activity, _Scanner(), salt="s", org_id="o")
    assert store.write_denials([denial]) == 1
    (path,) = (tmp_path / "store").rglob("*.jsonl")
    assert f"/date={denial.observed_at[:10]}/" in path.as_posix()
    assert denial.observed_at[:10] == utcnow()[:10]
    assert [d.activity_id for d in store.read_denials()] == [activity["id"]]


def test_a_denial_keeps_the_date_of_a_valid_created_at(tmp_path):
    from forgd_verdict.compliance.ingest import activity_to_denial

    store = LocalFileStore(tmp_path / "store", instance="t")
    denial = activity_to_denial({"id": "a", "created_at": "2026-09-17T10:00:00Z"}, _Scanner(),
                                salt="s", org_id="o")
    store.write_denials([denial])
    (path,) = (tmp_path / "store").rglob("*.jsonl")
    assert "/date=2026-09-17/" in path.as_posix()


def test_a_denial_with_neither_date_falls_back_to_today():
    from forgd_verdict.store.base import DenialRecord, utcnow

    assert DenialRecord(activity_id="a", created_at="", observed_at="").day == utcnow()[:10]


def test_agent_names_and_managed_labels_refuse_a_trailing_newline():
    from forgd_verdict.managed import scanner
    from forgd_verdict.otel import extract

    assert not extract.AGENT_NAME_OK.fullmatch("agent\n")
    assert extract.AGENT_NAME_OK.fullmatch("agent")
    assert not scanner._NAME_OK.fullmatch("prod\n")
