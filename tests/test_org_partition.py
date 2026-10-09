"""The org on every record, and the partition that follows from it.

The invariant these protect: every adapter that writes must derive the SAME
partition for the same organization. If they disagree, one org appears as
several on a dashboard and an org-scoped read misses most of its own data --
and nothing errors, which is what makes it worth pinning.
"""

from __future__ import annotations

import pytest

from forgd_verdict.policy import Policy
from forgd_verdict.store.base import (
    ORG_UNATTRIBUTED,
    DenialRecord,
    VerdictRecord,
    partition_path,
    path_segment,
    pseudonym,
    verdict_from_log_row,
)

# A fixture UUID, not a real organization. The property under test is that
# every adapter derives the same pseudonym from the same id; which id it is
# does not matter, and a real one in a test file is a real one in git.
ORG_ID = "00000000-1111-2222-3333-444444444444"
SALT = "a-test-salt"


def test_every_adapter_derives_the_same_partition_for_one_org():
    """Adapter 1's `tenant_id` on the hook frame IS the organization UUID, so
    the hook and the configured id agree without translation: the pseudonym
    on a real inference-hook record equals the one computed from the
    configured id.

    Were that ever untrue, one org would silently become two.
    """
    expected = pseudonym(ORG_ID, SALT, "org")

    # Adapter 1 — from the hook frame's tenant_id, via the log row.
    a1 = verdict_from_log_row({"tenant_id": ORG_ID}, SALT)

    # Adapters 3 and 4 — from the configured / asserted org id.
    a3 = VerdictRecord(source="compliance_scan",
                       tenant_hash=pseudonym(ORG_ID, SALT, "org"))
    a4 = VerdictRecord(source="otel_collect",
                       tenant_hash=pseudonym(ORG_ID, SALT, "org"))

    assert a1.tenant_hash == a3.tenant_hash == a4.tenant_hash == expected
    assert a1.org == a3.org == a4.org == expected


def test_the_partition_never_contains_the_real_org_id():
    """The path is as public as the object it names. A blob listing must not
    tell a reader which customers exist."""
    rec = VerdictRecord(source="otel_collect",
                        tenant_hash=pseudonym(ORG_ID, SALT, "org"))
    path = partition_path("verdicts", rec.source, "2026-09-19", "i", 1, rec.org)
    assert ORG_ID not in path
    assert path_segment(path, "org") == rec.org


def test_a_record_with_no_org_is_unattributed_not_dropped():
    assert VerdictRecord(source="inference_hook").org == ORG_UNATTRIBUTED
    assert DenialRecord(activity_id="a", created_at="2026-09-19").org == ORG_UNATTRIBUTED
    path = partition_path("verdicts", "inference_hook", "2026-09-19", "i", 1, None)
    assert "org=unattributed" in path


def test_a_missing_org_segment_reads_as_unattributed():
    """Objects written without an `org=` segment have one path level fewer."""
    legacy = "verdicts/source=inference_hook/date=2026-09-17/i-000001.jsonl"
    assert path_segment(legacy, "org") is None
    assert path_segment(legacy, "date") == "2026-09-17"


def test_labels_resolve_from_policy_and_unknown_orgs_stay_pseudonyms():
    """A label is configuration, so a rename is a config change rather than
    a data migration. An org we are not configured for stays a pseudonym
    rather than becoming a guess."""
    policy = Policy(raw={
        "privacy": {"hash_salt": SALT},
        "orgs": [{"id": ORG_ID, "label": "primary"},
                 {"id": "other-org-uuid"}],
    })
    labels = policy.org_labels()
    assert labels[pseudonym(ORG_ID, SALT, "org")] == "primary"
    # No label configured: left out, never named by its id.
    assert pseudonym("other-org-uuid", SALT, "org") not in labels
    assert "other-org-uuid" not in labels.values()
    assert pseudonym("never-configured", SALT, "org") not in labels


def test_a_label_only_resolves_under_the_salt_the_writers_used():
    """Labels are computed, not stored. A salt change must not silently map
    a label onto the wrong org -- it should map onto none."""
    policy = Policy(raw={"privacy": {"hash_salt": "different-salt"},
                         "orgs": [{"id": ORG_ID, "label": "primary"}]})
    assert pseudonym(ORG_ID, SALT, "org") not in policy.org_labels()


def test_a_summary_can_be_scoped_to_one_org():
    from forgd_verdict.store.query import build_summary

    a = pseudonym("org-a", SALT, "org")
    b = pseudonym("org-b", SALT, "org")
    records = [
        VerdictRecord(source="otel_collect", tenant_hash=a, session_id="1"),
        VerdictRecord(source="otel_collect", tenant_hash=a, session_id="2"),
        VerdictRecord(source="otel_collect", tenant_hash=b, session_id="3"),
    ]
    assert build_summary(records).total_requests == 3
    assert build_summary(records, orgs={a}).total_requests == 2
    assert build_summary(records, orgs={b}).total_requests == 1
    assert build_summary(records).orgs == {a: 2, b: 1}
    # Scoped summaries report only their own org, so a count on the page
    # cannot hint at how much traffic another org has.
    assert build_summary(records, orgs={a}).orgs == {a: 2}


def test_an_unscoped_summary_is_still_the_default():
    """Most deployments configure no entitlement map, and one customer is
    entitled to all of their own orgs. Fail-closed would break them on
    upgrade to protect against a risk they do not have."""
    from forgd_verdict.store.query import build_summary

    assert build_summary([]).scoped_to is None


def test_org_ids_are_read_from_the_environment_not_the_policy_file():
    """An organization UUID names a customer. It is not a credential, but a
    committed config file is the wrong place to enumerate which
    organizations a deployment serves -- and the policy file is committed.

    Pinned as a property of the shipped file, because the failure is one
    careless paste away and nothing else would catch it.
    """
    assert_org_ids_come_from_the_environment("policy.yaml")


def assert_org_ids_come_from_the_environment(path: str) -> None:
    import re

    from forgd_verdict.policy import load_policy

    with open(path, encoding="utf-8") as f:
        raw = f.read()
    uuids = re.findall(
        r"\b[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\b",
        raw,
        re.IGNORECASE,
    )
    assert uuids == [], f"organization UUIDs in {path}: {uuids}"

    policy = load_policy(path)
    lists = [
        policy.orgs,
        policy.otel.get("orgs") or [],
        policy.compliance.get("orgs") or [],
    ]
    for entries in lists:
        for org in entries:
            ids = org["ids"] if isinstance(org.get("ids"), list) else [org.get("id", "")]
            assert all(str(i).startswith("$") for i in ids), org
    intake = policy.raw.get("intake") or {}
    for entry in (intake.get("fleet") or []) + (intake.get("clients") or []):
        assert "org" not in entry or str(entry["org"]).startswith("$"), entry
    # And the single-org fallback key, if a deployment still uses it.
    legacy = str(policy.compliance.get("org_id", ""))
    assert not legacy or legacy.startswith("$")


def test_an_unset_org_id_partitions_as_unattributed_rather_than_literally():
    """The env-var fallback must not write `$FORGD_ORG_ID_PRIMARY` into a
    partition path as if it were an id."""
    from forgd_verdict.models import env_or_literal

    assert env_or_literal("$DEFINITELY_NOT_SET_ANYWHERE") is None


@pytest.mark.parametrize("element", ["00000000-1111-2222-3333-444444444444", "acme-prod"])
def test_a_literal_in_an_otel_ids_list_is_caught(tmp_path, element):
    path = tmp_path / "policy.yaml"
    path.write_text(
        "otel:\n  orgs:\n    - label: laptops\n"
        f'      ids: ["$FORGD_ORG_ID_PROD", "{element}"]\n'
        "      token: $FORGD_OTEL_TOKEN_FLEET\n", encoding="utf-8")
    with pytest.raises(AssertionError):
        assert_org_ids_come_from_the_environment(str(path))


def test_an_otel_ids_list_of_references_passes(tmp_path):
    path = tmp_path / "policy.yaml"
    path.write_text(
        "otel:\n  orgs:\n    - label: laptops\n"
        '      ids: ["$FORGD_ORG_ID_PROD", "$FORGD_ORG_ID_DEV"]\n'
        "      token: $FORGD_OTEL_TOKEN_FLEET\n", encoding="utf-8")
    assert_org_ids_come_from_the_environment(str(path))


def test_every_org_in_an_otel_ids_list_is_referenced(monkeypatch):
    from forgd_verdict.orgregistry import referenced_orgs

    monkeypatch.setenv("FORGD_ORG_ID_DEV", "00000000-0000-0000-0000-00000000000b")
    policy = Policy(raw={"otel": {"orgs": [
        {"label": "laptops", "ids": [ORG_ID, "$FORGD_ORG_ID_DEV"], "token": "t"}]}})
    assert set(referenced_orgs(policy)) == {ORG_ID, "00000000-0000-0000-0000-00000000000b"}
