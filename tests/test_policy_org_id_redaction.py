"""Every place the policy takes an org id goes through one redaction.

The Policy tab and `forgd-verdict policy` show the effective policy. An org
id is not a credential, but it names a customer, so a literal one written
anywhere the policy takes an org id is replaced and a `$FORGD_ORG_ID_*`
reference is shown as written.
"""

from __future__ import annotations

import pytest

from forgd_verdict.orgregistry import referenced_orgs
from forgd_verdict.policy import ORG_ID_PLACEHOLDER, Policy, redacted


def _literal(n: int) -> str:
    return f"{n:08x}-1111-4111-8111-{n:012x}"


# (where, a function that plants org id `v` there)
PLACES = {
    "orgs[].id": lambda v: {"orgs": [{"id": v}]},
    "compliance.org_id": lambda v: {"compliance": {"org_id": v}},
    "compliance.orgs[].id": lambda v: {"compliance": {"orgs": [{"id": v}]}},
    "otel.orgs[].id": lambda v: {"otel": {"orgs": [{"id": v}]}},
    "otel.orgs[].ids": lambda v: {"otel": {"orgs": [{"ids": ["$FORGD_ORG_ID_X", v]}]}},
    "dashboard.entitlements.map[].orgs": lambda v: {
        "dashboard": {"entitlements": {"map": [{"group": "g", "orgs": [v]}]}}},
    "intake.fleet[].org": lambda v: {"intake": {"fleet": [{"name": "f", "org": v}]}},
    "intake.fleet[].orgs": lambda v: {
        "intake": {"fleet": [{"name": "f", "orgs": ["$FORGD_ORG_ID_X", v]}]}},
    "intake.clients[].org": lambda v: {"intake": {"clients": [{"name": "a", "org": v}]}},
}


@pytest.mark.parametrize("where", sorted(PLACES))
def test_a_literal_org_id_is_replaced_wherever_the_policy_takes_one(where):
    literal = _literal(7)
    shown = redacted(Policy(raw=PLACES[where](literal)))
    assert literal not in str(shown)
    assert ORG_ID_PLACEHOLDER in str(shown)


@pytest.mark.parametrize("where", sorted(PLACES))
def test_an_org_id_reference_is_shown_as_written(where):
    shown = redacted(Policy(raw=PLACES[where]("$FORGD_ORG_ID_PROD")))
    assert "$FORGD_ORG_ID_PROD" in str(shown)
    assert ORG_ID_PLACEHOLDER not in str(shown)


def test_every_place_the_org_registry_reads_is_covered_here():
    """A new org id location read by `referenced_orgs` needs a row in PLACES
    and a branch in the redaction; this fails until it has both."""
    raw: dict = {}
    for n, where in enumerate(sorted(PLACES)):
        for key, value in PLACES[where](_literal(n)).items():
            if isinstance(value, dict) and isinstance(raw.get(key), dict):
                _merge(raw[key], value)
            elif isinstance(value, list) and isinstance(raw.get(key), list):
                raw[key] += value
            else:
                raw[key] = value
    shown = str(redacted(Policy(raw=raw)))
    for org_id in referenced_orgs(Policy(raw=raw)):
        assert org_id not in shown


def _merge(into: dict, more: dict) -> None:
    for key, value in more.items():
        if isinstance(value, dict) and isinstance(into.get(key), dict):
            _merge(into[key], value)
        elif isinstance(value, list) and isinstance(into.get(key), list):
            into[key] += value
        else:
            into[key] = value
