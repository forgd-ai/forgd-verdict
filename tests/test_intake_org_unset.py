"""A credential with no `org:` files under the deployment's only org only
when every org the policy names resolved. One unset `$FORGD_ORG_ID_<NAME>`
would otherwise leave one org standing and file the whole fleet under it."""

from __future__ import annotations

import logging
import uuid

import pytest

from forgd_verdict.intake.app import Intake
from forgd_verdict.intake.verify import org_partition
from forgd_verdict.policy import DEFAULT_POLICY, Policy, _deep_merge
from forgd_verdict.store import LocalFileStore
from forgd_verdict.store.base import ORG_UNATTRIBUTED, pseudonym

SALT = "s"
TOKEN = "intake-token-for-alice-0123456789"
PROD = {"id": "$FORGD_ORG_ID_PROD", "label": "Prod"}
DEV = {"id": "$FORGD_ORG_ID_DEV", "label": "Dev"}


@pytest.fixture
def ids(monkeypatch):
    """Synthetic org ids, in the environment only."""
    out = {"PROD": str(uuid.uuid4()), "DEV": str(uuid.uuid4())}
    for name in out:
        monkeypatch.delenv(f"FORGD_ORG_ID_{name}", raising=False)

    def set_(*names):
        for name in names:
            monkeypatch.setenv(f"FORGD_ORG_ID_{name}", out[name])
    set_.ids = out
    return set_


def _policy(orgs, otel=None) -> Policy:
    raw = {"orgs": orgs, "privacy": {"hash_salt": SALT},
           "intake": {"clients": [{"name": "alice-laptop", "token": TOKEN}]}}
    if otel is not None:
        raw["otel"] = {"orgs": otel}
    return Policy(raw=_deep_merge(DEFAULT_POLICY, raw))


def _partition(policy) -> str:
    return org_partition(policy, "intake.clients[0]", {"name": "alice-laptop"})


def _start(tmp_path, policy, caplog) -> list[str]:
    caplog.set_level(logging.WARNING, logger="forgd_verdict")
    Intake(policy, store=LocalFileStore(tmp_path, instance="t")).close()
    return [r.getMessage() + " " + str(getattr(r, "fields", ""))
            for r in caplog.records if r.levelno >= logging.WARNING]


def _unset_warnings(lines):
    return [line for line in lines if "resolves to nothing" in line]


def test_two_orgs_with_one_unset_is_unattributed_and_warns(ids, tmp_path, caplog):
    ids("PROD")
    policy = _policy([PROD, DEV])
    assert _partition(policy) == ORG_UNATTRIBUTED
    [warning] = _unset_warnings(_start(tmp_path, policy, caplog))
    assert "FORGD_ORG_ID_DEV" in warning
    for value in ids.ids.values():
        assert value not in warning


def test_two_orgs_both_set_is_unattributed(ids, tmp_path, caplog):
    ids("PROD", "DEV")
    policy = _policy([PROD, DEV])
    assert _partition(policy) == ORG_UNATTRIBUTED
    assert _unset_warnings(_start(tmp_path, policy, caplog)) == []


def test_one_org_named_twice_is_that_org(ids, tmp_path, caplog):
    ids("PROD")
    policy = _policy([PROD], otel=[{"id": "$FORGD_ORG_ID_PROD", "token": "$T"}])
    assert _partition(policy) == str(pseudonym(ids.ids["PROD"], SALT, "org"))
    assert _unset_warnings(_start(tmp_path, policy, caplog)) == []


def test_one_org_whose_variable_is_unset_is_unattributed_and_warns(ids, tmp_path,
                                                                   caplog):
    policy = _policy([PROD])
    assert _partition(policy) == ORG_UNATTRIBUTED
    [warning] = _unset_warnings(_start(tmp_path, policy, caplog))
    assert "FORGD_ORG_ID_PROD" in warning


def test_an_explicit_org_that_resolves_to_nothing_still_raises(ids):
    ids("PROD")
    with pytest.raises(ValueError, match="resolves to nothing"):
        org_partition(_policy([PROD]), "intake.clients[0]",
                      {"name": "alice-laptop", "org": "$FORGD_ORG_ID_DEV"})


def test_an_unset_org_does_not_warn_when_every_credential_names_one(ids, tmp_path,
                                                                   caplog):
    ids("PROD")
    policy = _policy([PROD, DEV])
    policy.raw["intake"]["clients"][0]["org"] = "$FORGD_ORG_ID_PROD"
    assert _unset_warnings(_start(tmp_path, policy, caplog)) == []
