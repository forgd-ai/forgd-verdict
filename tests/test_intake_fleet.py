"""Intake for a managed fleet: one token per fleet, the device as a field.

An intake client is a credential and never an org. Records file under the
org bound to the credential, else the deployment's only org, else the
unattributed partition; clients and devices are Event Log filters.
"""

from __future__ import annotations

import logging

import pytest
from conftest import ASGIClient

from forgd_verdict.dashboard.app import Dashboard
from forgd_verdict.intake.app import Intake
from forgd_verdict.metadata import MetadataGuard
from forgd_verdict.models import pseudonym
from forgd_verdict.policy import DEFAULT_POLICY, Policy, _deep_merge
from forgd_verdict.store import LocalFileStore
from forgd_verdict.store.base import (
    ORG_UNATTRIBUTED,
    SOURCE_CODE_HOOK,
    FindingRow,
    VerdictRecord,
)
from forgd_verdict.store.views import event_page

SALT = "s"
# Set through the environment, as a deployment would.
ORG_PROD = "org-prod-fixture"
ORG_DEV = "org-dev-fixture"

FLEET_TOKEN = "fleet-token-current-0123456789abcdef"
FLEET_TOKEN_OLD = "fleet-token-previous-0123456789abcdef"
ALICE_TOKEN = "intake-token-for-alice-0123456789"
AGENT_TOKEN = "intake-token-for-agent-0123456789"

DEVICE_HEADER = "x-forgd-device"


@pytest.fixture(autouse=True)
def org_env(monkeypatch):
    monkeypatch.setenv("FORGD_ORG_ID_PROD", ORG_PROD)
    monkeypatch.setenv("FORGD_ORG_ID_DEV", ORG_DEV)
    monkeypatch.setenv("FORGD_INTAKE_FLEET_TOKEN", FLEET_TOKEN)
    monkeypatch.setenv("FORGD_INTAKE_FLEET_TOKEN_PREVIOUS", FLEET_TOKEN_OLD)


def _org(org_id: str) -> str:
    return pseudonym(org_id, SALT, "org")


ORGS_BOTH = [{"id": "$FORGD_ORG_ID_PROD", "label": "Prod"},
             {"id": "$FORGD_ORG_ID_DEV", "label": "Dev"}]
ORGS_PROD = [{"id": "$FORGD_ORG_ID_PROD", "label": "Prod"}]


def _fleet(name="corp-laptops", tokens=("$FORGD_INTAKE_FLEET_TOKEN",),
           org="$FORGD_ORG_ID_PROD", **kw) -> dict:
    return {"name": name, "tokens": list(tokens), "org": org, **kw}


def _policy(*, orgs=ORGS_BOTH, fleet=None, clients=None, **intake) -> Policy:
    cfg: dict = {"fleet": [_fleet()] if fleet is None else fleet,
                 "clients": clients or []}
    cfg.update(intake)
    return Policy(raw=_deep_merge(DEFAULT_POLICY, {
        "orgs": orgs, "intake": cfg, "privacy": {"hash_salt": SALT}}))


def _app(tmp_path, policy: Policy) -> Intake:
    return Intake(policy, store=LocalFileStore(tmp_path / "store", instance="t"))


def _rec(**kw) -> VerdictRecord:
    return VerdictRecord(
        source=SOURCE_CODE_HOOK,
        observed_at="2026-09-20T10:00:00Z",
        surface="claude-code-local",
        action="deny",
        findings=[FindingRow("regex:aws-access-key", "block", "cmd", "h1")],
        findings_count=1,
        **kw,
    )


def _ndjson(*records) -> bytes:
    return ("\n".join(r.to_json() for r in records) + "\n").encode()


def _headers(token: str, device: str | None = None) -> dict:
    h = {"authorization": f"Bearer {token}",
         "content-type": "application/x-ndjson"}
    if device is not None:
        h[DEVICE_HEADER] = device
    return h


async def _ship(app, token, device=None, n=1):
    return await ASGIClient(app).post(
        "/intake", _ndjson(*[_rec() for _ in range(n)]), _headers(token, device))


def _stored(app) -> list[VerdictRecord]:
    app.flush()
    return list(app.store.read_verdicts())


# -- 1. 900 devices, one org ---------------------------------------------


@pytest.mark.serial  # 900 requests, each running the guard's gitleaks subprocess
async def test_900_devices_on_one_fleet_token_file_under_the_bound_org(tmp_path):
    policy = _policy()
    policy.raw["detectors"]["gitleaks"]["timeout_ms"] = 60000
    app = _app(tmp_path, policy)
    try:
        for i in range(900):
            status, body = await _ship(app, FLEET_TOKEN, f"d{i:012x}")
            assert status == 200, body
        stored = _stored(app)
        assert len(stored) == 900
        assert {r.org for r in stored} == {_org(ORG_PROD)}
        assert {r.device for r in stored} == {f"d{i:012x}" for i in range(900)}
        assert {r.client for r in stored} == {"corp-laptops"}
    finally:
        app.close()


def test_the_org_selector_lists_only_configured_orgs_with_a_fleet():
    labels = dict(_policy().partition_labels())
    assert labels == {_org(ORG_PROD): "Prod", _org(ORG_DEV): "Dev"}


# -- 2. mixed clients -----------------------------------------------------


def _mixed_policy() -> Policy:
    return _policy(clients=[
        {"name": "alice-laptop", "token": ALICE_TOKEN, "org": "$FORGD_ORG_ID_PROD"},
        {"name": "billing-agent", "token": AGENT_TOKEN, "agent": True,
         "org": "$FORGD_ORG_ID_DEV"},
    ])


async def _write_mixed(app):
    assert (await _ship(app, ALICE_TOKEN))[0] == 200
    assert (await _ship(app, AGENT_TOKEN))[0] == 200
    for i in range(3):
        assert (await _ship(app, FLEET_TOKEN, f"d{i:012x}"))[0] == 200
    app.flush()


def test_no_client_name_is_an_org_with_mixed_clients():
    labels = dict(_mixed_policy().partition_labels())
    assert set(labels) == {_org(ORG_PROD), _org(ORG_DEV)}
    for name in ("alice-laptop", "billing-agent", "corp-laptops"):
        assert name not in labels
        assert name not in labels.values()


async def test_every_mixed_record_is_reachable_under_its_org_by_client(tmp_path):
    app = _app(tmp_path, _mixed_policy())
    try:
        await _write_mixed(app)
        store = app.store
        expect = {"alice-laptop": (_org(ORG_PROD), 1),
                  "billing-agent": (_org(ORG_DEV), 1),
                  "corp-laptops": (_org(ORG_PROD), 3)}
        for client, (org, n) in expect.items():
            found = event_page(store, None, {org}, client=client).records
            assert len(found) == n, client
            assert {r.client for r in found} == {client}
        assert {r.org for r in _stored(app)} <= {_org(ORG_PROD), _org(ORG_DEV)}
    finally:
        app.close()


async def test_the_dashboard_shows_no_client_as_an_org_tab(tmp_path):
    policy = _mixed_policy()
    app = _app(tmp_path, policy)
    try:
        await _write_mixed(app)
        dash = Dashboard(app.store, org_labels=policy.partition_labels())
        for path in ("/", "/events"):
            status, html = await ASGIClient(dash).get(path)
            assert status == 200, path
            for name in ("alice-laptop", "billing-agent", "corp-laptops"):
                assert f'value="{name}"' not in html, (path, name)
                assert f"org={name}" not in html, (path, name)
        status, html = await ASGIClient(dash).get(
            f"/events?org={_org(ORG_DEV)}&client=billing-agent")
        assert status == 200
        assert "billing-agent" in html
        assert "d000000000000" not in html
    finally:
        app.close()


# -- 3. device filter -----------------------------------------------------


async def test_each_device_can_be_filtered_in_the_event_log(tmp_path):
    policy = _policy()
    app = _app(tmp_path, policy)
    try:
        for i in range(5):
            assert (await _ship(app, FLEET_TOKEN, f"d{i:012x}", n=i + 1))[0] == 200
        app.flush()
        for i in range(5):
            found = event_page(app.store, None, {_org(ORG_PROD)},
                               device=f"d{i:012x}").records
            assert len(found) == i + 1
            assert {r.device for r in found} == {f"d{i:012x}"}

        dash = Dashboard(app.store, org_labels=policy.partition_labels())
        status, html = await ASGIClient(dash).get(
            f"/events?org={_org(ORG_PROD)}&device=d000000000003")
        assert status == 200
        assert "d000000000003" in html
        assert "d000000000002" not in html and "d000000000004" not in html
    finally:
        app.close()


async def test_a_record_cannot_choose_its_own_device_or_client(tmp_path):
    app = _app(tmp_path, _policy())
    try:
        forged = _rec()
        body = forged.to_json().replace(
            "{", '{"device": "someone-else", "client": "alice-laptop", ', 1)
        status, _ = await ASGIClient(app).post(
            "/intake", (body + "\n").encode(), _headers(FLEET_TOKEN, "d000000000001"))
        assert status == 200
        (stored,) = _stored(app)
        assert stored.device == "d000000000001"
        assert stored.client == "corp-laptops"
    finally:
        app.close()


# -- 4. denylist: tests/test_intake_denylist.py ----------------------------


# -- 5. rotation ----------------------------------------------------------


async def test_fleet_token_rotation_accepts_both_then_refuses_the_old(tmp_path):
    both = _policy(fleet=[_fleet(tokens=("$FORGD_INTAKE_FLEET_TOKEN",
                                         "$FORGD_INTAKE_FLEET_TOKEN_PREVIOUS"))])
    app = _app(tmp_path, both)
    try:
        assert (await _ship(app, FLEET_TOKEN, "d000000000001"))[0] == 200
        assert (await _ship(app, FLEET_TOKEN_OLD, "d000000000002"))[0] == 200
        assert {r.client for r in _stored(app)} == {"corp-laptops"}
    finally:
        app.close()

    app = _app(tmp_path / "after", _policy())
    try:
        assert (await _ship(app, FLEET_TOKEN, "d000000000001"))[0] == 200
        status, _ = await _ship(app, FLEET_TOKEN_OLD, "d000000000002")
        assert status == 401
    finally:
        app.close()


# -- 6. legacy per-laptop client -----------------------------------------


async def test_a_legacy_client_files_under_the_only_org_and_warns(tmp_path, caplog):
    caplog.set_level(logging.WARNING, logger="forgd_verdict")
    policy = _policy(orgs=ORGS_PROD, fleet=[],
                     clients=[{"name": "alice-laptop", "token": ALICE_TOKEN}])
    app = _app(tmp_path, policy)
    try:
        assert any("intake.fleet" in r.getMessage() or
                   "intake.fleet" in str(getattr(r, "fields", ""))
                   for r in caplog.records if r.levelno >= logging.WARNING)
        assert (await _ship(app, ALICE_TOKEN))[0] == 200
        (stored,) = _stored(app)
        assert stored.org == _org(ORG_PROD)
        assert stored.client == "alice-laptop"
    finally:
        app.close()


async def test_a_legacy_client_with_org_files_under_that_org(tmp_path):
    policy = _policy(fleet=[], clients=[
        {"name": "alice-laptop", "token": ALICE_TOKEN, "org": "$FORGD_ORG_ID_DEV"}])
    app = _app(tmp_path, policy)
    try:
        assert (await _ship(app, ALICE_TOKEN))[0] == 200
        (stored,) = _stored(app)
        assert stored.org == _org(ORG_DEV)
    finally:
        app.close()


async def test_a_legacy_client_with_several_orgs_and_no_binding_is_unattributed(
        tmp_path):
    policy = _policy(fleet=[], clients=[{"name": "alice-laptop", "token": ALICE_TOKEN}])
    app = _app(tmp_path, policy)
    try:
        assert (await _ship(app, ALICE_TOKEN))[0] == 200
        (stored,) = _stored(app)
        assert stored.org == ORG_UNATTRIBUTED
        assert stored.client == "alice-laptop"
    finally:
        app.close()


# -- 7. unknown device ----------------------------------------------------


async def test_a_fleet_record_with_no_device_is_flagged_and_counted(tmp_path):
    app = _app(tmp_path, _policy(fleet=[_fleet(require_device=False)]))
    try:
        assert (await _ship(app, FLEET_TOKEN))[0] == 200
        assert (await _ship(app, FLEET_TOKEN, "not a device id!"))[0] == 200
        assert app.stats()["counts"].get("device_missing") == 2
        assert all(r.device is None for r in _stored(app))
    finally:
        app.close()


async def test_a_never_seen_device_is_counted_once(tmp_path):
    app = _app(tmp_path, _policy())
    try:
        await _ship(app, FLEET_TOKEN, "d000000000001")
        await _ship(app, FLEET_TOKEN, "d000000000001")
        await _ship(app, FLEET_TOKEN, "d000000000002")
        assert app.stats()["counts"].get("device_first_seen") == 2
    finally:
        app.close()


# -- 8. guard cost --------------------------------------------------------


async def test_intake_guard_calls_are_constant_per_request(tmp_path, monkeypatch):
    calls = {"n": 0}
    real = MetadataGuard.clean

    def counting(self, *a, **kw):
        calls["n"] += 1
        return real(self, *a, **kw)

    monkeypatch.setattr(MetadataGuard, "clean", counting)
    app = _app(tmp_path, _policy(fleet=[], clients=[
        {"name": "alice-laptop", "token": ALICE_TOKEN}]))
    findings = [FindingRow("regex:aws-access-key", "block", f"cmd{i}", "h1")
                for i in range(3)]

    async def cost(n: int) -> int:
        calls["n"] = 0
        records = [_rec() for _ in range(n)]
        for r in records:
            r.findings = list(findings)
            r.findings_count = len(findings)
        status, _ = await ASGIClient(app).post(
            "/intake", _ndjson(*records), _headers(ALICE_TOKEN))
        assert status == 200
        return calls["n"]

    try:
        one, many = await cost(1), await cost(100)
        assert many == one, (one, many)
    finally:
        app.close()


# -- the hook names its device -------------------------------------------


def test_the_shipper_sends_the_namespace_its_records_carry(tmp_path, monkeypatch):
    import io
    import json as _json

    from forgd_verdict.hook.device import device_salt, salt_namespace
    from forgd_verdict.hook.ship import run_ship
    from forgd_verdict.store.spool import Spool

    sent = []

    class Resp(io.BytesIO):
        status = 200

        def __enter__(self):
            return self

        def __exit__(self, *a):
            return False

    def fake_open(req, timeout, ca_file=None):
        sent.append({k.lower(): v for k, v in req.header_items()})
        return Resp(_json.dumps({"accepted": 1, "rejected": 0}).encode())

    monkeypatch.setattr("forgd_verdict.hook.ship.open_url", fake_open)
    spool_dir = tmp_path / "state" / "spool"
    Spool(str(spool_dir)).append(_rec())
    policy = Policy(raw={"hook": {"ship_endpoint": "https://intake.example/intake",
                                  "ship_token": FLEET_TOKEN}})
    run_ship(policy, spool_root=str(spool_dir))

    expected = salt_namespace(device_salt(spool_dir.parent))
    assert expected.startswith("d")
    assert sent and sent[0][DEVICE_HEADER] == expected


async def test_a_secret_shaped_device_id_is_not_stored(tmp_path):
    from conftest import FAKE_AWS_KEY

    app = _app(tmp_path, _policy())
    try:
        status, body = await _ship(app, FLEET_TOKEN, FAKE_AWS_KEY)
        assert (status, body) == (403, {"error": "device_required"})
    finally:
        app.close()
    app = _app(tmp_path / "optional", _policy(fleet=[_fleet(require_device=False)]))
    try:
        assert (await _ship(app, FLEET_TOKEN, FAKE_AWS_KEY))[0] == 200
        (stored,) = _stored(app)
        assert FAKE_AWS_KEY not in stored.to_json()
    finally:
        app.close()


def test_the_batched_guard_cleans_what_the_per_record_guard_did():
    from conftest import DETECTORS, FAKE_AWS_KEY, FAKE_GITHUB_TOKEN

    guard = MetadataGuard(list(DETECTORS), SALT)
    records = [
        _rec(request_id=f"r{i}", actor_hash=FAKE_AWS_KEY if i % 2 else "a",
             tiers_dropped=["gitleaks", FAKE_GITHUB_TOKEN] if i == 1 else [])
        for i in range(4)]
    records[2].findings = [FindingRow("regex:aws-access-key", "block",
                                      f"cmd:{FAKE_AWS_KEY}", "h1"),
                           FindingRow("regex:x", "warn", "l" * 2000, "h2")]
    batched = guard.records(records, untrusted=True)
    single = [guard.record(r, untrusted=True) for r in records]
    assert batched == single
    for r in batched:
        assert FAKE_AWS_KEY not in r.to_json() and FAKE_GITHUB_TOKEN not in r.to_json()


# -- a fleet with no way to deny one device ----------------------------------


def _denylist_warnings(caplog):
    return [r for r in caplog.records if r.levelno >= logging.WARNING
            and "one device cannot be denied" in r.getMessage()]


def test_a_fleet_with_runtime_overrides_off_warns_at_startup(tmp_path, caplog):
    caplog.set_level(logging.WARNING, logger="forgd_verdict")
    app = _app(tmp_path, _policy())
    try:
        assert not app.overrides.enabled
        (warning,) = _denylist_warnings(caplog)
        assert warning.fields["fleets"] == ["corp-laptops"]
    finally:
        app.close()


def test_clients_alone_do_not_warn_about_the_denylist(tmp_path, caplog):
    caplog.set_level(logging.WARNING, logger="forgd_verdict")
    app = _app(tmp_path, _policy(fleet=[], clients=[
        {"name": "alice-laptop", "token": ALICE_TOKEN}]))
    try:
        assert not _denylist_warnings(caplog)
    finally:
        app.close()


def test_the_policy_tab_hides_a_literal_org_id_under_intake():
    """`intake.fleet[].org` and `intake.clients[].org` take an org id like
    `orgs[].id`, so a literal one is replaced on the Policy tab."""
    from forgd_verdict.policy import ORG_ID_PLACEHOLDER, Policy, redacted

    literal = "0" * 8 + "-" + "1" * 4 + "-" + "2" * 4 + "-" + "3" * 4 + "-" + "4" * 12
    shown = redacted(Policy(raw={
        "orgs": [{"id": literal}],
        "intake": {"fleet": [{"name": "f", "tokens": ["$T"], "org": literal}],
                   "clients": [{"name": "a", "token": "$T2", "org": literal}]},
    }))
    assert literal not in str(shown)
    assert shown["intake"]["fleet"][0]["org"] == ORG_ID_PLACEHOLDER
    assert shown["intake"]["clients"][0]["org"] == ORG_ID_PLACEHOLDER


@pytest.mark.parametrize("header", ["Alices-MacBook-Pro.local", "DABCDEF012345", "d12345", "d0123456789abcd"])
def test_a_device_header_not_in_the_hook_form_is_no_device(header):
    """Only "d" and 12 hex characters is a device id; a machine name, which can
    carry a person's name, is never stored."""
    from forgd_verdict.intake.verify import DEVICE_HEADER, device_id

    assert device_id({DEVICE_HEADER: header}) is None
    assert device_id({DEVICE_HEADER: "d0123456789ab"}) == "d0123456789ab"
