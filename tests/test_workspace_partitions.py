"""Managed Agents workspaces as their own partition kind.

Adapter 6 files a workspace under `pseudonym(key, salt, "workspace")`. The
registry carries workspaces in their own section from version 2, the
entitlement map grants them by key under `workspaces`, and the dashboard
and connector accept `workspace_` partitions beside `org_` ones. No
workspace key reaches a log, a response or the Policy tab.
"""

from __future__ import annotations

import json
import logging
import types

import pytest
from conftest import ASGIClient, make_policy

from forgd_verdict.connector import tools as T
from forgd_verdict.entitlements import MODE_OIDC_JWT, Principal
from forgd_verdict.models import pseudonym
from forgd_verdict.orgregistry import (
    REGISTRY_STATE_NAMES,
    OrgResolver,
    build_registry,
    partition_kind,
    publish_registry,
)
from forgd_verdict.policy import redacted
from forgd_verdict.store.base import SOURCE_MANAGED_SCAN, VerdictRecord
from forgd_verdict.store.local import LocalFileStore

SALT = "writer-salt-0123456789"
ORG = "org-id-prod-7f3a"
OTHER_ORG = "org-id-dev-19bc"
KEY = "Kw-support-4c1e"  # gitleaks:allow (a made-up workspace key)
OTHER_KEY = "Kw-billing-9a2d"  # gitleaks:allow (a made-up workspace key)
VERDICT = REGISTRY_STATE_NAMES["verdict"]
COLLECTOR = REGISTRY_STATE_NAMES["collector"]
AUTH = {"mode": MODE_OIDC_JWT, "jwks_url": "https://idp/keys", "issuer": "https://idp",
        "audience": "aud"}
WS_SURFACE, ORG_SURFACE, OTHER_SURFACE = "surface-ws-q7", "surface-org-k3", "surface-other-z9"


def org_key(org_id: str, salt: str = SALT) -> str:
    return pseudonym(org_id, salt, "org")


def ws_key(key: str = KEY, salt: str = SALT) -> str:
    return pseudonym(key, salt, "workspace")


def raw_config(salt: str = SALT, entitlements=None, workspaces=None) -> dict:
    return {
        "privacy": {"hash_salt": salt},
        "orgs": [{"id": ORG, "label": "Prod"}, {"id": OTHER_ORG, "label": "Dev"}],
        "managed_agents": {"workspaces": workspaces if workspaces is not None else [
            {"key": KEY, "label": "support-agents"},
            {"key": OTHER_KEY, "label": "billing-agents"}]},
        "dashboard": {"auth": dict(AUTH), "entitlements": {"map": entitlements or [
            {"group": "g-ws", "workspaces": [KEY]},
            {"group": "g-org", "orgs": [ORG]},
            {"group": "g-both", "orgs": [ORG], "workspaces": [KEY]},
        ]}},
        "detectors": {"gitleaks": {"enabled": False, "severity": "block"}},
    }


def principal(*groups: str) -> Principal:
    return Principal(name="viewer@example.com", groups=groups)


def put(store, name, body):
    store.put_state(name, json.dumps(body).encode())


def v2(orgs=(), workspaces=()):
    return {"version": 2, "orgs": list(orgs), "workspaces": list(workspaces)}


def unsalted(store=None, **kw):
    policy = make_policy(**raw_config(salt="", **kw))
    if store is not None:
        policy.use_org_registry(store)
    return policy


def secrets_absent(text: str) -> None:
    for value in (KEY, OTHER_KEY, ORG, OTHER_ORG):
        assert value not in text


# --- the registry ------------------------------------------------------------


def test_the_registry_files_workspaces_apart_from_orgs():
    body = json.loads(build_registry(make_policy(**raw_config())))
    assert body["version"] == 2
    assert {e["id"] for e in body["orgs"]} == {ORG, OTHER_ORG}
    assert body["workspaces"] == [
        {"key": OTHER_KEY, "pseudonym": ws_key(OTHER_KEY), "label": "billing-agents"},
        {"key": KEY, "pseudonym": ws_key(), "label": "support-agents"}]


def test_a_workspace_labelled_with_an_org_id_is_not_that_org():
    policy = make_policy(**raw_config(workspaces=[{"key": KEY, "label": ORG}],
                                      entitlements=[{"group": "g", "workspaces": [KEY]}]))
    body = json.loads(build_registry(policy))
    assert [e["pseudonym"] for e in body["orgs"] if e["id"] == ORG] == [org_key(ORG)]
    assert body["workspaces"] == [{"key": KEY, "pseudonym": ws_key(), "label": ORG}]
    assert policy.org_labels()[org_key(ORG)] == "Prod"
    assert dict(policy.workspace_labels()) == {ws_key(): ORG}


def _collide(monkeypatch):
    monkeypatch.setattr("forgd_verdict.orgregistry.pseudonym",
                        lambda value, salt, prefix="id": f"{prefix}_0000000000")


def _assert_collision_refusal(exc: pytest.ExceptionInfo) -> None:
    text = str(exc.value)
    assert "'support-agents'" in text and "'billing-agents'" in text
    assert "same partition" in text
    secrets_absent(text)


def _assert_collision_logged(text: str) -> None:
    assert "'support-agents'" in text and "'billing-agents'" in text
    assert "same partition" in text
    secrets_absent(text)


def test_publishing_colliding_workspaces_drops_the_workspaces_and_keeps_the_orgs(
        tmp_path, monkeypatch, caplog):
    store = LocalFileStore(tmp_path, instance="t")
    _collide(monkeypatch)
    log = logging.getLogger("test.workspace_partitions")
    with caplog.at_level(logging.ERROR):
        assert publish_registry(store, make_policy(**raw_config()), "verdict", log)
    body = json.loads(store.get_state(VERDICT))
    assert body["workspaces"] == [] and body["orgs"]
    _assert_collision_logged(caplog.text)


def test_publishing_without_a_salt_writes_nothing_even_with_a_collision(tmp_path, monkeypatch):
    _collide(monkeypatch)
    store = LocalFileStore(tmp_path, instance="t")
    assert publish_registry(store, make_policy(**raw_config(salt="")), "verdict") is False
    assert store.get_state(VERDICT) is None


def _writers():
    from forgd_verdict.intake.app import Intake
    from forgd_verdict.otel.app import Collector
    from forgd_verdict.server.app import VerdictServer

    # A named logger, because the writers' default one does not propagate
    # to caplog.
    log = logging.getLogger("test.workspace_partitions")
    return {
        "verdict": lambda p, s: VerdictServer(p, store=s, detectors=[], logger=log),
        "collector": lambda p, s: Collector(p, store=s, detectors=[], late_detectors=[],
                                            logger=log),
        "intake": lambda p, s: Intake(p, store=s),
    }


@pytest.mark.parametrize("role", list(REGISTRY_STATE_NAMES))
def test_every_writer_starts_on_colliding_workspaces_and_publishes_no_workspaces(
        tmp_path, monkeypatch, caplog, role):
    """Only the ingest job writes workspace records, and it refuses a
    collision itself; the verdict server must keep serving governed prompts."""
    _collide(monkeypatch)
    store = LocalFileStore(tmp_path, instance="t")
    with caplog.at_level(logging.DEBUG):
        app = _writers()[role](make_policy(**raw_config()), store)
    app.close()
    assert json.loads(store.get_state(REGISTRY_STATE_NAMES[role]))["workspaces"] == []
    secrets_absent(caplog.text)


@pytest.mark.parametrize("role", list(REGISTRY_STATE_NAMES))
def test_every_writer_starts_on_colliding_workspaces_without_a_store(monkeypatch, role):
    _collide(monkeypatch)
    _writers()[role](make_policy(**raw_config()), None).close()


def test_load_policy_accepts_colliding_workspaces(tmp_path, monkeypatch):
    from forgd_verdict.policy import load_policy

    _collide(monkeypatch)
    path = tmp_path / "policy.json"
    path.write_text(json.dumps(raw_config()))
    load_policy(str(path))


def test_the_ingest_workspaces_refuse_a_collision(monkeypatch):
    from forgd_verdict.managed.scanner import workspaces

    _collide(monkeypatch)
    with pytest.raises(ValueError, match="same partition"):
        workspaces(make_policy(**raw_config()))


@pytest.mark.parametrize("block", [["not", "a", "mapping"], {"workspaces": "support-agents"}])
def test_a_wrongly_shaped_managed_agents_block_does_not_stop_a_writer(tmp_path, block):
    raw = raw_config()
    raw["managed_agents"] = block
    store = LocalFileStore(tmp_path, instance="t")
    _writers()["verdict"](make_policy(**raw), store).close()
    assert json.loads(store.get_state(VERDICT))["workspaces"] == []


def test_a_numeric_key_is_not_a_key():
    """Unquoted YAML 0123 is the integer 83; quoting it later would move
    the partition, so only a string names one."""
    from forgd_verdict.orgregistry import workspace_key

    assert workspace_key({"key": 83, "label": "x"}) == ""
    assert workspace_key({"key": "0123", "label": "x"}) == "0123"


class FailingWrites(LocalFileStore):
    def put_state(self, name, blob):
        raise OSError("store unavailable")


@pytest.mark.parametrize("role", list(REGISTRY_STATE_NAMES))
def test_a_writer_still_starts_when_the_store_write_fails(tmp_path, role, caplog):
    with caplog.at_level(logging.ERROR):
        app = _writers()[role](make_policy(**raw_config()), FailingWrites(tmp_path, instance="t"))
    app.close()
    assert any("could not publish the org registry" in r.getMessage() for r in caplog.records)
    secrets_absent(caplog.text)


def test_duplicate_keys_are_refused_like_a_collision():
    with pytest.raises(ValueError, match="same partition"):
        build_registry(make_policy(**raw_config(workspaces=[
            {"key": KEY, "label": "a"}, {"key": KEY, "label": "b"}])))


# --- version skew --------------------------------------------------------------


def test_a_version_1_registry_resolves_orgs_and_fails_workspaces_closed(tmp_path, caplog):
    store = LocalFileStore(tmp_path, instance="t")
    put(store, VERDICT, {"version": 1, "orgs": [
        {"id": ORG, "pseudonym": org_key(ORG), "label": "Prod"},
        # What a version 1 writer published for a workspace.
        {"id": "support-agents", "pseudonym": org_key("support-agents")}]})
    policy = unsalted(store)
    with caplog.at_level(logging.WARNING):
        assert policy.org_pseudonym(ORG) == org_key(ORG)
        assert policy.workspace_pseudonym(KEY) is None
        assert policy.workspace_pseudonym(KEY) is None
    assert policy.entitlements().allowed(principal("g-both")) == {org_key(ORG)}
    assert dict(policy.workspace_labels()) == {}
    warned = [r for r in caplog.records if "carries workspaces" in r.getMessage()]
    assert len(warned) == 1
    secrets_absent(caplog.text)


def test_a_version_2_file_beside_a_version_1_file_resolves_workspaces(tmp_path):
    store = LocalFileStore(tmp_path, instance="t")
    put(store, VERDICT, {"version": 1, "orgs": [{"id": ORG, "pseudonym": org_key(ORG)}]})
    put(store, COLLECTOR, v2(workspaces=[{"key": KEY, "pseudonym": ws_key(),
                                          "label": "support-agents"}]))
    policy = unsalted(store)
    assert policy.workspace_pseudonym(KEY) == ws_key()
    assert policy.entitlements().allowed(principal("g-both")) == {org_key(ORG), ws_key()}


@pytest.mark.parametrize("body", [
    {"version": 3, "orgs": [], "workspaces": []},
    {"version": True, "orgs": []},
    {"version": "2", "orgs": [], "workspaces": []},
    {"version": 2, "orgs": []},
    {"version": 2, "orgs": [], "workspaces": {}},
    v2(workspaces=[{"key": KEY, "pseudonym": org_key(KEY)}]),
    v2(orgs=[{"id": ORG, "pseudonym": ws_key(ORG)}]),
    v2(workspaces=[{"id": KEY, "pseudonym": ws_key()}]),
])
def test_an_unreadable_version_or_shape_fails_everything_closed(tmp_path, body, caplog):
    store = LocalFileStore(tmp_path, instance="t")
    put(store, VERDICT, v2(orgs=[{"id": ORG, "pseudonym": org_key(ORG)}],
                           workspaces=[{"key": KEY, "pseudonym": ws_key()}]))
    put(store, COLLECTOR, body)
    policy = unsalted(store)
    with caplog.at_level(logging.WARNING):
        assert policy.org_pseudonym(ORG) is None
        assert policy.workspace_pseudonym(KEY) is None
    assert any("malformed or of an unknown version" in r.getMessage() for r in caplog.records)


def test_writers_disagreeing_on_a_workspace_fail_only_that_workspace(tmp_path):
    store = LocalFileStore(tmp_path, instance="t")
    both = [{"id": ORG, "pseudonym": org_key(ORG)}]
    put(store, VERDICT, v2(orgs=both, workspaces=[{"key": KEY, "pseudonym": ws_key()}]))
    put(store, COLLECTOR, v2(orgs=both, workspaces=[
        {"key": KEY, "pseudonym": ws_key(salt="other-salt-000000000")}]))
    policy = unsalted(store)
    assert policy.workspace_pseudonym(KEY) is None
    assert policy.org_pseudonym(ORG) == org_key(ORG)


def test_a_salted_reader_warns_when_only_a_workspace_pseudonym_differs(tmp_path, caplog):
    store = LocalFileStore(tmp_path, instance="t")
    put(store, VERDICT, v2(orgs=[{"id": ORG, "pseudonym": org_key(ORG)}], workspaces=[
        {"key": KEY, "pseudonym": ws_key(salt="other-salt-000000000")}]))
    resolver = OrgResolver(SALT, store)
    with caplog.at_level(logging.WARNING):
        resolver.check_salt()
    (record,) = caplog.records
    assert "salt differs" in record.getMessage() and record.fields == {"roles": ["verdict"]}


# --- entitlements ------------------------------------------------------------


@pytest.mark.parametrize("salt", [SALT, ""])
def test_workspaces_are_granted_by_key_and_unioned_with_orgs(tmp_path, salt):
    store = LocalFileStore(tmp_path, instance="t")
    publish_registry(store, make_policy(**raw_config()), "verdict")
    policy = make_policy(**raw_config(salt=salt))
    policy.use_org_registry(store)
    ent = policy.entitlements()
    assert ent.allowed(principal("g-ws")) == {ws_key()}
    assert ent.allowed(principal("g-org")) == {org_key(ORG)}
    assert ent.allowed(principal("g-both")) == {org_key(ORG), ws_key()}
    assert ent.allowed(principal("g-ws", "g-org")) == {org_key(ORG), ws_key()}


def test_a_workspace_key_under_orgs_grants_no_org(tmp_path):
    """An `orgs` value is resolved as an org id only."""
    policy = make_policy(**raw_config(entitlements=[{"group": "g", "orgs": ["unlisted"]}]))
    assert policy.entitlements().allowed(principal("g")) == {org_key("unlisted")}


REFUSE_UNDER_ORGS = (
    "dashboard.entitlements.map: group 'g' lists the managed_agents workspace "
    "labelled 'support-agents' under `orgs`. Remove it from `orgs` and add that "
    "workspace's `key` to the same entry's `workspaces` list.")


@pytest.mark.parametrize("value", [KEY, "support-agents"])
def test_an_orgs_entry_naming_a_workspace_is_refused_by_label(value):
    policy = make_policy(**raw_config(entitlements=[{"group": "g", "orgs": [value]}]))
    with pytest.raises(ValueError) as exc:
        policy.entitlements()
    assert str(exc.value) == REFUSE_UNDER_ORGS
    secrets_absent(str(exc.value))


def test_an_orgs_entry_equal_to_a_workspace_labelled_with_it_is_refused():
    policy = make_policy(**raw_config(workspaces=[{"key": KEY, "label": ORG}],
                                      entitlements=[{"group": "g", "orgs": [ORG]}]))
    with pytest.raises(ValueError, match="under `orgs`"):
        policy.entitlements()


def test_a_workspaces_entry_naming_a_label_is_refused():
    policy = make_policy(**raw_config(
        entitlements=[{"group": "g", "workspaces": ["support-agents"]}]))
    with pytest.raises(ValueError) as exc:
        policy.entitlements()
    assert str(exc.value) == (
        "dashboard.entitlements.map: group 'g' names the managed_agents workspace "
        "labelled 'support-agents' by its label under `workspaces`. Replace it with "
        "that workspace's `key`.")


def _policy_file(tmp_path, monkeypatch, raw) -> str:
    path = tmp_path / "policy.json"
    path.write_text(json.dumps(raw))
    monkeypatch.setenv("FORGD_VERDICT_POLICY", str(path))
    return str(path)


@pytest.mark.parametrize("value", [KEY, "support-agents"])
def test_entitlements_refuse_a_workspace_under_orgs(tmp_path, monkeypatch, value):
    """The verdict server loads the policy without using entitlements, so a
    mistake in the map stops the dashboard and the connector, not it."""
    from forgd_verdict.policy import load_policy

    path = _policy_file(tmp_path, monkeypatch,
                        raw_config(entitlements=[{"group": "g", "orgs": [value]}]))
    policy = load_policy(path)
    with pytest.raises(ValueError) as exc:
        policy.entitlements()
    assert str(exc.value) == REFUSE_UNDER_ORGS
    secrets_absent(str(exc.value))


def test_entitlements_refuse_a_workspace_under_orgs_through_an_env_reference(
        tmp_path, monkeypatch):
    from forgd_verdict.policy import load_policy

    monkeypatch.setenv("FORGD_ORG_ID_ALIAS", KEY)
    path = _policy_file(tmp_path, monkeypatch, raw_config(
        entitlements=[{"group": "g", "orgs": ["$FORGD_ORG_ID_ALIAS"]}]))
    with pytest.raises(ValueError, match="under `orgs`"):
        load_policy(path).entitlements()


def test_entitlements_refuse_a_label_under_workspaces(tmp_path, monkeypatch):
    from forgd_verdict.policy import load_policy

    path = _policy_file(tmp_path, monkeypatch, raw_config(
        entitlements=[{"group": "g", "workspaces": ["support-agents"]}]))
    with pytest.raises(ValueError, match="by its label under `workspaces`"):
        load_policy(path).entitlements()


def test_load_policy_accepts_a_workspace_granted_by_key(tmp_path, monkeypatch):
    from forgd_verdict.policy import load_policy

    load_policy(_policy_file(tmp_path, monkeypatch, raw_config()))


def test_the_dashboard_refuses_to_start_on_a_workspace_under_orgs(tmp_path, monkeypatch):
    _policy_file(tmp_path, monkeypatch, raw_config(entitlements=[{"group": "g", "orgs": [KEY]}]))
    from forgd_verdict.dashboard.app import create_app

    with pytest.raises(ValueError, match="under `orgs`"):
        create_app(store_spec=str(tmp_path / "store"))


# --- the dashboard -------------------------------------------------------------


def _three_partition_store(root) -> LocalFileStore:
    store = LocalFileStore(root, instance="t")
    store.write_verdicts([
        VerdictRecord(source=SOURCE_MANAGED_SCAN, tenant_hash=ws_key(), surface=WS_SURFACE),
        VerdictRecord(source="otel_collect", tenant_hash=org_key(ORG), surface=ORG_SURFACE),
        VerdictRecord(source=SOURCE_MANAGED_SCAN, tenant_hash=ws_key(OTHER_KEY),
                      surface=OTHER_SURFACE),
    ])
    publish_registry(store, make_policy(**raw_config()), "verdict")
    return store


def _dashboard(tmp_path, monkeypatch, store_dir, groups):
    policy_file = tmp_path / "policy.json"
    policy_file.write_text(json.dumps(raw_config(salt="")))
    monkeypatch.setenv("FORGD_VERDICT_POLICY", str(policy_file))
    monkeypatch.delenv("FORGD_HASH_SALT", raising=False)
    from forgd_verdict.dashboard.app import create_app

    app = create_app(store_spec=str(store_dir))
    viewer = principal(*groups)
    app.auth = types.SimpleNamespace(mode=app.auth.mode, authenticate=lambda h: viewer,
                                     describe=app.auth.describe)
    return ASGIClient(app)


async def test_a_workspace_scoped_viewer_sees_only_that_workspace(tmp_path, monkeypatch):
    store_dir = tmp_path / "store"
    _three_partition_store(store_dir)
    client = _dashboard(tmp_path, monkeypatch, store_dir, ("g-ws",))
    for route in ("/events", f"/events?org={ws_key()}"):
        status, body = await client.get(route)
        assert status == 200, route
        assert WS_SURFACE in body and ORG_SURFACE not in body and OTHER_SURFACE not in body
        secrets_absent(body)
    status, _ = await client.get(f"/events?org={org_key(ORG)}")
    assert status == 403


async def test_the_picker_lists_orgs_and_workspaces_by_kind(tmp_path, monkeypatch):
    store_dir = tmp_path / "store"
    _three_partition_store(store_dir)
    client = _dashboard(tmp_path, monkeypatch, store_dir, ("g-both",))
    status, body = await client.get("/events")
    assert status == 200
    assert f"?org={ws_key()}" in body and "support-agents (workspace)" in body
    assert f"?org={org_key(ORG)}" in body and "Prod (workspace)" not in body
    assert "billing-agents" not in body
    status, body = await client.get(f"/events?org={ws_key()}")
    assert status == 200 and WS_SURFACE in body and ORG_SURFACE not in body
    secrets_absent(body)


async def test_a_refused_workspace_is_logged_as_well_formed(tmp_path, monkeypatch, caplog):
    store_dir = tmp_path / "store"
    _three_partition_store(store_dir)
    client = _dashboard(tmp_path, monkeypatch, store_dir, ("g-org",))
    with caplog.at_level(logging.INFO, logger="forgd_verdict.dashboard"):
        status, _ = await client.get(f"/events?org={ws_key()}")
    assert status == 403
    (record,) = [r for r in caplog.records if r.getMessage() == "dashboard org refused"]
    assert record.fields["org_well_formed"] is True


# --- the connector -------------------------------------------------------------


def _caller(tmp_path, *groups):
    store = _three_partition_store(tmp_path / "store")
    policy = unsalted(store)
    cfg = types.SimpleNamespace(auth=None, entitlements=policy.entitlements())
    return T.Caller(T.reader_from_policy(policy, cfg, store), principal(*groups))


async def test_the_connector_reads_a_workspace_partition_and_names_its_kind(tmp_path):
    caller = _caller(tmp_path, "g-both")
    out = await T.summary(caller, "30d", org=ws_key())
    assert {o["org"] for o in out["orgs"]} == {ws_key()}
    (entry,) = out["orgs"]
    assert entry["kind"] == "workspace" and entry["label"] == "support-agents"
    everything = await T.summary(caller, "30d")
    kinds = {o["org"]: o["kind"] for o in everything["orgs"]}
    assert kinds == {ws_key(): "workspace", org_key(ORG): "org"}
    secrets_absent(json.dumps(everything))


async def test_the_connector_refuses_an_unentitled_workspace(tmp_path):
    from mcp.server.mcpserver.exceptions import ToolError

    caller = _caller(tmp_path, "g-ws")
    with pytest.raises(ToolError, match="forbidden"):
        await T.summary(caller, "30d", org=ws_key(OTHER_KEY))


@pytest.mark.parametrize("value", ["workspace_0123456789", "org_0123456789", "unattributed"])
def test_the_connector_accepts_either_partition_kind(value):
    assert T._org_arg(value) == value


@pytest.mark.parametrize("value", ["workspace_012345678", "workspace_0123456789a",
                                   "workspaces_0123456789", "ws_0123456789", KEY])
def test_the_connector_rejects_anything_else(value):
    from mcp.server.mcpserver.exceptions import ToolError

    with pytest.raises(ToolError):
        T._org_arg(value)


def test_partition_kind():
    assert partition_kind(ws_key()) == "workspace"
    assert partition_kind(org_key(ORG)) == "org"
    assert partition_kind("unattributed") is None
    assert partition_kind("workspace_" + "0" * 10 + "\n") is None


# --- privacy -------------------------------------------------------------------


def test_the_policy_tab_shows_no_workspace_key():
    effective = json.dumps(redacted(make_policy(**raw_config())))
    assert KEY not in effective and OTHER_KEY not in effective
    assert "support-agents" in effective


@pytest.mark.parametrize("field", ["orgs", "workspaces"])
def test_entitlements_refuse_a_string_where_a_list_belongs(tmp_path, monkeypatch, field):
    """A bare string would be read character by character."""
    from forgd_verdict.policy import load_policy

    path = _policy_file(tmp_path, monkeypatch, raw_config(
        entitlements=[{"group": "g", field: "support-agents"}]))
    with pytest.raises(ValueError, match="must be a list"):
        load_policy(path).entitlements()


def test_the_verdict_server_starts_on_a_bad_entitlement_map(tmp_path, monkeypatch):
    from forgd_verdict.policy import load_policy
    from forgd_verdict.server.app import VerdictServer

    path = _policy_file(tmp_path, monkeypatch, raw_config(
        entitlements=[{"group": "g", "orgs": ["support-agents"]}]))
    VerdictServer(load_policy(path), store=LocalFileStore(tmp_path / "s", instance="t"),
                  detectors=[]).close()


def test_the_connector_refuses_to_start_on_a_bad_entitlement_map(tmp_path, monkeypatch):
    from forgd_verdict.connector import config
    from forgd_verdict.policy import load_policy

    raw = raw_config(entitlements=[{"group": "g", "orgs": ["support-agents"]}])
    raw["connector"] = {"enabled": True, "resource": "https://mcp.example.com/mcp",
                        "required_scope": "findings.read",
                        "auth": {"mode": "oidc_jwt", "issuer": "https://idp",
                                 "jwks_url": "https://idp/keys",
                                 "audience": "https://mcp.example.com/mcp"}}
    with pytest.raises(ValueError, match="under `orgs`"):
        config.load(load_policy(_policy_file(tmp_path, monkeypatch, raw)))
