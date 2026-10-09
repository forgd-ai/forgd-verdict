"""A service that logs or records findings refuses to start without a salt,
with or without a store, unless the policy file sets
`privacy.allow_unsalted: true`."""

from __future__ import annotations

import json

import pytest

from forgd_verdict.policy import (
    DEFAULT_POLICY,
    ENV_OVERRIDES,
    Policy,
    Unsalted,
    _deep_merge,
    load_policy,
)
from forgd_verdict.store.local import LocalFileStore


def _policy(**privacy) -> Policy:
    return Policy(raw=_deep_merge(DEFAULT_POLICY, {
        "privacy": privacy,
        "server": {"csv_path": None},
        "otel": {"orgs": []},
        "intake": {"clients": []},
    }))


def _verdict(policy, store):
    from forgd_verdict.server.app import VerdictServer
    return VerdictServer(policy, store=store)


def _collector(policy, store):
    from forgd_verdict.otel.app import Collector
    return Collector(policy, store=store)


def _intake(policy, store):
    from forgd_verdict.intake.app import Intake
    return Intake(policy, store=store)


SERVICES = pytest.mark.parametrize("build", [_verdict, _collector, _intake],
                                   ids=["verdict", "collector", "intake"])


@SERVICES
def test_a_writer_with_a_store_and_no_salt_refuses_to_start(build, tmp_path):
    with pytest.raises(Unsalted, match=r"privacy\.allow_unsalted: true"):
        build(_policy(), LocalFileStore(tmp_path, instance="t"))


@SERVICES
def test_a_writer_with_no_store_and_no_salt_refuses_to_start(build, tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    monkeypatch.delenv("FORGD_VERDICT_STORE", raising=False)
    with pytest.raises(Unsalted, match=r"FORGD_HASH_SALT.*privacy\.allow_unsalted: true"):
        build(_policy(), None)


@SERVICES
def test_a_writer_with_a_salt_starts(build, tmp_path):
    build(_policy(hash_salt="a-deployment-salt"), LocalFileStore(tmp_path, instance="t")).close()


@SERVICES
def test_a_writer_with_a_salt_and_no_store_starts(build, tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    monkeypatch.delenv("FORGD_VERDICT_STORE", raising=False)
    build(_policy(hash_salt="a-deployment-salt"), None).close()


@SERVICES
@pytest.mark.parametrize("with_store", [True, False], ids=["store", "no-store"])
def test_the_opt_out_in_the_policy_file_starts_a_writer(build, with_store, tmp_path,
                                                         monkeypatch):
    monkeypatch.chdir(tmp_path)
    monkeypatch.delenv("FORGD_VERDICT_STORE", raising=False)
    monkeypatch.delenv("FORGD_HASH_SALT", raising=False)
    path = tmp_path / "policy.json"
    path.write_text(json.dumps({"privacy": {"allow_unsalted": True},
                                "server": {"csv_path": None}}))
    policy = load_policy(path)
    assert policy.allow_unsalted and not policy.hash_salt
    store = LocalFileStore(tmp_path / "s", instance="t") if with_store else None
    build(policy, store).close()


@pytest.mark.parametrize("with_store", [True, False], ids=["store", "no-store"])
def test_the_ingest_jobs_refuse_too(with_store, tmp_path):
    from forgd_verdict.compliance.ingest import run_ingest
    from forgd_verdict.managed.scanner import run_managed_ingest

    store = LocalFileStore(tmp_path, instance="t") if with_store else None
    with pytest.raises(Unsalted, match="allow_unsalted"):
        run_ingest(_policy(), store)
    with pytest.raises(Unsalted, match="allow_unsalted"):
        run_managed_ingest(_policy(), store)


def test_the_ingest_command_refuses_in_one_line(tmp_path, monkeypatch, capsys):
    from forgd_verdict.cli import main

    monkeypatch.setattr("forgd_verdict.compliance.ingest.run_ingest",
                        lambda policy, store, **kw: policy.refuse_unsalted("x"))
    path = tmp_path / "p.json"
    path.write_text(json.dumps({"server": {"store": str(tmp_path / "findings"),
                                           "csv_path": None},
                                "compliance": {"api_key": "k"}}))
    assert main(["--policy", str(path), "ingest"]) == 2
    err = capsys.readouterr().err
    assert "allow_unsalted" in err and "Traceback" not in err


@pytest.mark.parametrize("store", [True, False], ids=["store", "no-store"])
@pytest.mark.parametrize("module", ["server", "otel", "intake"])
def test_each_service_entrypoint_refuses_in_one_line(module, store, tmp_path, monkeypatch,
                                                     capsys):
    import importlib
    import sys
    import types

    def started(*args, **kwargs):
        raise AssertionError("the service started without a salt")

    monkeypatch.setitem(sys.modules, "uvicorn", types.SimpleNamespace(run=started))
    main = importlib.import_module(f"forgd_verdict.{module}.__main__").main
    path = tmp_path / "p.json"
    path.write_text(json.dumps({"server": {"store": str(tmp_path / "findings")}}
                               if store else {}))
    monkeypatch.delenv("FORGD_HASH_SALT", raising=False)
    monkeypatch.delenv("FORGD_VERDICT_STORE", raising=False)
    assert main(["--policy", str(path)]) == 2
    err = capsys.readouterr().err
    assert "allow_unsalted" in err and "FORGD_HASH_SALT" in err and "Traceback" not in err


@pytest.mark.parametrize("value", ["true", "yes", 1, "$FORGD_ALLOW_UNSALTED"])
def test_only_the_boolean_true_opts_out(value, monkeypatch):
    monkeypatch.setenv("FORGD_ALLOW_UNSALTED", "true")
    assert not _policy(allow_unsalted=value).allow_unsalted


def test_no_environment_variable_reaches_the_opt_out(monkeypatch, tmp_path):
    assert all(path[0] != "privacy" for path, _ in ENV_OVERRIDES.values())
    for name in ("FORGD_ALLOW_UNSALTED", "FORGD_PRIVACY_ALLOW_UNSALTED",
                 "FORGD_VERDICT_ALLOW_UNSALTED", "ALLOW_UNSALTED"):
        monkeypatch.setenv(name, "true")
    path = tmp_path / "policy.json"
    path.write_text("{}")
    policy = load_policy(path)
    assert not policy.allow_unsalted
    with pytest.raises(Unsalted):
        policy.refuse_unsalted("x")


def test_the_dashboard_reads_a_store_without_a_salt(tmp_path):
    from forgd_verdict.dashboard.app import Dashboard

    Dashboard(LocalFileStore(tmp_path, instance="t"))


def test_the_shipped_policy_takes_its_salt_from_the_environment():
    from pathlib import Path

    raw = load_policy(Path(__file__).parents[1] / "policy.yaml").raw
    assert raw["privacy"]["hash_salt"] == "$FORGD_HASH_SALT"
    assert "allow_unsalted" not in raw["privacy"]


SCANNED = "key AKIAIOSFODNN7EXAMPLE end"  # gitleaks:allow
MATCHED = "AKIAIOSFODNN7EXAMPLE"  # gitleaks:allow


def _scan(tmp_path, capsys, policy: dict) -> tuple[list[dict], str, str]:
    from forgd_verdict.cli import main

    path = tmp_path / "policy.json"
    path.write_text(json.dumps(policy))
    text = tmp_path / "input.txt"
    text.write_text(SCANNED)
    main(["--policy", str(path), "scan", str(text)])
    out = capsys.readouterr()
    return json.loads(out.out)["findings"], out.err, out.out


def test_scan_without_a_salt_uses_a_key_no_other_run_shares(tmp_path, monkeypatch, capsys):
    from forgd_verdict.models import digest

    monkeypatch.delenv("FORGD_HASH_SALT", raising=False)
    first, err, stdout = _scan(tmp_path, capsys, {})
    second, _, _ = _scan(tmp_path, capsys, {})
    assert first and second
    assert "privacy.hash_salt is empty" in err and "random key" in err
    hashes = [f["excerpt_hash"] for f in first]
    assert digest(MATCHED) not in stdout
    assert set(hashes).isdisjoint(f["excerpt_hash"] for f in second)


def test_scan_with_a_salt_hashes_with_it(tmp_path, monkeypatch, capsys):
    from forgd_verdict.models import digest

    monkeypatch.delenv("FORGD_HASH_SALT", raising=False)
    findings, err, _ = _scan(tmp_path, capsys, {"privacy": {"hash_salt": "a-deployment-salt"}})
    assert digest(MATCHED, "a-deployment-salt") in [f["excerpt_hash"] for f in findings]
    assert "hash_salt is empty" not in err


def test_compliance_sessions_refuses_without_a_salt(tmp_path, monkeypatch, capsys):
    from forgd_verdict.cli import main

    monkeypatch.delenv("FORGD_HASH_SALT", raising=False)
    path = tmp_path / "p.json"
    path.write_text(json.dumps({"server": {"store": "", "csv_path": None},
                                "compliance": {"api_key": "k"}}))
    assert main(["--policy", str(path), "compliance", "sessions"]) == 2
    err = capsys.readouterr().err
    assert "allow_unsalted" in err and "Traceback" not in err
