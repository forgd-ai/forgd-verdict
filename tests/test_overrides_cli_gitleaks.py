"""The overrides CLI on a machine that cannot reach the gitleaks daemon.

It refuses by default, saying how to go on, and `--without-gitleaks`
scans the change with every other configured detector. Each test names
the mutation that makes it fail.
"""

from __future__ import annotations

import json

import pytest
from conftest import FAKE_GITHUB_TOKEN, OVERRIDES_PUBLIC_TEXT

from forgd_verdict import cli
from forgd_verdict import overrides as ov
from forgd_verdict.policy import Policy, load_policy
from forgd_verdict.store import LocalFileStore

pytestmark = pytest.mark.usefixtures("control_identity", "signing_env")


def _policy(tmp_path, **gitleaks):
    path = tmp_path / "policy.json"
    path.write_text(json.dumps({
        "dashboard": {"admins": {"groups": [{"group": "ops"}]}},
        "overrides": {"verify_keys": [OVERRIDES_PUBLIC_TEXT]},
        "detectors": {"gitleaks": {"enabled": True,
                                   "daemon": str(tmp_path / "absent" / "gitleaksd.sock"),
                                   **gitleaks}},
    }))
    return path


def _main(tmp_path, *argv, **gitleaks):
    return cli.main(["--policy", str(_policy(tmp_path, **gitleaks)), *argv])


@pytest.fixture
def store(tmp_path):
    return LocalFileStore(tmp_path / "store", instance="t")


def test_an_unreachable_daemon_refuses_the_change_and_names_the_flag(tmp_path, store, capsys):
    """Mutation: drop the hint from the build refusal."""
    assert _main(tmp_path, "overrides", "--store", str(store.root), "init") == 2
    err = capsys.readouterr().err
    assert "detectors.gitleaks is required here but unavailable" in err
    assert "--without-gitleaks" in err
    assert store.read_control().status == "absent"


def test_a_daemon_config_nothing_vouches_for_names_the_flag(tmp_path, store, capsys,
                                                           monkeypatch):
    """The config check refuses before the socket is tried. Mutation: match
    only the unavailable-detector wording."""
    monkeypatch.delenv("FORGD_GITLEAKS_CONFIG", raising=False)
    assert _main(tmp_path, "overrides", "--store", str(store.root), "init",
                 config=str(tmp_path / "gitleaks.toml")) == 2
    err = capsys.readouterr().err
    assert "detectors.gitleaks.config" in err and "--without-gitleaks" in err
    assert _main(tmp_path, "overrides", "--without-gitleaks", "--store", str(store.root),
                 "init", config=str(tmp_path / "gitleaks.toml")) == 0


def test_without_gitleaks_another_required_detector_still_refuses(tmp_path, store, capsys,
                                                                  monkeypatch):
    """Mutation: leave out every detector that cannot run."""
    from forgd_verdict.detectors.entropy import EntropyDetector

    path = _policy(tmp_path)
    policy = json.loads(path.read_text())
    policy["detectors"]["entropy"] = {"enabled": True}
    path.write_text(json.dumps(policy))
    monkeypatch.setattr(EntropyDetector, "available", lambda self: False)
    assert cli.main(["--policy", str(path), "overrides", "--without-gitleaks", "--store",
                     str(store.root), "init"]) == 2
    err = capsys.readouterr().err
    assert "detectors.entropy is required" in err and "--without-gitleaks" not in err


@pytest.mark.parametrize("argv", [
    ("overrides", "--without-gitleaks", "--store", "{store}", "init"),
], ids=["overrides"])
def test_without_gitleaks_the_change_is_scanned_by_the_other_detectors(
        tmp_path, store, capsys, argv):
    """Mutation: ignore --without-gitleaks when building the detectors."""
    argv = [a.format(store=store.root) for a in argv]
    assert _main(tmp_path, *argv) == 0
    err = capsys.readouterr().err
    assert "gitleaks does not scan this change (--without-gitleaks)" in err
    assert store.read_control().status == "ok"


def test_without_gitleaks_a_value_the_other_detectors_match_is_refused(tmp_path, store, capsys):
    """Mutation: build no detectors under --without-gitleaks."""
    assert _main(tmp_path, "overrides", "--without-gitleaks", "--store", str(store.root),
                 "init") == 0
    capsys.readouterr()
    assert _main(tmp_path, "overrides", "--without-gitleaks", "--store", str(store.root),
                 "set", "server.mode", FAKE_GITHUB_TOKEN) == 2
    err = capsys.readouterr().err
    assert "matched a detector" in err and FAKE_GITHUB_TOKEN not in err


@pytest.mark.parametrize("argv", [
    ("exclude", "--without-gitleaks", "--store", "{store}", "--request-id", "req_0123456789abcdef"),
    ("reset-stats", "--without-gitleaks", "--store", "{store}"),
], ids=["exclude", "reset-stats"])
def test_exclude_and_reset_stats_take_the_flag(tmp_path, store, capsys, argv):
    """Mutation: leave the flag off either parser."""
    assert _main(tmp_path, "overrides", "--without-gitleaks", "--store", str(store.root),
                 "init") == 0
    capsys.readouterr()
    assert _main(tmp_path, *[a.format(store=store.root) for a in argv]) == 0
    assert "gitleaks does not scan this change" in capsys.readouterr().err


def test_gitleaks_skipping_mid_scan_refuses_and_names_the_flag(tmp_path, store, capsys,
                                                                monkeypatch):
    """A daemon that was reachable when the detectors were built and fails
    during the scan. Mutation: drop the hint from the Refused handler."""
    def skipped(*_a, **_k):
        raise ov.Refused("the change could not be checked: gitleaks did not run")

    monkeypatch.setattr(ov, "apply_change", skipped)
    monkeypatch.setattr(Policy, "build_detectors", lambda self, **_k: [])
    assert _main(tmp_path, "overrides", "--store", str(store.root), "init") == 2
    err = capsys.readouterr().err
    assert "gitleaks did not run" in err and "--without-gitleaks" in err


def test_build_detectors_leaves_out_only_what_it_is_told(tmp_path):
    """Mutation: ignore leave_out."""
    policy = load_policy(str(_policy(tmp_path)))
    with pytest.raises(RuntimeError, match="detectors.gitleaks is required"):
        policy.build_detectors(profile="dashboard")
    built = policy.build_detectors(profile="dashboard", leave_out=("gitleaks",))
    names = {d.name for d in built}
    assert "gitleaks" not in names and {"regex", "entropy"} <= names
