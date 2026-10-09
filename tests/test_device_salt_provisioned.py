"""`hook.device_salt_path`: an MDM-provisioned salt the user cannot rewrite.

The device id is a digest of the device salt. With the salt in the user's
own home directory, deleting it gives the laptop a new id, so a denied
device comes back as a new one. A provisioned salt is root-owned and
read-only to the user; when it is configured and not fit for that, the
hook sends no device id rather than falling back to the per-user one."""

from __future__ import annotations

import io
import os
import secrets
import sys
from pathlib import Path

import pytest
from conftest import make_policy

from forgd_verdict.hook import cli, device
from forgd_verdict.hook.device import salt_namespace

posix = pytest.mark.skipif(os.name != "posix", reason="POSIX permissions")
not_root = pytest.mark.skipif(hasattr(os, "geteuid") and os.geteuid() == 0,
                              reason="root can write any file")
OTHER_UID = 4242


@pytest.fixture
def provisioned(tmp_path, monkeypatch):
    """A salt file in a directory, read-only, owned by 'someone else'."""
    made = []

    def make(mode=0o444, dir_mode=0o555, content=None, owner_is_me=False):
        folder = tmp_path / f"etc{len(made)}"
        folder.mkdir()
        path = folder / "device-salt"
        salt = secrets.token_hex(32)
        path.write_text(content if content is not None else salt + "\n")
        path.chmod(mode)
        folder.chmod(dir_mode)
        made.append(folder)
        if not owner_is_me:
            monkeypatch.setattr(device, "_euid", lambda: OTHER_UID)
        return path, salt

    yield make
    for folder in made:
        folder.chmod(0o755)


def _policy(tmp_path, salt_path=None, **hook):
    cfg = {"spool": str(tmp_path / "home" / "spool"), **hook}
    if salt_path is not None:
        cfg["device_salt_path"] = str(salt_path)
    return make_policy(hook=cfg)


def _per_user_salt(tmp_path) -> Path:
    return tmp_path / "home" / "device-salt"


# -- (a) the provisioned salt --------------------------------------------------


@posix
@not_root
def test_a_provisioned_salt_is_the_device_salt_and_id(tmp_path, provisioned, capsys):
    path, salt = provisioned()
    policy = _policy(tmp_path, path)
    assert device.hook_salt(policy) == salt
    assert device.hook_device_id(policy) == salt_namespace(salt)
    assert not _per_user_salt(tmp_path).exists()
    assert "device_salt_path" not in capsys.readouterr().err


@posix
@not_root
@pytest.mark.parametrize("case", [
    "missing", "group-writable", "world-writable", "owned-by-this-user",
    "directory-writable", "malformed", "symlink", "relative", "placeholder"])
def test_an_unfit_provisioned_salt_sends_no_device_id(tmp_path, provisioned, capsys,
                                                       monkeypatch, case):
    if case == "missing":
        path = tmp_path / "nowhere" / "device-salt"
    elif case == "group-writable":
        path, _ = provisioned(mode=0o464)
    elif case == "world-writable":
        path, _ = provisioned(mode=0o446)
    elif case == "owned-by-this-user":
        path, _ = provisioned(owner_is_me=True)
    elif case == "directory-writable":
        path, _ = provisioned(dir_mode=0o755)
    elif case == "malformed":
        path, _ = provisioned(content="not a salt\n")
    elif case == "symlink":
        target, _ = provisioned()
        link_dir = tmp_path / "links"
        link_dir.mkdir()
        path = link_dir / "device-salt"
        path.symlink_to(target)
        link_dir.chmod(0o555)
        monkeypatch.setattr(device, "_euid", lambda: OTHER_UID)
    elif case == "relative":
        path = "etc/device-salt"
    else:
        path = "$FORGD_DEVICE_SALT"
    policy = _policy(tmp_path, path)
    try:
        assert device.hook_device_id(policy) is None
        salt = device.hook_salt(policy)
        assert salt and len(salt) == 64
        assert not _per_user_salt(tmp_path).exists()
        err = capsys.readouterr().err
        assert "hook.device_salt_path" in err
    finally:
        if case == "symlink":
            (tmp_path / "links").chmod(0o755)


def test_with_no_provisioned_salt_the_per_user_one_is_used_and_said(tmp_path, capsys):
    policy = _policy(tmp_path)
    first = device.hook_device_id(policy)
    assert first and first == device.hook_device_id(policy)
    assert _per_user_salt(tmp_path).exists()
    err = capsys.readouterr().err
    assert "hook.device_salt_path is not set" in err


def test_device_salt_path_is_not_environment_tunable():
    from forgd_verdict.policy import ENV_OVERRIDES

    assert all(target != ("hook", "device_salt_path")
               for target, _ in ENV_OVERRIDES.values())


# -- the hook sends what it computes ---------------------------------------------


def _sent_device(monkeypatch, policy) -> str | None:
    sent = {}

    def capture(request, *a, **k):
        sent.update({k.lower(): v for k, v in request.header_items()})
        raise OSError("not reached")

    monkeypatch.setattr(cli, "open_url", capture)
    policy.raw["hook"]["scan_endpoint"] = "https://scan.example/scan"
    cli._remote_verdict(policy, {"hook_event_name": "UserPromptSubmit"}, 100)
    return sent.get("x-forgd-device")


@posix
@not_root
def test_an_unfit_provisioned_salt_sends_no_device_header(tmp_path, monkeypatch, capsys):
    policy = _policy(tmp_path, tmp_path / "nowhere" / "device-salt")
    assert _sent_device(monkeypatch, policy) is None


@posix
@not_root
def test_the_header_is_the_provisioned_id(tmp_path, monkeypatch, provisioned, capsys):
    path, salt = provisioned()
    assert _sent_device(monkeypatch, _policy(tmp_path, path)) == salt_namespace(salt)


# -- (b) forgd-verdict hook device-id ----------------------------------------------


def _write_policy(tmp_path, hook) -> Path:
    import json

    path = tmp_path / "managed.json"
    path.write_text(json.dumps({"hook": hook}))
    return path


def _device_id_cli(policy_path, monkeypatch, capsys):
    from forgd_verdict.cli import main

    monkeypatch.setattr(sys, "stdin", io.StringIO(""))
    code = main(["hook", "device-id", "--policy", str(policy_path)])
    out = capsys.readouterr()
    return code, out.out, out.err


@posix
@not_root
def test_device_id_prints_what_the_hook_sends(tmp_path, monkeypatch, capsys, provisioned):
    path, salt = provisioned()
    hook = {"spool": str(tmp_path / "home" / "spool"), "device_salt_path": str(path)}
    code, out, _ = _device_id_cli(_write_policy(tmp_path, hook), monkeypatch, capsys)
    assert code == 0
    assert out.strip() == salt_namespace(salt)
    from forgd_verdict.policy import load_policy

    sent = _sent_device(monkeypatch,
                        load_policy(str(_write_policy(tmp_path, hook)), for_hook=True))
    assert out.strip() == sent


@posix
@not_root
def test_device_id_exits_non_zero_when_there_is_none(tmp_path, monkeypatch, capsys):
    hook = {"spool": str(tmp_path / "home" / "spool"),
            "device_salt_path": str(tmp_path / "nowhere" / "device-salt")}
    code, out, err = _device_id_cli(_write_policy(tmp_path, hook), monkeypatch, capsys)
    assert code != 0
    assert out == ""
    assert "hook.device_salt_path" in err


@posix
@not_root
def test_as_root_the_id_is_read_for_an_inventory_script(tmp_path, provisioned, monkeypatch):
    """A Jamf extension attribute runs as root, who owns the file and can
    write anything; only the mode bits still say anything there."""
    path, salt = provisioned()
    monkeypatch.setattr(device, "_euid", lambda: 0)
    assert device.provisioned_salt(str(path)) == (salt, None)


@posix
@not_root
@pytest.mark.parametrize("mode,dir_mode", [(0o446, 0o555), (0o444, 0o557)])
def test_as_root_a_writable_file_or_directory_is_still_unfit(tmp_path, provisioned,
                                                             monkeypatch, mode, dir_mode):
    path, _ = provisioned(mode=mode, dir_mode=dir_mode)
    monkeypatch.setattr(device, "_euid", lambda: 0)
    assert device.provisioned_salt(str(path))[0] is None


@posix
@not_root
def test_device_id_takes_the_policy_before_the_subcommand(tmp_path, monkeypatch, capsys,
                                                          provisioned):
    from forgd_verdict.cli import main

    path, salt = provisioned()
    policy = _write_policy(tmp_path, {"spool": str(tmp_path / "home" / "spool"),
                                      "device_salt_path": str(path)})
    monkeypatch.setattr(sys, "stdin", io.StringIO(""))
    assert main(["--policy", str(policy), "hook", "device-id"]) == 0
    assert capsys.readouterr().out.strip() == salt_namespace(salt)
