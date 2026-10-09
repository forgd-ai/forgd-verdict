"""The hook's per-device salt.

The deployment's hash salt covers the server-side writers and exempts the hook, because a
deployment secret copied to every developer machine leaks with the first
lost one. That reasoning stands. The FALLBACK did not: the hook hashed with
an empty salt, spooled those hashes, and shipped them unchanged into the
shared store -- so an export containing adapter-2 rows could be swept back
to the matched secret. A bare sha256 of an SSN is about a billion guesses.
"""

from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path

from forgd_verdict.hook.device import device_salt, device_salt_path, salt_namespace

ROOT = Path(__file__).resolve().parents[1]


def test_a_salt_is_generated_and_then_stable(tmp_path):
    first = device_salt(tmp_path)
    assert len(first) >= 32
    assert device_salt(tmp_path) == first, "a second call must not re-roll it"


def test_the_salt_file_is_not_world_readable(tmp_path):
    device_salt(tmp_path)
    mode = device_salt_path(tmp_path).stat().st_mode & 0o777
    assert mode == 0o600, oct(mode)


def test_two_devices_get_different_salts(tmp_path):
    a = device_salt(tmp_path / "a")
    b = device_salt(tmp_path / "b")
    assert a != b, "a shared salt would make one lost laptop leak every laptop's"


def test_the_namespace_is_not_the_salt(tmp_path):
    """It is written onto every record. Publishing the salt there would undo
    the point: an export carrying both the hashes and the salt is an export
    carrying the values."""
    salt = device_salt(tmp_path)
    ns = salt_namespace(salt)
    assert ns
    assert salt not in ns
    assert ns not in salt
    # And it is derived, so the same device keeps the same marker.
    assert salt_namespace(salt) == ns


def test_the_namespace_distinguishes_devices(tmp_path):
    """Without it a reader unions two laptops' hashes and reports one
    leaked key as two."""
    assert salt_namespace(device_salt(tmp_path / "a")) != salt_namespace(
        device_salt(tmp_path / "b")
    )


def test_the_deployment_salt_has_an_empty_namespace():
    """Empty means "the deployment salt", which is every server-side
    writer -- so existing records need no migration."""
    assert salt_namespace("") == ""


def test_an_unwritable_state_directory_still_yields_a_salt():
    """A hook that cannot persist a salt must still run AND must still
    refuse to hash unsalted. Failing the developer's action would be the
    wrong trade -- the hook sits in front of what they are trying to do."""
    salt = device_salt("/proc/forgd-does-not-exist")
    assert salt
    assert len(salt) >= 32


def test_a_concurrent_hook_does_not_overwrite_a_salt_in_use(tmp_path):
    """Records written either side of a re-roll would be hashed differently
    with nothing recording that."""
    first = device_salt(tmp_path)
    # Simulate the race: the file exists, so O_EXCL fails and the existing
    # value must win rather than the freshly generated one.
    assert device_salt(tmp_path) == first


def test_the_hook_no_longer_hashes_with_an_empty_salt(trusted_home, monkeypatch):
    """End to end, because this is the exposure being closed.

    An unsalted excerpt_hash is sha256(value). If a spooled hash equals
    that, an export can be swept back to the value by brute force over a
    space of about a billion.
    """
    from forgd_verdict.hook.cli import run
    from forgd_verdict.policy import load_policy

    secret = "AKIAQYLPMN5HGZTHX4UQ"
    spool = trusted_home / ".local" / "state" / "forgd-verdict" / "spool"
    monkeypatch.delenv("FORGD_HASH_SALT", raising=False)

    payload = {
        "hook_event_name": "PreToolUse",
        "tool_name": "Bash",
        "tool_input": {"command": f"aws configure set key {secret}"},
        "session_id": "s1",
    }
    run(payload, load_policy(str(ROOT / "policy.yaml")))

    lines = [
        line
        for f in spool.rglob("*")
        if f.is_file()
        for line in f.read_text().splitlines()
        if line.strip()
    ]
    assert lines, "nothing spooled"

    unsalted = hashlib.sha256(secret.encode()).hexdigest()
    saw_hash = False
    for line in lines:
        record = json.loads(line)
        for finding in record.get("findings") or []:
            digest = finding.get("excerpt_hash")
            if not digest:
                continue
            saw_hash = True
            assert digest != unsalted, "spooled an UNSALTED hash of the secret"
        if record.get("findings"):
            assert record.get("salt_namespace"), (
                "a record whose hashes came from a device salt must say so, "
                "or a reader unions them with the server's"
            )
    assert saw_hash, "expected at least one finding carrying a hash"


def test_the_actor_hash_uses_the_device_salt_too(trusted_home, monkeypatch):
    """It pseudonymises a username. Unsalted, a short list of plausible
    usernames recovers it immediately."""
    from forgd_verdict.hook.cli import run
    from forgd_verdict.policy import load_policy

    spool = trusted_home / ".local" / "state" / "forgd-verdict" / "spool"
    monkeypatch.delenv("FORGD_HASH_SALT", raising=False)
    run(
        {
            "hook_event_name": "PreToolUse",
            "tool_name": "Bash",
            "tool_input": {"command": "echo hello"},
            "session_id": "s2",
        },
        load_policy(str(ROOT / "policy.yaml")),
    )
    lines = [
        line for f in spool.rglob("*") if f.is_file()
        for line in f.read_text().splitlines() if line.strip()
    ]
    for line in lines:
        actor = json.loads(line).get("actor_hash") or ""
        if actor.startswith("user_"):
            bare = hashlib.sha256(os.environ.get("USER", "").encode()).hexdigest()
            assert actor[5:] not in bare, "actor_hash looks unsalted"
