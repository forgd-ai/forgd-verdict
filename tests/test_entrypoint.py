"""The entrypoint's policy-from-environment block.

This block decodes FORGD_POLICY_INLINE_GZ into a file before the app starts.
Its default directory must be one the image creates: the container runs as
uid 10001 and cannot mkdir at the filesystem root, so a default such as
/config makes every deployment carrying an inline policy die on start. The
first test here pins that.

Roles are exercised through the unknown-role exit (64), which the script
reaches only after the policy block has run to completion. That keeps these
tests from needing the app installed.
"""

from __future__ import annotations

import base64
import gzip
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parents[1]
ENTRYPOINT = REPO / "deploy" / "entrypoint.sh"
DOCKERFILE = REPO / "deploy" / "Dockerfile"

UNKNOWN_ROLE_EXIT = 64


def default_policy_dir() -> str:
    """The POLICY_DIR default, read out of the script rather than duplicated."""
    m = re.search(
        r'POLICY_DIR="\$\{FORGD_POLICY_DIR:-([^}]+)\}"', ENTRYPOINT.read_text()
    )
    assert m, "the entrypoint no longer defaults FORGD_POLICY_DIR the way this reads it"
    return m.group(1)


def runtime_uid() -> str:
    m = re.search(r"useradd --system --uid (\d+)", DOCKERFILE.read_text())
    assert m, "the Dockerfile no longer creates the runtime user the way this reads it"
    return m.group(1)


def run_entrypoint(tmp_path: Path, env: dict[str, str]) -> subprocess.CompletedProcess:
    """Run the entrypoint with a `python` on PATH that can import yaml.

    The script's YAML check prefers `python` and falls back to `python3`. On a
    machine where neither resolves to an interpreter with PyYAML the check
    silently passes, so the shim is what keeps these assertions meaningful.
    """
    shim = tmp_path / "bin"
    shim.mkdir(exist_ok=True)
    wrapper = shim / "python"
    # A wrapper, not a symlink: a symlink to the venv interpreter from outside
    # the venv resolves sys.prefix elsewhere and loses site-packages, so yaml
    # would be missing and the script's mapping check would fail for a reason
    # that has nothing to do with the policy.
    wrapper.write_text(f'#!/bin/sh\nexec "{sys.executable}" "$@"\n')
    wrapper.chmod(0o755)
    full = {
        "PATH": f"{shim}:{os.environ.get('PATH', '')}",
        "FORGD_ROLE": "no-such-role",
        **env,
    }
    return subprocess.run(
        ["sh", str(ENTRYPOINT)], env=full, capture_output=True, text=True, timeout=60
    )


def gz(text: str) -> str:
    return base64.b64encode(gzip.compress(text.encode())).decode()


def test_default_policy_dir_is_one_the_image_makes_writable():
    """The default must land under a directory the image chowns to the runtime uid.

    /config failed precisely this: the Dockerfile never created it, so mkdir
    at the root was denied and the container exited 1 before serving. A
    default that only works as root is a default that only works in testing.
    """
    default = default_policy_dir()
    dockerfile = DOCKERFILE.read_text()
    uid = runtime_uid()

    chowned = set(re.findall(rf"chown -R {uid}:{uid} (\S+)", dockerfile))
    chowned |= {
        "/app" for _ in re.findall(r"chown -R forgd:forgd /app", dockerfile)
    }
    assert chowned, "the Dockerfile chowns nothing to the runtime uid"

    parents = {str(p) for p in [Path(default), *Path(default).parents]}
    assert parents & chowned, (
        f"the policy default {default!r} is not under any directory the image "
        f"makes writable for uid {uid} (chowned: {sorted(chowned)}); as uid "
        f"{uid} the container cannot create it and will exit before serving"
    )


def test_default_policy_dir_is_created_by_the_image():
    """Being chowned is not enough -- mkdir -p needs its parent to exist."""
    default = default_policy_dir()
    made = set(re.findall(r"mkdir -p ([^&\\\n]+)", DOCKERFILE.read_text()))
    made = {d for line in made for d in line.split()}
    parents = {str(p) for p in Path(default).parents}
    assert parents & made, (
        f"nothing in the Dockerfile creates a parent of {default!r} "
        f"(created: {sorted(made)})"
    )


def test_inline_gz_policy_is_decoded_to_the_policy_dir(tmp_path):
    policy_dir = tmp_path / "policy"
    r = run_entrypoint(
        tmp_path,
        {
            "FORGD_POLICY_DIR": str(policy_dir),
            "FORGD_POLICY_INLINE_GZ": gz("mode: observe\ndetectors: {}\n"),
        },
    )
    assert r.returncode == UNKNOWN_ROLE_EXIT, r.stderr
    written = policy_dir / "policy.yaml"
    assert written.read_text() == "mode: observe\ndetectors: {}\n"
    assert "policy: from the environment" in r.stderr
    # The temporary file is renamed, never left behind.
    assert list(policy_dir.iterdir()) == [written]


def test_inline_plain_policy_is_written(tmp_path):
    policy_dir = tmp_path / "policy"
    r = run_entrypoint(
        tmp_path,
        {
            "FORGD_POLICY_DIR": str(policy_dir),
            "FORGD_POLICY_INLINE": "mode: enforce\n",
        },
    )
    assert r.returncode == UNKNOWN_ROLE_EXIT, r.stderr
    assert (policy_dir / "policy.yaml").read_text() == "mode: enforce\n"


def test_no_inline_policy_leaves_the_baked_one_alone(tmp_path):
    policy_dir = tmp_path / "policy"
    r = run_entrypoint(tmp_path, {"FORGD_POLICY_DIR": str(policy_dir)})
    assert r.returncode == UNKNOWN_ROLE_EXIT, r.stderr
    assert not policy_dir.exists()
    assert "policy: from the environment" not in r.stderr


def test_truncated_gz_refuses_to_start(tmp_path):
    """A truncated stream emits valid YAML before failing; it must not be used."""
    policy_dir = tmp_path / "policy"
    blob = gzip.compress(("mode: observe\n" + "detectors: {}\n" * 200).encode())
    r = run_entrypoint(
        tmp_path,
        {
            "FORGD_POLICY_DIR": str(policy_dir),
            "FORGD_POLICY_INLINE_GZ": base64.b64encode(blob[:-20]).decode(),
        },
    )
    assert r.returncode == 1
    assert "did not decode" in r.stderr
    assert not (policy_dir / "policy.yaml").exists()
    assert list(policy_dir.iterdir()) == []


def test_policy_that_is_not_a_mapping_refuses_to_start(tmp_path):
    policy_dir = tmp_path / "policy"
    r = run_entrypoint(
        tmp_path,
        {
            "FORGD_POLICY_DIR": str(policy_dir),
            "FORGD_POLICY_INLINE_GZ": gz("- one\n- two\n"),
        },
    )
    assert r.returncode == 1
    assert "not a YAML mapping" in r.stderr
    assert not (policy_dir / "policy.yaml").exists()


def test_empty_decode_refuses_to_start(tmp_path):
    policy_dir = tmp_path / "policy"
    r = run_entrypoint(
        tmp_path,
        {"FORGD_POLICY_DIR": str(policy_dir), "FORGD_POLICY_INLINE_GZ": gz("")},
    )
    assert r.returncode == 1
    assert "decoded to nothing" in r.stderr


@pytest.mark.skipif(os.geteuid() == 0, reason="root can write anywhere")
def test_unwritable_policy_dir_fails_loudly(tmp_path):
    """The failure the deploy actually hit, named rather than swallowed."""
    locked = tmp_path / "locked"
    locked.mkdir()
    locked.chmod(0o500)
    try:
        r = run_entrypoint(
            tmp_path,
            {
                "FORGD_POLICY_DIR": str(locked / "policy"),
                "FORGD_POLICY_INLINE_GZ": gz("mode: observe\n"),
            },
        )
        assert r.returncode == 1
        assert "cannot create" in r.stderr
        assert "set FORGD_POLICY_DIR" in r.stderr
    finally:
        locked.chmod(0o700)


def test_a_rerun_replaces_the_read_only_policy(tmp_path):
    """The written policy is 0400; a restart over a persisted dir must still update."""
    policy_dir = tmp_path / "policy"
    env = {"FORGD_POLICY_DIR": str(policy_dir)}
    first = run_entrypoint(tmp_path, {**env, "FORGD_POLICY_INLINE_GZ": gz("mode: observe\n")})
    assert first.returncode == UNKNOWN_ROLE_EXIT, first.stderr
    assert (policy_dir / "policy.yaml").stat().st_mode & 0o777 == 0o400

    second = run_entrypoint(tmp_path, {**env, "FORGD_POLICY_INLINE_GZ": gz("mode: enforce\n")})
    assert second.returncode == UNKNOWN_ROLE_EXIT, second.stderr
    assert (policy_dir / "policy.yaml").read_text() == "mode: enforce\n"


def test_the_daemon_deadline_is_not_shorter_than_the_probe_that_waits_for_it():
    """gitleaksd compiles the rule set before it creates the socket.

    The entrypoint exits if the socket does not appear, so that deadline
    is a bound on the compile. At 5 s it was shorter than every
    startupProbe window in the chart: on a throttled node the entrypoint
    left while kubelet was still waiting, and a probe cannot keep alive a
    process that already exited.
    """
    script = ENTRYPOINT.read_text()
    m = re.search(r'limit="\$\{FORGD_GITLEAKSD_WAIT_S:-(\d+)\}"', script)
    assert m, "the daemon wait is no longer a named, overridable limit"
    deadline_s = int(m.group(1))

    chart = REPO / "deploy" / "helm" / "forgd-verdict" / "templates"
    windows = []
    for tmpl in chart.glob("*.yaml"):
        text = tmpl.read_text()
        if "FORGD_GITLEAKS_SOCKET" not in text:
            continue
        probe = re.search(
            r"startupProbe:.*?periodSeconds:\s*(\d+).*?failureThreshold:\s*(\d+)",
            text, re.S)
        assert probe, f"{tmpl.name} runs gitleaksd with no startupProbe"
        windows.append((tmpl.name, int(probe.group(1)) * int(probe.group(2))))

    assert windows, "no role was found running gitleaksd"
    for name, window_s in windows:
        assert deadline_s >= window_s, (
            f"{name} waits {window_s}s for the app but the entrypoint gives "
            f"gitleaksd only {deadline_s}s, so a slow compile is a crash loop"
        )


# A stand-in gitleaksd: records its argv, then creates the socket the
# entrypoint waits for.
FAKE_GITLEAKSD = """#!{python}
import json, os, socket, sys, time
argv = sys.argv[1:]
with open(os.environ["FAKE_GITLEAKSD_ARGV"], "w") as fh:
    json.dump(argv, fh)
s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
s.bind(argv[argv.index("--socket") + 1])
time.sleep(5)
"""

# A stand-in app: records the FORGD_GITLEAKS_CONFIG it was started with.
FAKE_APP = """#!/bin/sh
printf '%s' "${FORGD_GITLEAKS_CONFIG:-}" > "$FAKE_APP_ENV"
"""


@pytest.fixture
def daemon_role(tmp_path):
    """Run a daemon role (`server` unless named) with a fake gitleaksd and a
    fake app on PATH."""
    shim = tmp_path / "bin"
    shim.mkdir()
    (shim / "gitleaksd").write_text(FAKE_GITLEAKSD.format(python=sys.executable))
    (shim / "forgd-verdict").write_text(FAKE_APP)
    for f in ("gitleaksd", "forgd-verdict"):
        (shim / f).chmod(0o755)
    # Not tmp_path: macOS caps a Unix socket path at 104 bytes.
    sock_dir = Path(tempfile.mkdtemp(prefix="gl", dir="/tmp"))
    argv, app_env = tmp_path / "argv.json", tmp_path / "app-env"

    def run(policy: str, env: dict[str, str] | None = None, role: str = "server"):
        path = tmp_path / "policy.yaml"
        path.write_text(policy)
        r = run_entrypoint(tmp_path, {
            "FORGD_ROLE": role,
            "FORGD_VERDICT_POLICY": str(path),
            "FORGD_GITLEAKS_SOCKET": str(sock_dir / "gl.sock"),
            "FAKE_GITLEAKSD_ARGV": str(argv),
            "FAKE_APP_ENV": str(app_env),
            **(env or {}),
        })
        daemon = json.loads(argv.read_text()) if argv.exists() else None
        app = app_env.read_text() if app_env.exists() else None
        return r, daemon, app

    yield run
    shutil.rmtree(sock_dir, ignore_errors=True)


def _daemon_config(argv: list[str]) -> str:
    return argv[argv.index("--config") + 1]


def test_the_policy_gitleaks_config_is_what_the_daemon_loads(daemon_role, tmp_path):
    rules = tmp_path / "rules.toml"
    r, daemon, app = daemon_role(
        "server:\n  detectors:\n    gitleaks:\n"
        f"      daemon: $FORGD_GITLEAKS_SOCKET\n      config: {rules}\n")
    assert r.returncode == 0, r.stderr
    assert _daemon_config(daemon) == os.path.realpath(rules)
    assert app == os.path.realpath(rules)


def test_profiles_that_disagree_on_the_gitleaks_config_refuse_to_start(
        daemon_role, tmp_path):
    a, b = tmp_path / "a.toml", tmp_path / "b.toml"
    r, daemon, app = daemon_role(
        "server:\n  detectors:\n    gitleaks:\n"
        f"      daemon: $FORGD_GITLEAKS_SOCKET\n      config: {a}\n"
        "hook:\n  detectors:\n    gitleaks:\n"
        f"      daemon: $FORGD_GITLEAKS_SOCKET\n      config: {b}\n",
        role="intake")
    assert r.returncode != 0
    assert daemon is None and app is None
    assert "detectors.gitleaks.config" in r.stderr
    assert os.path.realpath(a) in r.stderr and os.path.realpath(b) in r.stderr


@pytest.mark.parametrize("role, wanted", [("server", "a.toml"), ("collect", "b.toml")])
def test_each_role_loads_its_own_profiles_gitleaks_config(
        daemon_role, tmp_path, role, wanted):
    a, b = tmp_path / "a.toml", tmp_path / "b.toml"
    r, daemon, app = daemon_role(
        "server:\n  detectors:\n    gitleaks:\n"
        f"      daemon: $FORGD_GITLEAKS_SOCKET\n      config: {a}\n"
        "otel:\n  detectors:\n    gitleaks:\n"
        f"      daemon: $FORGD_GITLEAKS_SOCKET\n      config: {b}\n",
        role=role)
    assert r.returncode == 0, r.stderr
    assert _daemon_config(daemon) == os.path.realpath(tmp_path / wanted)
    assert app == os.path.realpath(tmp_path / wanted)


def test_an_env_config_that_differs_from_the_policy_refuses_to_start(
        daemon_role, tmp_path):
    rules, other = tmp_path / "rules.toml", tmp_path / "other.toml"
    r, daemon, app = daemon_role(
        "server:\n  detectors:\n    gitleaks:\n"
        f"      daemon: $FORGD_GITLEAKS_SOCKET\n      config: {rules}\n",
        {"FORGD_GITLEAKS_CONFIG": str(other)})
    assert r.returncode != 0
    assert daemon is None and app is None
    assert "FORGD_GITLEAKS_CONFIG" in r.stderr
    assert os.path.realpath(rules) in r.stderr and os.path.realpath(other) in r.stderr


def test_with_no_gitleaks_config_set_the_daemon_loads_the_baseline(daemon_role):
    from forgd_verdict.detectors.gitleaks import BASELINE_CONFIG

    r, daemon, app = daemon_role(
        "server:\n  detectors:\n    gitleaks:\n"
        "      daemon: $FORGD_GITLEAKS_SOCKET\n")
    assert r.returncode == 0, r.stderr
    assert _daemon_config(daemon) == str(BASELINE_CONFIG)
    assert app == str(BASELINE_CONFIG)


def test_the_baked_suffix_list_is_seeded_into_a_writable_cache(tmp_path):
    """tldextract locks beside its cache file even to read it, so the copy
    baked into the read-only image cannot be the cache. The entrypoint
    copies it where TLDEXTRACT_CACHE points; without that, Presidio's
    email recognizer fetched publicsuffix.org on every start."""
    seed = tmp_path / "seed"
    (seed / "publicsuffix.org-tlds").mkdir(parents=True)
    (seed / "publicsuffix.org-tlds" / "list.json").write_text("{}")
    cache = tmp_path / "cache"
    run_entrypoint(tmp_path, {
        "TLDEXTRACT_SEED": str(seed), "TLDEXTRACT_CACHE": str(cache),
        "FORGD_POLICY_DIR": str(tmp_path / "policy")})
    assert (cache / "publicsuffix.org-tlds" / "list.json").read_text() == "{}"


def test_no_seed_means_the_cache_is_left_alone(tmp_path):
    """The base image has no Presidio and no seed; nothing is created."""
    cache = tmp_path / "cache"
    run_entrypoint(tmp_path, {"TLDEXTRACT_CACHE": str(cache),
                              "FORGD_POLICY_DIR": str(tmp_path / "policy")})
    assert not cache.exists()


def test_the_connector_role_runs_the_connector_and_it_refuses_unconfigured(tmp_path):
    """Dispatch reaches `python -m forgd_verdict.connector`, which exits 2
    rather than serving when the connector is not enabled."""
    r = run_entrypoint(tmp_path, {"FORGD_ROLE": "connector",
                                  "FORGD_POLICY_DIR": str(tmp_path / "config")})
    assert r.returncode == 2, (r.stdout, r.stderr)
    assert "refusing to start the connector" in r.stderr
    assert "unknown FORGD_ROLE" not in r.stderr


def _ingest_argv(tmp_path: Path, args: str | None) -> list[str]:
    """The argv the ingest role execs, from a stub `forgd-verdict` on PATH."""
    shim = tmp_path / "bin"
    shim.mkdir(exist_ok=True)
    stub = shim / "forgd-verdict"
    stub.write_text('#!/bin/sh\nfor a in "$@"; do printf "%s\\n" "$a"; done\n')
    stub.chmod(0o755)
    (tmp_path / "match-me").write_text("")
    env = {"FORGD_ROLE": "ingest", "FORGD_POLICY_DIR": str(tmp_path / "config")}
    if args is not None:
        env["FORGD_INGEST_ARGS"] = args
    full = {"PATH": f"{shim}:{os.environ.get('PATH', '')}", **env}
    r = subprocess.run(["sh", str(ENTRYPOINT)], env=full, capture_output=True, text=True,
                       timeout=60, cwd=tmp_path)
    assert r.returncode == 0, (r.stdout, r.stderr)
    return r.stdout.splitlines()


def test_ingest_args_split_on_whitespace(tmp_path):
    assert _ingest_argv(tmp_path, "--family  local\t--once") == [
        "ingest", "--family", "local", "--once"]


def test_ingest_args_are_not_globbed(tmp_path):
    assert _ingest_argv(tmp_path, "--org *") == ["ingest", "--org", "*"]


@pytest.mark.parametrize("args", [None, "", "   "])
def test_no_ingest_args_pass_no_arguments(tmp_path, args):
    assert _ingest_argv(tmp_path, args) == ["ingest"]


def _dashboard(tmp_path: Path, serve_open: str | None) -> subprocess.CompletedProcess:
    """The dashboard role, with a stub `forgd-verdict` that prints its argv."""
    shim = tmp_path / "bin"
    shim.mkdir(exist_ok=True)
    stub = shim / "forgd-verdict"
    stub.write_text('#!/bin/sh\nfor a in "$@"; do printf "%s\\n" "$a"; done\n')
    stub.chmod(0o755)
    env = {"PATH": f"{shim}:{os.environ.get('PATH', '')}", "FORGD_ROLE": "dashboard",
           "PORT": "8080"}
    if serve_open is not None:
        env["FORGD_DASHBOARD_SERVE_OPEN"] = serve_open
    return subprocess.run(["sh", str(ENTRYPOINT)], env=env, capture_output=True, text=True,
                          timeout=60, cwd=tmp_path)


DASHBOARD_ARGV = ["dashboard", "--host", "0.0.0.0", "--port", "8080"]


def test_serve_open_true_passes_serve_open(tmp_path):
    r = _dashboard(tmp_path, "true")
    assert r.returncode == 0, (r.stdout, r.stderr)
    assert r.stdout.splitlines() == [*DASHBOARD_ARGV, "--serve-open"]


@pytest.mark.parametrize("value", [None, ""], ids=["unset", "empty"])
def test_no_serve_open_passes_nothing_extra(tmp_path, value):
    r = _dashboard(tmp_path, value)
    assert r.returncode == 0, (r.stdout, r.stderr)
    assert r.stdout.splitlines() == DASHBOARD_ARGV


@pytest.mark.parametrize("value", ["1", "yes", "TRUE", "True", "true ", "false", "0"])
def test_any_other_serve_open_value_refuses_to_start(tmp_path, value):
    r = _dashboard(tmp_path, value)
    assert r.returncode == 1, (r.stdout, r.stderr)
    assert r.stdout == ""
    assert "FORGD_DASHBOARD_SERVE_OPEN is set but is not 'true'" in r.stderr


def test_the_image_installs_the_extra_each_role_imports():
    """A role whose extra is missing starts, fails its import, and exits:
    the connector would say which extra, but only once the pod is running."""
    m = re.search(r"'forgd-verdict\[([a-z,-]+)\]'", DOCKERFILE.read_text())
    assert m, "the Dockerfile no longer installs the package the way this reads it"
    extras = set(m.group(1).split(","))
    assert {"server", "dashboard", "connector"} <= extras, extras
