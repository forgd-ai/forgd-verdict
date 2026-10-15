"""verify_deployment.sh — the gate that decides whether a deploy finishes.

Every deployment path calls this script, so a silent regression here would
mean each of them reporting success while asserting nothing.

Driven against a stub that answers whatever a case needs, because the point of
the script is that it speaks HTTP and nothing else -- so a test needs no cloud,
no credentials and no deployment.
"""

from __future__ import annotations

import json
import subprocess
import sys
import threading
from collections import Counter
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
SCRIPT = ROOT / "src" / "forgd_verdict" / "verify_deployment.sh"

# A healthy service: /healthz 200 with a low uptime, the protected endpoints
# refusing, the root refusing. Each case overrides only what it is about.
HEALTHY_VERDICT = {
    ("GET", "/healthz"): (200, {"status": "ok", "uptime_s": 3.0}, {}),
    ("POST", "/hook"): (401, {"error": "invalid_signature"}, {}),
}
# The collector is probed at /health, not /healthz. It answers both
# (otel/app.py), and the alias is what lets a deployment that path-routes
# every service off one hostname reach this one -- /healthz there can only
# belong to a single backend. Both are served here so the stub matches the
# app rather than only the call the script happens to make.
HEALTHY_COLLECTOR = {
    ("GET", "/healthz"): (200, {"status": "ok", "uptime_s": 3.0}, {}),
    ("GET", "/health"): (200, {"status": "ok", "uptime_s": 3.0}, {}),
    ("POST", "/v1/logs"): (401, {"error": "unauthorized"}, {}),
}
HEALTHY_DASHBOARD = {
    ("GET", "/healthz"): (200, {"status": "ok", "uptime_s": 3.0}, {}),
    ("GET", "/"): (401, {"error": "authentication_required"}, {}),
    ("GET", "/api/summary"): (401, {"error": "authentication_required"}, {}),
}


class _Stub:
    """One service. `routes` maps (method, path) -> (status, body, headers).
    `hits` counts the requests answered per (method, path)."""

    def __init__(self, routes: dict):
        self.routes = routes
        self.hits: Counter[tuple[str, str]] = Counter()
        outer = self

        class Handler(BaseHTTPRequestHandler):
            def _answer(self, method: str) -> None:
                outer.hits[(method, self.path)] += 1
                status, body, headers = outer.routes.get(
                    (method, self.path), (404, {"error": "not_found"}, {})
                )
                payload = json.dumps(body).encode() if body is not None else b""
                self.send_response(status)
                for k, v in headers.items():
                    self.send_header(k, v)
                self.send_header("content-type", "application/json")
                self.send_header("content-length", str(len(payload)))
                self.end_headers()
                self.wfile.write(payload)

            def do_GET(self):  # noqa: N802
                self._answer("GET")

            def do_POST(self):  # noqa: N802
                self.rfile.read(int(self.headers.get("content-length") or 0))
                self._answer("POST")

            def log_message(self, *a):  # keep pytest output readable
                pass

        self.server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        self.url = f"http://127.0.0.1:{self.server.server_port}"
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()

    def close(self) -> None:
        self.server.shutdown()
        self.server.server_close()


@pytest.fixture
def stub():
    made: list[_Stub] = []

    def make(routes: dict) -> str:
        s = _Stub(routes)
        made.append(s)
        return s.url

    yield make
    for s in made:
        s.close()


def run(verdict="", collector="", dashboard="", *, command=None, **env):
    """Run the verifier. Short timeouts so a failing case does not wait 240s."""
    import os

    environ = {
        **os.environ,
        "VERIFY_READY_TIMEOUT_S": "6",
        "VERIFY_REQUEST_TIMEOUT_S": "4",
        "VERIFY_POLL_INTERVAL_S": "1",
        **{k: str(v) for k, v in env.items()},
    }
    return subprocess.run(
        [*(command or ["bash", str(SCRIPT)]), verdict, collector, dashboard],
        capture_output=True, text=True, timeout=180, env=environ,
    )


# --- the happy path ------------------------------------------------------


def test_a_healthy_stack_passes_every_assertion(stub):
    r = run(stub(HEALTHY_VERDICT), stub(HEALTHY_COLLECTOR), stub(HEALTHY_DASHBOARD))
    assert r.returncode == 0, r.stdout + r.stderr
    out = r.stdout + r.stderr
    for assertion in ("verdict.unsigned-post", "collector.unauthenticated-post",
                      "dashboard.root-requires-auth"):
        assert f"PASS [{assertion}]" in out, out
    assert "7 assertion(s) passed" in out


def test_the_cli_runs_the_packaged_script(stub):
    r = run(stub(HEALTHY_VERDICT), stub(HEALTHY_COLLECTOR), stub(HEALTHY_DASHBOARD),
            command=[sys.executable, "-m", "forgd_verdict.cli", "verify-deployment"])
    assert r.returncode == 0, r.stdout + r.stderr
    assert "7 assertion(s) passed" in r.stdout + r.stderr


def test_the_cli_passes_the_scripts_exit_status_through(stub):
    r = run(stub({}), "", "",
            command=[sys.executable, "-m", "forgd_verdict.cli", "verify-deployment"])
    assert r.returncode == 1, r.stdout + r.stderr
    usage = subprocess.run([sys.executable, "-m", "forgd_verdict.cli", "verify-deployment"],
                           capture_output=True, text=True, timeout=30)
    assert usage.returncode == 2
    assert "usage: verify_deployment.sh" in usage.stderr


def test_the_repository_path_is_the_packaged_script():
    link = ROOT / "scripts" / "verify_deployment.sh"
    assert link.is_symlink()
    assert link.resolve() == SCRIPT


# --- the assertions that matter ------------------------------------------


def test_a_verdict_server_accepting_unsigned_posts_fails(stub):
    """The one failure that must never reach production: a 200 means the app
    came up accepting unsigned traffic."""
    routes = {**HEALTHY_VERDICT, ("POST", "/hook"): (200, {"action": "allow"}, {})}
    r = run(stub(routes))
    assert r.returncode == 1
    assert "FAIL [verdict.unsigned-post]" in r.stdout + r.stderr


def test_a_collector_accepting_unauthenticated_exports_fails(stub):
    routes = {**HEALTHY_COLLECTOR, ("POST", "/v1/logs"): (200, {}, {})}
    r = run(stub(HEALTHY_VERDICT), stub(routes))
    assert r.returncode == 1
    assert "FAIL [collector.unauthenticated-post]" in r.stdout + r.stderr


def test_an_unauthenticated_dashboard_fails(stub):
    routes = {**HEALTHY_DASHBOARD, ("GET", "/"): (200, {"findings": []}, {})}
    r = run(stub(HEALTHY_VERDICT), "", stub(routes))
    assert r.returncode == 1
    assert "FAIL [dashboard.root-requires-auth]" in r.stdout + r.stderr


def test_an_auth_proxy_that_redirects_is_caught(stub):
    """A login redirect in front of the verdict server turns every governed
    prompt into a webhook failure rather than a deny."""
    routes = {
        **HEALTHY_VERDICT,
        ("POST", "/hook"): (302, None, {"location": "https://login.microsoftonline.com/x"}),
    }
    r = run(stub(routes))
    assert r.returncode == 1
    assert "FAIL [verdict.no-auth-redirect]" in r.stdout + r.stderr


def test_an_auth_proxy_that_answers_401_passes_and_that_is_the_known_gap(stub):
    """**Pinned deliberately.** An auth front end configured to answer 401
    rather than redirect is indistinguishable from the app's own refusal, so
    it passes -- while refusing Anthropic's signed requests too.

    This replaced an `az containerapp auth show` query that could tell the
    difference but needed a credential and answered only for Azure. The gap
    is documented in README.md, CLAUDE.md and the script header. If someone
    later closes it, this test is what tells them they changed the contract.
    """
    routes = {
        **HEALTHY_VERDICT,
        ("POST", "/hook"): (401, None, {"www-authenticate": 'Bearer realm="proxy"'}),
    }
    r = run(stub(routes))
    assert r.returncode == 0, r.stdout + r.stderr
    assert "PASS [verdict.unsigned-post]" in r.stdout + r.stderr


# --- freshness -----------------------------------------------------------


def test_an_old_revision_still_serving_fails_the_freshness_bound(stub):
    """A 401 from the revision this deploy is replacing proves nothing about
    the image being rolled."""
    routes = {**HEALTHY_VERDICT,
              ("GET", "/healthz"): (200, {"status": "ok", "uptime_s": 99999.0}, {})}
    r = run(stub(routes), VERIFY_MAX_UPTIME_S=180)
    assert r.returncode == 1
    assert "FAIL [verdict.health-fresh]" in r.stdout + r.stderr


def test_a_fresh_replica_satisfies_the_freshness_bound(stub):
    r = run(stub(HEALTHY_VERDICT), VERIFY_MAX_UPTIME_S=180)
    assert r.returncode == 0, r.stdout + r.stderr
    assert "new replica serving" in r.stdout + r.stderr


def test_an_unreachable_service_fails_rather_than_hanging(stub):
    # Port 1 is reserved and nothing listens on it.
    r = run("http://127.0.0.1:1")
    assert r.returncode == 1
    assert "FAIL [verdict.health]" in r.stdout + r.stderr


# --- the argument contract -----------------------------------------------


def test_an_empty_url_skips_that_service_and_asserts_the_others(stub):
    r = run(stub(HEALTHY_VERDICT), "", stub(HEALTHY_DASHBOARD))
    assert r.returncode == 0, r.stdout + r.stderr
    out = r.stdout + r.stderr
    assert "SKIP [collector]" in out
    assert "PASS [dashboard.root-requires-auth]" in out


def test_verifying_nothing_is_not_a_verification():
    """Accepted, three empty URLs print `verified -- 0 assertion(s) passed`
    and exit 0. `deploy_azure.sh` always passes the verdict URL, but a Helm
    test with empty values would go green having asserted nothing."""
    r = run("", "", "")
    assert r.returncode == 2
    assert "no services to verify" in r.stdout + r.stderr


def test_a_url_without_a_scheme_is_a_usage_error():
    """Otherwise it becomes a relative path and every request fails with the
    same unhelpful 000."""
    r = run("ca-forgd-verdict.example.com")
    assert r.returncode == 2


def test_dropping_an_argument_is_a_usage_error():
    """A caller must not be able to skip a service by forgetting it."""
    r = subprocess.run(["bash", str(SCRIPT), "http://x", ""],
                       capture_output=True, text=True, timeout=60)
    assert r.returncode == 2
    assert "usage:" in r.stdout + r.stderr


# --- the entrypoint's policy delivery -------------------------------------

ENTRYPOINT = Path(__file__).resolve().parent.parent / "deploy" / "entrypoint.sh"


def _run_entrypoint(tmp_path, env):
    import os

    # The entrypoint runs whichever `python` PATH finds first. Without this,
    # an unactivated shell handed it a system interpreter lacking PyYAML and
    # the round-trip tests failed on the environment, not the entrypoint.
    path = os.pathsep.join([str(Path(sys.executable).parent), os.environ.get("PATH", "")])
    return subprocess.run(
        ["sh", str(ENTRYPOINT)], capture_output=True, text=True, timeout=60,
        env={**os.environ, "PATH": path, "FORGD_POLICY_DIR": str(tmp_path / "config"),
             "FORGD_ROLE": "unknown-role-so-it-exits-after-the-policy-step", **env},
    )


def test_policy_from_the_environment_round_trips(tmp_path):
    """Changing a detector threshold must be a config change, not an image
    rebuild. Compressed because the plain file is ~18 KB, above the
    single-variable limit on some targets."""
    import base64
    import gzip

    source = (Path(__file__).resolve().parent.parent / "policy.yaml").read_bytes()
    packed = base64.b64encode(gzip.compress(source)).decode()

    r = _run_entrypoint(tmp_path, {"FORGD_POLICY_INLINE_GZ": packed})
    written = tmp_path / "config" / "policy.yaml"
    assert written.exists(), r.stderr

    import yaml

    assert yaml.safe_load(written.read_text()) == yaml.safe_load(source.decode())


def test_an_undecodable_policy_is_fatal_rather_than_a_silent_fallback(tmp_path):
    """Falling back to the baked default would run rules nobody chose, and
    look exactly like a successful start."""
    r = _run_entrypoint(tmp_path, {"FORGD_POLICY_INLINE_GZ": "not-valid-base64!!"})
    assert r.returncode == 1
    assert "did not decode" in r.stdout + r.stderr
    assert not (tmp_path / "config" / "policy.yaml").exists()


def test_a_truncated_policy_is_refused_rather_than_partially_loaded(tmp_path):
    """A truncated gzip stream emits a valid YAML prefix before reporting
    failure. Swallowing the failure would load a PARTIAL policy that looks
    like a clean start -- running rules nobody chose."""
    import base64
    import gzip

    source = (Path(__file__).resolve().parent.parent / "policy.yaml").read_bytes()
    truncated = gzip.compress(source)[: len(gzip.compress(source)) // 2]
    r = _run_entrypoint(
        tmp_path, {"FORGD_POLICY_INLINE_GZ": base64.b64encode(truncated).decode()}
    )
    assert r.returncode == 1
    assert not (tmp_path / "config" / "policy.yaml").exists()


def test_a_policy_that_is_not_a_mapping_is_refused(tmp_path):
    """It would merge into the defaults as nothing."""
    import base64
    import gzip

    payload = base64.b64encode(gzip.compress(b"just a string")).decode()
    r = _run_entrypoint(tmp_path, {"FORGD_POLICY_INLINE_GZ": payload})
    assert r.returncode == 1


def test_a_rerun_replaces_the_previous_policy(tmp_path):
    """The written file is 0400, so a container restarting over a persisted
    directory could not overwrite it. That failure was swallowed and the OLD
    policy stayed in place under a new revision."""
    import base64
    import gzip

    source = (Path(__file__).resolve().parent.parent / "policy.yaml").read_bytes()
    packed = base64.b64encode(gzip.compress(source)).decode()
    first = _run_entrypoint(tmp_path, {"FORGD_POLICY_INLINE_GZ": packed})
    assert (tmp_path / "config" / "policy.yaml").exists(), first.stderr

    changed = source.replace(b"budget_ms: 1500", b"budget_ms: 1234")
    assert changed != source
    second = _run_entrypoint(
        tmp_path,
        {"FORGD_POLICY_INLINE_GZ": base64.b64encode(gzip.compress(changed)).decode()},
    )
    assert "unknown FORGD_ROLE" in second.stdout + second.stderr
    assert b"budget_ms: 1234" in (tmp_path / "config" / "policy.yaml").read_bytes()


def test_no_inline_policy_leaves_the_baked_default_alone(tmp_path):
    """A deployment that does not override policy must still start."""
    r = _run_entrypoint(tmp_path, {})
    assert not (tmp_path / "config" / "policy.yaml").exists()
    # It got past the policy step to the role dispatch, which is the signal.
    assert "unknown FORGD_ROLE" in r.stdout + r.stderr


# --- which health path each service is probed at -------------------------


def test_the_collector_is_probed_at_its_health_alias(stub):
    """Not /healthz, and the difference is load-bearing.

    A deployment that path-routes all three services off one hostname can
    only give /healthz to one of them. Both the verdict server and the
    collector answer /healthz AND /health, so the alias is what lets a probe
    name a backend there. This stub serves ONLY /health, so the assertion
    fails if the script goes back to appending /healthz.
    """
    collector = {
        ("GET", "/health"): (200, {"status": "ok", "uptime_s": 3.0}, {}),
        ("POST", "/v1/logs"): (401, {"error": "unauthorized"}, {}),
    }
    r = run(stub(HEALTHY_VERDICT), stub(collector), stub(HEALTHY_DASHBOARD))
    assert r.returncode == 0, r.stdout + r.stderr
    assert "PASS [collector.health]" in r.stdout + r.stderr


def test_the_verdict_server_is_still_probed_at_healthz(stub):
    """The alias split only moves the collector. Anthropic's own path and
    the freshness check both hang off the verdict server's /healthz, and
    the deploy gate that caught a container exiting before it bound was
    reading exactly that."""
    verdict = {
        ("GET", "/health"): (200, {"status": "ok", "uptime_s": 3.0}, {}),
        ("POST", "/hook"): (401, {"error": "invalid_signature"}, {}),
    }
    r = run(stub(verdict), stub(HEALTHY_COLLECTOR), stub(HEALTHY_DASHBOARD))
    assert r.returncode != 0
    assert "verdict.health" in r.stdout + r.stderr


# --- FORGD_DASHBOARD_IAP=1: the dashboard behind Identity-Aware Proxy -----

GOOGLE = "https://accounts.google.com/o/oauth2/v2/auth?client_id=x&redirect_uri=y"
IAP_DASHBOARD = {
    ("GET", "/healthz"): (302, None, {"Location": GOOGLE}),
    ("GET", "/"): (302, None, {"Location": GOOGLE}),
    ("GET", "/api/summary"): (302, None, {"Location": GOOGLE}),
}


def test_iap_mode_passes_with_a_google_redirect_on_both_dashboard_paths(stub):
    r = run(stub(HEALTHY_VERDICT), stub(HEALTHY_COLLECTOR), stub(IAP_DASHBOARD), FORGD_DASHBOARD_IAP="1")
    out = r.stdout + r.stderr
    assert r.returncode == 0, out
    assert "PASS [dashboard.iap-healthz]" in out and "PASS [dashboard.iap-root]" in out, out
    assert "dashboard.health" not in out and "dashboard.root-requires-auth" not in out, out
    assert "7 assertion(s) passed" in out


@pytest.mark.parametrize("path,label", [("/healthz", "dashboard.iap-healthz"), ("/", "dashboard.iap-root")])
def test_iap_mode_fails_a_dashboard_path_that_answers_without_sign_in(stub, path, label):
    routes = {**IAP_DASHBOARD, ("GET", path): (200, {"status": "ok", "uptime_s": 3.0}, {})}
    r = run(dashboard=stub(routes), FORGD_DASHBOARD_IAP="1")
    out = r.stdout + r.stderr
    assert r.returncode == 1, out
    assert f"FAIL [{label}]" in out and "without sign-in" in out, out


def test_iap_mode_fails_a_200_at_healthz_at_once_rather_than_polling(stub):
    routes = {**IAP_DASHBOARD, ("GET", "/healthz"): (200, {"status": "ok"}, {})}
    dashboard = _Stub(routes)
    try:
        r = run(dashboard=dashboard.url, FORGD_DASHBOARD_IAP="1")
    finally:
        dashboard.close()
    assert dashboard.hits[("GET", "/healthz")] == 1, dashboard.hits
    assert r.returncode == 1
    assert "FAIL [dashboard.iap-healthz]" in r.stderr


@pytest.mark.parametrize("location", ["https://login.microsoftonline.com/x/oauth2/v2.0/authorize",
                                      "https://dash.example.test/?next=https://accounts.google.com/",
                                      "https://accounts.google.com.attacker.example/o/oauth2/v2/auth"])
def test_iap_mode_fails_a_redirect_somewhere_other_than_google(stub, location):
    routes = {("GET", "/healthz"): (302, None, {"Location": location}),
              ("GET", "/"): (302, None, {"Location": location})}
    r = run(dashboard=stub(routes), FORGD_DASHBOARD_IAP="1")
    out = r.stdout + r.stderr
    assert r.returncode == 1, out
    for label in ("dashboard.iap-healthz", "dashboard.iap-root"):
        assert f"FAIL [{label}]" in out, out
    assert location in out and "302" in out


def test_iap_mode_polls_healthz_until_the_redirect_appears(stub):
    routes = dict(IAP_DASHBOARD)
    routes[("GET", "/healthz")] = (503, None, {})
    url = stub(routes)
    threading.Timer(2.0, lambda: routes.__setitem__(("GET", "/healthz"), IAP_DASHBOARD[("GET", "/healthz")])).start()
    r = run(dashboard=url, FORGD_DASHBOARD_IAP="1")
    assert r.returncode == 0, r.stdout + r.stderr
    assert "PASS [dashboard.iap-healthz]" in r.stdout


def test_iap_mode_fails_an_unreachable_dashboard_as_reachable(stub):
    r = run(dashboard="http://127.0.0.1:1", FORGD_DASHBOARD_IAP="1", VERIFY_READY_TIMEOUT_S="2")
    out = r.stdout + r.stderr
    assert r.returncode == 1, out
    assert "FAIL [dashboard.reachable]" in out, out
    assert "PASS [dashboard" not in out


@pytest.mark.parametrize("value", ["0", "true", "yes", " 1"])
def test_any_iap_value_but_1_is_a_usage_error(stub, value):
    r = run(stub(HEALTHY_VERDICT), "", stub(IAP_DASHBOARD), FORGD_DASHBOARD_IAP=value)
    assert r.returncode == 2, r.stdout + r.stderr
    assert "FORGD_DASHBOARD_IAP" in r.stderr
    assert "PASS" not in r.stdout


@pytest.mark.parametrize("probe", ["health", "post"])
def test_iap_mode_still_fails_a_google_login_redirect_on_verdict_and_collector(stub, probe):
    """Each probe on its own: the health poll and the POST both catch a
    login redirect, and one must not stand in for the other."""
    google = (302, None, {"Location": GOOGLE})
    if probe == "health":
        verdict = {**HEALTHY_VERDICT, ("GET", "/healthz"): google}
        collector = {**HEALTHY_COLLECTOR, ("GET", "/health"): google}
    else:
        verdict = {**HEALTHY_VERDICT, ("POST", "/hook"): google}
        collector = {**HEALTHY_COLLECTOR, ("POST", "/v1/logs"): google}
    r = run(stub(verdict), stub(collector), stub(IAP_DASHBOARD), FORGD_DASHBOARD_IAP="1")
    out = r.stdout + r.stderr
    assert r.returncode == 1, out
    assert "FAIL [verdict.no-auth-redirect]" in out and "FAIL [collector.no-auth-redirect]" in out, out


def test_iap_mode_notes_that_dashboard_freshness_was_not_checked(stub):
    r = run(stub(HEALTHY_VERDICT), "", stub(IAP_DASHBOARD), FORGD_DASHBOARD_IAP="1", VERIFY_MAX_UPTIME_S="60")
    assert r.returncode == 0, r.stdout + r.stderr
    assert "NOTE" in r.stdout and "freshness was not checked" in r.stdout
    # The verdict server's freshness is still asserted.
    assert "new replica serving" in r.stdout


def test_iap_mode_skips_an_empty_dashboard_url(stub):
    r = run(stub(HEALTHY_VERDICT), "", "", FORGD_DASHBOARD_IAP="1")
    assert r.returncode == 0, r.stdout + r.stderr
    assert "SKIP [dashboard] not deployed here" in r.stdout


# --- the findings connector ------------------------------------------------

def _connector_routes(url: str, **override) -> dict:
    """What the real connector app answers, re-addressed to the stub.

    The challenge and the metadata body are taken from a ConnectorApp built
    for an https URL, then that URL is swapped for the stub's, so a change
    to the app's format is a change here too.
    """
    pytest.importorskip("mcp", reason="needs forgd-verdict[connector]")
    from forgd_verdict.connector.app import ConnectorApp
    from forgd_verdict.connector.config import ConnectorConfig
    from forgd_verdict.connector.tools import Reader
    from forgd_verdict.dashboard.auth import AuthConfig

    real = "https://connector.example.test/mcp"
    auth = AuthConfig.parse({"mode": "oidc_jwt", "header": "authorization",
                             "issuer": "https://idp.example.test", "audience": real,
                             "jwks_url": "https://idp.example.test/keys"})
    cfg = ConnectorConfig(resource=real, scopes=(f"{real}/findings.read",),
                          required_scope="findings.read",
                          allowed_origins=("https://claude.ai",), auth=auth)
    app = ConnectorApp(cfg, Reader(store=None, auth=auth))
    prm_path = "/.well-known/oauth-protected-resource/mcp"
    challenge = app.challenge.replace(real.rsplit("/mcp", 1)[0], url)
    body = json.loads(json.dumps(app.metadata()).replace(real, f"{url}/mcp"))
    routes = {
        ("POST", "/mcp"): (401, {"error": "unauthorized"}, {"www-authenticate": challenge}),
        ("GET", prm_path): (200, body, {}),
    }
    routes.update(override)
    return routes


def _connector(stub, **override):
    """A stub connector, and its MCP URL."""
    holder: dict = {}
    base = stub(holder)
    holder.update(_connector_routes(base, **override))
    return f"{base}/mcp"


def test_a_healthy_connector_passes(stub):
    url = _connector(stub)
    r = run(FORGD_CONNECTOR_URL=url)
    assert r.returncode == 0, r.stdout + r.stderr
    assert "PASS [connector.unauthenticated-post]" in r.stdout
    assert "PASS [connector.metadata]" in r.stdout


def test_the_connector_is_not_checked_when_unset(stub):
    r = run(verdict=stub(HEALTHY_VERDICT))
    assert r.returncode == 0, r.stdout + r.stderr
    assert "connector" not in r.stdout


@pytest.mark.parametrize("case,expect", [
    ("no-challenge", "connector.challenge"),
    ("wrong-metadata", "connector.challenge"),
    ("login-redirect", "connector.no-auth-redirect"),
    ("other-redirect", "connector.no-redirect"),
    ("open", "connector.unauthenticated-post"),
    ("no-metadata", "connector.metadata"),
    ("wrong-resource", "connector.metadata-resource"),
    ("no-issuer", "connector.metadata-issuer"),
])
def test_a_broken_connector_fails(stub, case, expect):
    holder: dict = {}
    base = stub(holder)
    routes = _connector_routes(base)
    prm = ("GET", "/.well-known/oauth-protected-resource/mcp")
    post = ("POST", "/mcp")
    if case == "no-challenge":
        routes[post] = (401, {"error": "unauthorized"}, {})
    elif case == "wrong-metadata":
        routes[post] = (401, {}, {"www-authenticate":
                                  'Bearer resource_metadata="https://elsewhere.test/x"'})
    elif case == "login-redirect":
        routes[post] = (302, None, {"location": "https://login.microsoftonline.com/t/oauth2/v2.0/authorize"})
    elif case == "other-redirect":
        routes[post] = (307, None, {"location": "https://www.example.test/mcp"})
    elif case == "open":
        routes[post] = (200, {"jsonrpc": "2.0", "id": 1, "result": {}}, {})
    elif case == "no-metadata":
        del routes[prm]
    elif case == "wrong-resource":
        routes[prm] = (200, dict(routes[prm][1], resource="https://other.test/mcp"), {})
    elif case == "no-issuer":
        routes[prm] = (200, dict(routes[prm][1], authorization_servers=[]), {})
    holder.update(routes)
    r = run(FORGD_CONNECTOR_URL=f"{base}/mcp")
    assert r.returncode == 1, r.stdout + r.stderr
    assert f"FAIL [{expect}]" in r.stderr, r.stderr


def test_a_connector_url_without_a_scheme_is_a_usage_error():
    r = run(FORGD_CONNECTOR_URL="connector.example.test/mcp")
    assert r.returncode == 2 and "connector base URL must start with" in r.stderr


# --- the intake, when FORGD_INTAKE_URL is set ----------------------------

HEALTHY_INTAKE = {
    ("GET", "/healthz"): (200, {"status": "ok", "uptime_s": 3.0}, {}),
    ("POST", "/intake"): (401, {"error": "unauthorized"}, {}),
    ("POST", "/scan"): (401, {"error": "unauthorized"}, {}),
}


def test_a_healthy_intake_passes(stub):
    r = run(stub(HEALTHY_VERDICT), "", "", FORGD_INTAKE_URL=stub(HEALTHY_INTAKE))
    assert r.returncode == 0, r.stdout + r.stderr
    assert "PASS [intake.unauthenticated-post]" in r.stdout
    assert "PASS [intake.health]" in r.stdout


def test_an_intake_behind_a_login_redirect_fails(stub):
    routes = {**HEALTHY_INTAKE,
              ("POST", "/intake"): (302, None, {"Location": "https://login.microsoftonline.com/x/oauth2/v2.0/authorize"})}
    r = run(stub(HEALTHY_VERDICT), "", "", FORGD_INTAKE_URL=stub(routes))
    assert r.returncode == 1
    assert "FAIL [intake.no-auth-redirect]" in r.stderr


def test_an_intake_accepting_unauthenticated_batches_fails(stub):
    routes = {**HEALTHY_INTAKE, ("POST", "/intake"): (200, {"accepted": 0}, {})}
    r = run(stub(HEALTHY_VERDICT), "", "", FORGD_INTAKE_URL=stub(routes))
    assert r.returncode == 1
    assert "FAIL [intake.unauthenticated-post]" in r.stderr


def test_the_intake_alone_is_a_verification(stub):
    r = run("", "", "", FORGD_INTAKE_URL=stub(HEALTHY_INTAKE))
    assert r.returncode == 0, r.stdout + r.stderr


def test_an_intake_url_without_a_scheme_is_a_usage_error(stub):
    r = run(stub(HEALTHY_VERDICT), "", "", FORGD_INTAKE_URL="intake.example.com")
    assert r.returncode == 2


def test_without_an_intake_url_the_intake_is_not_probed(stub):
    intake = _Stub(HEALTHY_INTAKE)
    try:
        r = run(stub(HEALTHY_VERDICT), "", "")
        assert r.returncode == 0, r.stdout + r.stderr
        assert not intake.hits and "intake" not in r.stdout
    finally:
        intake.close()


# --- what counts as a protected dashboard ---------------------------------
#
# The dashboard's own answer to an unauthenticated request is a 401. A front
# end in front of it may answer instead, and the answer has to be read for
# what it proves: a redirect to a sign-in page, or a 401, is authentication;
# any other redirect, and any 403, is something a proxy or WAF also sends in
# front of an open dashboard, so it proves nothing.

APP_401 = (401, {"error": "authentication_required"}, {})
OPEN = (200, {"findings": []}, {})


def _dashboard(root, summary=None):
    return {("GET", "/healthz"): (200, {"status": "ok", "uptime_s": 3.0}, {}),
            ("GET", "/"): root,
            ("GET", "/api/summary"): summary if summary is not None else root}


def _redirect(location, code=302):
    return (code, None, {"Location": location})


PROTECTED = {
    "app-401": APP_401,
    "proxy-401-no-body": (401, None, {"www-authenticate": 'Bearer realm="alb"'}),
    "easyauth-absolute": _redirect("https://dash.example.test/.auth/login/aad?post_login_redirect_uri=%2F"),
    "easyauth-relative": _redirect("/.auth/login/aad?post_login_redirect_uri=/"),
    "iap-google": _redirect(GOOGLE),
    "alb-cognito": _redirect("https://fv.auth.eu-west-1.amazoncognito.com/oauth2/authorize"
                             "?response_type=code&client_id=abc&redirect_uri=https%3A%2F%2Fdash"),
    "alb-keycloak": _redirect("https://sso.example.test/realms/forgd/protocol/openid-connect/auth"
                              "?response_type=code&client_id=dash&redirect_uri=https%3A%2F%2Fdash"
                              "%2Foauth2%2Fidpresponse&scope=openid&state=x"),
    "alb-generic-idp": _redirect("https://idp.example.test/authorize?client_id=dash&response_type=code"),
    "alb-entra": _redirect("https://login.microsoftonline.com/t/oauth2/v2.0/authorize?client_id=x"),
    "oauth2-proxy": _redirect("/oauth2/start?rd=%2F"),
    "okta": _redirect("https://acme.okta.com/oauth2/v1/authorize?client_id=x&response_type=code"),
    "cloudflare-access": _redirect("https://acme.cloudflareaccess.com/cdn-cgi/access/login/dash.example.test?kid=x"),
    "saml": _redirect("https://idp.example.test/sso?SAMLRequest=abc"),
    "redirect-303": _redirect("/.auth/login/aad", 303),
    "redirect-307": _redirect(GOOGLE, 307),
}


@pytest.mark.parametrize("name", sorted(PROTECTED))
def test_a_dashboard_behind_a_sign_in_passes(stub, name):
    r = run(dashboard=stub(_dashboard(PROTECTED[name])))
    out = r.stdout + r.stderr
    assert r.returncode == 0, out
    assert "PASS [dashboard.root-requires-auth]" in out, out


OPEN_BEHIND_A_FRONT_END = {
    "200": OPEN,
    "proxy-path-redirect": _redirect("https://dash.example.test/dashboard/"),
    "https-upgrade-301": _redirect("https://dash.example.test/", 301),
    "www-308": _redirect("https://www.dash.example.test/", 308),
    "redirect-without-location": (302, None, {}),
    "login-only-in-query": _redirect("https://dash.example.test/?next=/login"),
    "google-only-in-query": _redirect("https://dash.example.test/?next=https://accounts.google.com/"),
    "lookalike-google-host": _redirect("https://accounts.google.com.attacker.example/o/oauth2/v2/auth"),
    "lookalike-entra-host": _redirect("https://login.microsoftonline.com.attacker.example/common"),
    "lookalike-okta-host": _redirect("https://okta.com.attacker.example/x"),
    "fragment-login": _redirect("https://dash.example.test/#/login"),
    "waf-403": (403, None, {}),
    "waf-403-html": (403, {"message": "Request blocked by WAF"}, {}),
    "cloud-run-iam-403": (403, {"error": "Your client does not have permission"}, {}),
    "app-gateway-502": (502, None, {}),
}


@pytest.mark.parametrize("name", sorted(OPEN_BEHIND_A_FRONT_END))
def test_a_root_answer_that_proves_no_authentication_fails(stub, name):
    r = run(dashboard=stub(_dashboard(OPEN_BEHIND_A_FRONT_END[name])))
    out = r.stdout + r.stderr
    assert r.returncode == 1, out
    assert "FAIL [dashboard.root-requires-auth]" in out, out
    assert "PASS [dashboard.root-requires-auth]" not in out, out


def test_a_403_failure_says_why_it_is_not_accepted(stub):
    r = run(dashboard=stub(_dashboard((403, None, {}))))
    assert r.returncode == 1
    assert "403" in r.stderr and "WAF" in r.stderr, r.stderr


@pytest.mark.parametrize("root", ["app-401", "easyauth-absolute", "iap-google", "oauth2-proxy"])
def test_a_front_end_that_protects_only_the_root_fails(stub, root):
    """/api/summary returns the counts the page renders; a rule that sends /
    to sign-in and lets every other path through still publishes them."""
    r = run(dashboard=stub(_dashboard(PROTECTED[root], summary=OPEN)))
    out = r.stdout + r.stderr
    assert r.returncode == 1, out
    assert "FAIL [dashboard.summary-requires-auth]" in out, out


def test_iap_mode_also_requires_the_redirect_on_the_summary(stub):
    routes = {**IAP_DASHBOARD, ("GET", "/api/summary"): OPEN}
    r = run(dashboard=stub(routes), FORGD_DASHBOARD_IAP="1")
    out = r.stdout + r.stderr
    assert r.returncode == 1, out
    assert "FAIL [dashboard.iap-summary]" in out, out


# --- the intake's /scan ----------------------------------------------------

@pytest.mark.parametrize("answer,label", [
    (_redirect("https://login.microsoftonline.com/x/oauth2/v2.0/authorize"), "intake.no-auth-redirect"),
    (_redirect("/.auth/login/aad?post_login_redirect_uri=/scan"), "intake.no-auth-redirect"),
    (_redirect(GOOGLE), "intake.no-auth-redirect"),
    ((200, {"action": "allow"}, {}), "intake.unauthenticated-scan"),
    ((403, None, {}), "intake.unauthenticated-scan"),
    ((404, {"error": "not_found"}, {}), "intake.unauthenticated-scan"),
])
def test_a_scan_route_that_does_not_refuse_with_401_fails(stub, answer, label):
    """A laptop's hook waits on /scan with the same bearer it ships with; a
    sign-in in front of /scan alone sends every verdict to the local
    fallback while /intake still passes."""
    routes = {**HEALTHY_INTAKE, ("POST", "/scan"): answer}
    r = run(stub(HEALTHY_VERDICT), "", "", FORGD_INTAKE_URL=stub(routes))
    assert r.returncode == 1, r.stdout + r.stderr
    assert f"FAIL [{label}]" in r.stderr, r.stderr
    assert "PASS [intake.unauthenticated-post]" in r.stdout
