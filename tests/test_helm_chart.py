"""The Helm chart, rendered and checked against the invariants it exists to hold.

These are not "does it template" tests -- `helm lint` answers that. They are
the properties that took work to learn and that a plausible edit would
quietly undo:

* the dashboard holds a READER identity and no hash salt,
* nothing that authenticates a human is attached to the two paths Anthropic
  posts to,
* the ingest cursor has no volume, because it lives in the store,
* the policy arrives as a mounted file, not through the entrypoint's
  inline-decode branch.

Rendered with the real `helm` binary rather than a template parser: the
failures worth catching are in what Kubernetes receives.
"""

from __future__ import annotations

import re
import secrets
import shlex
import shutil
import subprocess
import tempfile
from pathlib import Path

import pytest
import yaml
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

from forgd_verdict.overrides_signing import encode

REPO = Path(__file__).resolve().parents[1]
CHART = REPO / "deploy" / "helm" / "forgd-verdict"


def overrides_verify_key() -> str:
    """A fresh Ed25519 public key in the form `forgd-verdict overrides keygen` prints."""
    public = Ed25519PrivateKey.generate().public_key()
    return encode(public.public_bytes(Encoding.Raw, PublicFormat.Raw))

helm = shutil.which("helm")
requires_helm = pytest.mark.skipif(helm is None, reason="helm is not installed")

WRITER_ID = "11111111-1111-1111-1111-111111111111"
READER_ID = "22222222-2222-2222-2222-222222222222"

BASE = [
    "--set", "store.url=https://acct.blob.core.windows.net/findings",
    "--set", "image.repository=reg.azurecr.io/forgd-verdict",
    "--set", "image.tag=deadbeef",
    # THE REAL LAYOUT: one repository, tagged twice. With a separate
    # `forgd-verdict-ingest` repository here, `ingest.image.tag` falling back
    # to `image.tag` would look harmless and the fallback would go unnoticed.
    "--set", "ingest.image.repository=reg.azurecr.io/forgd-verdict",
    "--set", "ingest.image.tag=deadbeef-ingest",
    # tls.enabled defaults true and the chart refuses it with neither an
    # issuer nor a secret name, because nginx would serve its self-signed
    # default.
    "--set", "ingress.tls.clusterIssuer=letsencrypt",
    "--set", f"serviceAccounts.writer.clientId={WRITER_ID}",
    "--set", f"serviceAccounts.reader.clientId={READER_ID}",
    "--set", "secrets.hashSalt=a-salt",
    "--set", "secrets.webhookSecret=whsec_AAAA",
    "--set", "secrets.complianceKey=sk-ant-x",
    "--set", "secrets.metricsToken=mtok",
    "--set", "secrets.otelTokens.primary=otok",
    "--set", "orgIds.primary=00000000-0000-0000-0000-000000000000",
    "--set", "ingress.host=verdict.example.test",
    # The shipped policy uses auth.mode: trusted_header, which the chart
    # refuses without this assertion -- see the guard tests below. Set here
    # so every other test renders the realistic configuration rather than
    # one that avoids the question.
    "--set", "dashboard.trustedHeaderStrippedBy=a proxy checked in this test",
    # The same policy needs the dashboard isolated from other pods, or this
    # acknowledgement; test_helm_network_policy.py covers both.
    "--set", "networkPolicy.trustedHeaderWithoutPolicyAcknowledged=true",
    "--set-file", f"policy.inline={REPO / 'policy.yaml'}",
]


def base_without(*needles: str) -> list[str]:
    """BASE minus whole flag/value PAIRS.

    BASE is a flat alternating list, so filtering it by value leaves an
    orphan `--set` and helm fails with "key has no value" -- which looks
    like the refusal a guard test is asserting, so the test passes on
    helm's error rather than the chart's.
    """
    out: list[str] = []
    i = 0
    while i < len(BASE):
        flag, value = BASE[i], BASE[i + 1]
        if not any(n in value for n in needles):
            out += [flag, value]
        i += 2
    return out


def _argv(extra: tuple[str, ...], policy: str | None) -> list[str]:
    """Build the helm command line.

    `policy` needs its own parameter rather than a `--set` in `extra`. Helm
    applies every --set-file AFTER every --set, whatever order the flags
    appear in, so a `--set policy.inline=...` here is silently overridden by
    the base --set-file and the test passes against the wrong input. Two
    --set-file flags for one key resolve last-wins, which is what this does.
    """
    argv = [helm, "template", "rel", str(CHART), *BASE, *extra]
    if policy is not None:
        f = tempfile.NamedTemporaryFile("w", suffix=".yaml", delete=False)
        f.write(policy)
        f.close()
        argv += ["--set-file", f"policy.inline={f.name}"]
    return argv


def render_error_without(key: str) -> str:
    """Render with one BASE key dropped, expecting a refusal."""
    out = subprocess.run(
        [helm, "template", "rel", str(CHART), *base_without(key)],
        capture_output=True, text=True, timeout=120,
    )
    assert out.returncode != 0, f"dropping {key} rendered anyway"
    assert "has no value" not in out.stderr, out.stderr
    return out.stderr


def render(*extra: str, policy: str | None = None) -> list[dict]:
    out = subprocess.run(
        _argv(extra, policy), capture_output=True, text=True, timeout=120
    )
    if out.returncode != 0:
        raise AssertionError(out.stderr.strip())
    return [d for d in yaml.safe_load_all(out.stdout) if d]


def render_error(*extra: str, policy: str | None = None) -> str:
    out = subprocess.run(
        _argv(extra, policy), capture_output=True, text=True, timeout=120
    )
    assert out.returncode != 0, "expected the render to be refused, and it was not"
    return out.stderr


@pytest.fixture(scope="module")
def docs() -> list[dict]:
    return render()


def by_kind(docs: list[dict], kind: str) -> dict[str, dict]:
    return {d["metadata"]["name"]: d for d in docs if d.get("kind") == kind}


def pod_specs(docs: list[dict]) -> dict[str, dict]:
    """Component name -> pod spec, across Deployments and the CronJob."""
    out = {}
    for d in docs:
        if d.get("kind") == "Deployment":
            out[d["metadata"]["labels"]["app.kubernetes.io/component"]] = d["spec"]["template"]["spec"]
        elif d.get("kind") == "CronJob":
            out["ingest"] = d["spec"]["jobTemplate"]["spec"]["template"]["spec"]
    return out


def env_of(spec: dict) -> dict[str, dict]:
    return {e["name"]: e for e in spec["containers"][0].get("env", [])}


# -- identities ----------------------------------------------------------

@requires_helm
def test_every_role_is_rendered(docs):
    assert set(pod_specs(docs)) == {"verdict", "collector", "dashboard", "ingest"}


@requires_helm
def test_only_the_dashboard_runs_on_the_reader_identity(docs):
    """Reader for the one service a human signs into; writer for the rest.

    The dashboard holding write access would mean a compromise of the
    sign-in path could rewrite the findings -- rewriting the evidence.
    """
    specs = pod_specs(docs)
    sas = {name: s["serviceAccountName"] for name, s in specs.items()}
    assert sas["dashboard"].endswith("-reader"), sas
    for role in ("verdict", "collector", "ingest"):
        assert sas[role].endswith("-writer"), sas
    assert sas["dashboard"] != sas["verdict"]


@requires_helm
def test_the_dashboard_azure_client_id_is_the_reader_one(docs):
    """The RBAC split is undone by one wrong env var.

    ManagedIdentityCredential picks the identity named here. Left as the
    writer id, the dashboard authenticates as the writer regardless of which
    service account it runs on.
    """
    specs = pod_specs(docs)
    assert env_of(specs["dashboard"])["AZURE_CLIENT_ID"]["value"] == READER_ID
    for role in ("verdict", "collector", "ingest"):
        assert env_of(specs[role])["AZURE_CLIENT_ID"]["value"] == WRITER_ID


@requires_helm
def test_the_service_accounts_carry_their_own_workload_identity_annotation(docs):
    sas = by_kind(docs, "ServiceAccount")
    writer = next(v for k, v in sas.items() if k.endswith("-writer"))
    reader = next(v for k, v in sas.items() if k.endswith("-reader"))
    assert writer["metadata"]["annotations"]["azure.workload.identity/client-id"] == WRITER_ID
    assert reader["metadata"]["annotations"]["azure.workload.identity/client-id"] == READER_ID


@requires_helm
def test_reusing_one_identity_for_both_is_refused():
    err = render_error("--set", f"serviceAccounts.reader.clientId={WRITER_ID}")
    assert "reader identity" in err


def pod_templates(docs: list[dict]) -> dict[str, dict]:
    """Component name -> pod template, across Deployments and the CronJob."""
    out = {}
    for d in docs:
        if d.get("kind") == "Deployment":
            out[d["metadata"]["labels"]["app.kubernetes.io/component"]] = d["spec"]["template"]
        elif d.get("kind") == "CronJob":
            out["ingest"] = d["spec"]["jobTemplate"]["spec"]["template"]
    return out


@requires_helm
def test_pods_are_labelled_for_the_workload_identity_webhook(docs):
    """The annotation alone does nothing; the webhook reads the pod label.

    Without it the pod gets no projected token, falls back to whatever
    credential the node offers, and the failure surfaces as an empty
    dashboard rather than as an auth error.
    """
    templates = pod_templates(docs)
    assert set(templates) == {"verdict", "collector", "dashboard", "ingest"}
    for name, tmpl in templates.items():
        assert tmpl["metadata"]["labels"].get("azure.workload.identity/use") == "true", name


# -- the hash salt -------------------------------------------------------

@requires_helm
def test_the_dashboard_never_receives_the_hash_salt(docs):
    """It reads every finding hash; the salt beside them is one compromise for both.

    Every role that HASHES gets the salt. The one that only reads does not.
    """
    specs = pod_specs(docs)
    assert "FORGD_HASH_SALT" not in env_of(specs["dashboard"])
    for role in ("verdict", "collector", "ingest"):
        e = env_of(specs[role])["FORGD_HASH_SALT"]
        assert e["valueFrom"]["secretKeyRef"]["key"] == "hash-salt", role
        assert "value" not in e, f"{role}: the salt must be a secret reference, not a literal"


@requires_helm
def test_a_missing_salt_is_refused_rather_than_defaulted():
    """Unsalted, the hash of an SSN is about a billion guesses -- so it is the SSN."""
    err = render_error("--set", "secrets.hashSalt=")
    assert "hashSalt" in err


# -- what Anthropic posts to --------------------------------------------

@requires_helm
def test_the_paths_anthropic_posts_to_carry_no_auth_annotation(docs):
    """The default render. Weak on its own -- the template controls every key
    here, so this cannot fail. The tests below exercise what an operator can
    actually set, which is where the hole was.
    """
    ingresses = by_kind(docs, "Ingress")
    public = next(v for k, v in ingresses.items() if k.endswith("-public"))
    paths = [p["path"] for r in public["spec"]["rules"] for p in r["http"]["paths"]]
    assert paths == ["/hook", "/v1"], paths
    for key in public["metadata"].get("annotations") or {}:
        leaf = key.rsplit("/", 1)[-1]
        assert not leaf.startswith("auth-"), key
        assert leaf != "rewrite-target", key


@requires_helm
@pytest.mark.parametrize(
    "leaf",
    [
        "auth-url",
        "auth-signin",
        "auth-tls-secret",
        "enable-global-auth",
        "rewrite-target",
        "use-regex",
        "configuration-snippet",
        "server-snippet",
        "permanent-redirect",
    ],
)
def test_an_auth_or_rewrite_annotation_on_the_public_object_is_refused(leaf):
    """The hole the object split did not cover.

    `ingress.annotations` is a passthrough map on the very object carrying
    /hook and /v1, so splitting the objects says nothing about it. The
    default render cannot show this, because there the template controls
    every key; the test has to set an annotation and expect a refusal.
    """
    err = render_error(
        "--set", f"ingress.annotations.nginx\\.ingress\\.kubernetes\\.io/{leaf}=x"
    )
    assert "/hook" in err, err


@requires_helm
@pytest.mark.parametrize(
    "leaf",
    ["auth-tls-secret", "auth-tls-verify-client", "server-snippet", "rewrite-target"],
)
def test_server_scoped_annotations_on_the_dashboard_are_refused(leaf):
    """ingress-nginx renders these into the server block, not the location.

    So one set on the dashboard object applies to every path on that
    hostname, /hook included. Requiring a client certificate there turns
    every governed prompt into a webhook failure -- Anthropic does not send
    one -- and separate objects do not help, because the scope is the host.
    """
    err = render_error(
        "--set",
        f"ingress.dashboard.annotations.nginx\\.ingress\\.kubernetes\\.io/{leaf}=x",
    )
    assert "server-scoped" in err, err


@requires_helm
def test_server_scoped_annotations_are_allowed_on_a_separate_dashboard_host():
    """The refusal is about the shared hostname, not about the annotation.

    A deployment that wants mTLS on the dashboard moves it to its own name,
    and nothing then reaches /hook.
    """
    docs = render(
        "--set", "ingress.dashboard.host=dash.example.test",
        "--set",
        "ingress.dashboard.annotations.nginx\\.ingress\\.kubernetes\\.io/auth-tls-secret=ns/tls",
    )
    ingresses = by_kind(docs, "Ingress")
    dash = next(v for k, v in ingresses.items() if k.endswith("-dashboard"))
    public = next(v for k, v in ingresses.items() if k.endswith("-public"))
    assert dash["spec"]["rules"][0]["host"] == "dash.example.test"
    assert public["spec"]["rules"][0]["host"] != dash["spec"]["rules"][0]["host"]
    # Distinct TLS secrets, or cert-manager is asked for one certificate
    # covering a name it was never given.
    assert dash["spec"]["tls"][0]["secretName"] != public["spec"]["tls"][0]["secretName"]


@requires_helm
def test_per_location_auth_on_the_dashboard_is_still_allowed():
    """The guard must not forbid the thing the dashboard object exists for.

    oauth2-proxy in front of the dashboard is the supported arrangement; a
    denylist that blocked auth-url would make the split pointless.
    """
    docs = render(
        "--set",
        "ingress.dashboard.annotations.nginx\\.ingress\\.kubernetes\\.io/auth-url=https://p/oauth2/auth",
    )
    ingresses = by_kind(docs, "Ingress")
    dash = next(v for k, v in ingresses.items() if k.endswith("-dashboard"))
    public = next(v for k, v in ingresses.items() if k.endswith("-public"))
    assert any("auth-url" in k for k in dash["metadata"]["annotations"])
    assert not any("auth-url" in k for k in public["metadata"].get("annotations") or {})
    # One hostname, different objects -- the single-name design is not
    # bought by merging them.
    assert public["spec"]["rules"][0]["host"] == dash["spec"]["rules"][0]["host"]


@requires_helm
@pytest.mark.parametrize(
    "leaf", ["proxy-read-timeout", "proxy-buffer-size", "affinity", "ssl-redirect"]
)
def test_benign_tuning_annotations_are_not_refused(leaf):
    """A denylist broad enough to block ordinary tuning gets edited out.

    This is what keeps the guard from being a nuisance, and it is why it
    names what breaks /hook rather than allowlisting what does not.
    """
    docs = render(
        "--set", f"ingress.annotations.nginx\\.ingress\\.kubernetes\\.io/{leaf}=1"
    )
    public = next(
        v for k, v in by_kind(docs, "Ingress").items() if k.endswith("-public")
    )
    assert any(k.endswith(leaf) for k in public["metadata"]["annotations"])


@requires_helm
def test_no_object_on_the_public_host_uses_a_rewrite_target(docs):
    """A rewrite anywhere on a host re-matches every path on that host.

    ingress-nginx: if rewrite-target is used on any Ingress for a given
    host, the case-insensitive regex location modifier is enforced on ALL
    paths for that host, regardless of which Ingress defined them. One for
    /verdict/* and /collector/* would make /v1 stop being an element-wise
    Prefix match -- /v1anything and /V1/LOGS would reach the collector --
    and what kept /hook ahead of / would be ingress-nginx's location
    ordering rather than the longest-prefix rule.
    """
    ingresses = by_kind(docs, "Ingress")
    public_host = next(
        v for k, v in ingresses.items() if k.endswith("-public")
    )["spec"]["rules"][0]["host"]
    for name, ing in ingresses.items():
        if public_host not in {r["host"] for r in ing["spec"]["rules"]}:
            continue
        for key in ing["metadata"].get("annotations") or {}:
            assert key.rsplit("/", 1)[-1] != "rewrite-target", name


@requires_helm
def test_global_auth_is_opted_out_on_every_path_anthropic_uses(docs):
    """enable-global-auth defaults to TRUE.

    On a cluster whose ingress-nginx ConfigMap sets global-auth-url -- the
    usual way to put oauth2-proxy in front of everything -- /hook and /v1
    are fronted however the objects are split. The split is irrelevant to
    this one, which is why it is set unconditionally rather than offered as
    a value.
    """
    ingresses = by_kind(docs, "Ingress")
    key = "nginx.ingress.kubernetes.io/enable-global-auth"
    for suffix in ("-public", "-diagnostics"):
        ing = next(v for k, v in ingresses.items() if k.endswith(suffix))
        assert ing["metadata"]["annotations"][key] == "false", suffix


@requires_helm
def test_the_diagnostic_paths_are_the_apps_real_paths(docs):
    """No rewrite means no prefix to strip, which is the point.

    Both roles answer /healthz AND /health, so the two aliases are what let
    one hostname send a health probe to a chosen backend. /metrics and
    /stats are already unique to one role each.
    """
    diag = next(
        v for k, v in by_kind(docs, "Ingress").items() if k.endswith("-diagnostics")
    )
    routes = {
        p["path"]: (p["backend"]["service"]["name"], p["pathType"])
        for r in diag["spec"]["rules"] for p in r["http"]["paths"]
    }
    assert routes["/healthz"][0].endswith("-verdict")
    assert routes["/metrics"][0].endswith("-verdict")
    assert routes["/health"][0].endswith("-collector")
    assert routes["/stats"][0].endswith("-collector")
    # Exact renders as `location = /healthz`, which nginx resolves ahead of
    # the dashboard's `/` without depending on ordering.
    assert {t for _, t in routes.values()} == {"Exact"}, routes
    assert not any(p.startswith(("/hook", "/v1")) for p in routes), routes


@requires_helm
def test_the_body_size_limit_matches_what_the_app_accepts(docs):
    """nginx defaults to 1 MB and answers 413 above it.

    A fixed floor such as `>= 8m` passes for a limit well under what the
    app takes -- so nginx could reject a frame the server would have
    scanned and the test would still be green. Tied to policy.yaml's
    hook.max_body_bytes instead, which is the number that actually decides.
    """

    policy = yaml.safe_load((REPO / "policy.yaml").read_text())
    # Both roles are behind this one annotation, so it has to clear the
    # larger: server.max_body_bytes is 64 MiB and otel.max_body_bytes 8 MiB.
    # Letting each app enforce its own limit is also better than nginx
    # guessing -- the app answers with something the caller can act on,
    # nginx answers 413.
    accepted = max(
        int(policy["server"]["max_body_bytes"]),
        int(policy["otel"]["max_body_bytes"]),
    )

    ingresses = by_kind(docs, "Ingress")
    public = next(v for k, v in ingresses.items() if k.endswith("-public"))
    size = public["metadata"]["annotations"][
        "nginx.ingress.kubernetes.io/proxy-body-size"
    ]
    m = re.fullmatch(r"(\d+)([kmg])", size)
    assert m, size
    bytes_ = int(m.group(1)) * {"k": 1024, "m": 1024**2, "g": 1024**3}[m.group(2)]
    assert bytes_ >= accepted, (
        f"nginx would 413 at {size} a frame the app accepts up to {accepted} bytes"
    )


@requires_helm
def test_public_paths_route_to_the_right_backends(docs):
    ingresses = by_kind(docs, "Ingress")
    public = next(v for k, v in ingresses.items() if k.endswith("-public"))
    routes = {
        p["path"]: p["backend"]["service"]["name"]
        for r in public["spec"]["rules"] for p in r["http"]["paths"]
    }
    assert routes["/hook"].endswith("-verdict")
    assert routes["/v1"].endswith("-collector")


# -- the ingest cursor ---------------------------------------------------

@requires_helm
def test_the_ingest_job_has_no_persistent_volume(docs):
    """The cursor lives in the findings store, so there is nothing to mount.

    An emptyDir here is the obvious mistake: it persists within a replica,
    and a scheduled job gets a new replica every run, so the cursor would be
    gone before the next pass read it. It would look like a fix and be none.
    """
    spec = pod_specs(docs)["ingest"]
    volumes = {v["name"]: v for v in spec["volumes"]}
    # policy is the ConfigMap; run, tmp and state are scratch for a
    # read-only root filesystem. Nothing here outlives the pod, which is
    # the point: the cursor lives in the findings store.
    assert set(volumes) == {"policy", "run", "tmp", "state"}, volumes
    assert not any("persistentVolumeClaim" in v for v in volumes.values())
    assert all(
        "emptyDir" in v for n, v in volumes.items() if n != "policy"
    ), volumes
    mounts = {m["mountPath"] for m in spec["containers"][0]["volumeMounts"]}
    assert mounts == {"/etc/forgd", "/run/forgd", "/tmp", "/var/lib/forgd"}, mounts


@requires_helm
def test_no_persistent_volume_claims_anywhere(docs):
    assert not by_kind(docs, "PersistentVolumeClaim")


@requires_helm
def test_the_ingest_cron_cannot_overlap_itself(docs):
    """Two passes against one cursor rescan pages and advance past unfinished work."""
    cron = next(iter(by_kind(docs, "CronJob").values()))
    assert cron["spec"]["concurrencyPolicy"] == "Forbid"


@requires_helm
def test_the_ingest_job_does_not_run_the_base_image(docs):
    """The assertion that matters, stated against the base image itself.

    Two weaker forms of this test miss it. Asserting that with no
    ingest.image.repository the job runs the base image pins in place the
    configuration the chart's own comment calls dangerous. Asserting the
    image starts with `reg.azurecr.io/forgd-verdict-ingest:`, a repository
    that is never built, compares against a fictional string and cannot
    notice that the real one resolved to the base image.

    So: not equal to what the online roles run, and carrying the variant.
    """
    ingest = pod_specs(docs)["ingest"]["containers"][0]["image"]
    online = pod_specs(docs)["verdict"]["containers"][0]["image"]
    # Not what the online roles run -- the assertion the base-image failure
    # is actually about, and the one a fictional-repository prefix check
    # could not make.
    assert ingest != online, ingest
    # And exactly what BASE asked for, so a wrong repository is caught too.
    # Dropping this left `someoneelse/x:deadbeef-ingest` passing.
    assert ingest == "reg.azurecr.io/forgd-verdict:deadbeef-ingest", ingest


@requires_helm
def test_the_ingest_repository_is_read_and_not_image_repository():
    """BASE sets both repositories to the same string, because that is the
    real layout -- which means it cannot tell the two apart.

    A helper reading `image.repository` where it meant
    `ingest.image.repository` would render identically under BASE and be
    invisible. So this one test pulls them apart deliberately.
    """
    docs = render("--set", "ingest.image.repository=other.registry/ingest-only")
    ingest = pod_specs(docs)["ingest"]["containers"][0]["image"]
    assert ingest == "other.registry/ingest-only:deadbeef-ingest", ingest


@requires_helm
def test_the_ingest_repository_has_no_default():
    """Because the wrong one does not fail -- it reports no PII anywhere."""
    err = render_error_without("ingest.image.repository")
    assert "ingest.image.repository is required" in err, err


@requires_helm
def test_the_ingest_tag_has_no_default_either():
    """The half that was missing, and the only one that carries the variant.

    `ingest.image.repository` is the SAME STRING as `image.repository` in
    every real deployment, so requiring it alone checked a value that
    carries no information while the tag fell back to `image.tag` -- the
    base image, under a repository that had just been validated. Adapter 3
    then completes, finds nothing at the Presidio tier because the
    dependency is absent, and reports a clean scan.
    """
    err = render_error_without("ingest.image.tag")
    assert "ingest.image.tag is required" in err, err
    assert "reports clean" in err, err


@requires_helm
def test_dropping_the_ingest_tag_refuses_rather_than_silently_using_the_base(docs):
    """The regression, rendered rather than argued.

    Without a required tag this configuration renders, and the CronJob
    comes out byte-identical to the verdict server's image.
    """
    out = subprocess.run(
        [helm, "template", "rel", str(CHART), *base_without("ingest.image.tag")],
        capture_output=True, text=True, timeout=120,
    )
    assert out.returncode != 0, (
        "rendered with no ingest.image.tag; the CronJob would run "
        + pod_specs(docs)["verdict"]["containers"][0]["image"]
    )


@requires_helm
def test_the_ingest_image_is_only_required_when_ingest_runs():
    """A deployment without adapter 3 should not have to name an image."""
    out = subprocess.run(
        [
            helm, "template", "rel", str(CHART),
            *base_without("ingest.image.repository", "ingest.image.tag"),
            "--set", "ingest.enabled=false",
        ],
        capture_output=True, text=True, timeout=120,
    )
    assert out.returncode == 0, out.stderr


# -- image digests -------------------------------------------------------

BASE_DIGEST = "sha256:" + "a" * 64
INGEST_DIGEST = "sha256:" + "b" * 64


def images(docs: list[dict]) -> dict[str, str]:
    return {role: spec["containers"][0]["image"] for role, spec in pod_specs(docs).items()}


@requires_helm
def test_without_a_digest_every_role_renders_its_tag(docs):
    assert images(docs) == {
        "verdict": "reg.azurecr.io/forgd-verdict:deadbeef",
        "collector": "reg.azurecr.io/forgd-verdict:deadbeef",
        "dashboard": "reg.azurecr.io/forgd-verdict:deadbeef",
        "ingest": "reg.azurecr.io/forgd-verdict:deadbeef-ingest",
    }


@requires_helm
def test_a_digest_replaces_the_tag_for_each_image():
    docs = render("--set", f"image.digest={BASE_DIGEST}",
                  "--set", f"ingest.image.digest={INGEST_DIGEST}")
    assert images(docs) == {
        "verdict": f"reg.azurecr.io/forgd-verdict@{BASE_DIGEST}",
        "collector": f"reg.azurecr.io/forgd-verdict@{BASE_DIGEST}",
        "dashboard": f"reg.azurecr.io/forgd-verdict@{BASE_DIGEST}",
        "ingest": f"reg.azurecr.io/forgd-verdict@{INGEST_DIGEST}",
    }


@requires_helm
@pytest.mark.parametrize("key, value, missing", [
    ("image.digest", BASE_DIGEST, "ingest.image.digest is not"),
    ("ingest.image.digest", INGEST_DIGEST, "image.digest is not"),
])
def test_one_digest_without_the_other_is_refused(key, value, missing):
    err = render_error("--set", f"{key}={value}")
    assert missing in err and "Set both digests, or neither" in err, err


@requires_helm
def test_an_ingest_digest_needs_no_ingest_tag():
    out = subprocess.run(
        [helm, "template", "rel", str(CHART), *base_without("ingest.image.tag"),
         "--set", f"image.digest={BASE_DIGEST}",
         "--set", f"ingest.image.digest={INGEST_DIGEST}"],
        capture_output=True, text=True, timeout=120,
    )
    assert out.returncode == 0, out.stderr
    docs = [d for d in yaml.safe_load_all(out.stdout) if d]
    assert images(docs)["ingest"] == f"reg.azurecr.io/forgd-verdict@{INGEST_DIGEST}"


@requires_helm
def test_an_ingest_job_with_neither_tag_nor_digest_is_refused():
    err = render_error_without("ingest.image.tag")
    assert "unless ingest.image.digest is set" in err, err


@requires_helm
@pytest.mark.parametrize("key", ["image.digest", "ingest.image.digest"])
@pytest.mark.parametrize("value", [
    "a" * 64,                                         # no algorithm
    "sha256:" + "A" * 64,                             # uppercase
    "sha256:" + "a" * 63,                             # short
    "sha256:" + "a" * 65,                             # long
    "sha512:" + "a" * 64,                             # another algorithm
    "@sha256:" + "a" * 64,                            # leading @
    "reg.azurecr.io/forgd-verdict@sha256:" + "a" * 64,  # a whole reference
])
def test_a_malformed_digest_is_refused(key, value):
    other = "ingest.image.digest" if key == "image.digest" else "image.digest"
    valid = INGEST_DIGEST if other == "ingest.image.digest" else BASE_DIGEST
    err = render_error("--set", f"{key}={value}", "--set", f"{other}={valid}")
    assert f"{key} must be sha256: followed by 64 lowercase hex characters" in err, err


# -- the policy ----------------------------------------------------------

@requires_helm
def test_the_policy_arrives_as_a_file_not_through_the_inline_decode(docs):
    """Kubernetes has a ConfigMap, so the entrypoint's decode branch is unused.

    That branch is where a deploy-breaking default lived; not entering it is
    one fewer thing to be wrong here.
    """
    for name, spec in pod_specs(docs).items():
        env = env_of(spec)
        assert "FORGD_POLICY_INLINE_GZ" not in env, name
        assert "FORGD_POLICY_INLINE" not in env, name
        assert env["FORGD_VERDICT_POLICY"]["value"] == "/etc/forgd/policy.yaml", name


@requires_helm
def test_every_role_mounts_the_same_policy_object(docs):
    """The live path and the collector must not run different rules."""
    names = set()
    for spec in pod_specs(docs).values():
        vol = next(v for v in spec["volumes"] if v["name"] == "policy")
        names.add(vol["configMap"]["name"])
    assert len(names) == 1, names
    assert names.pop() in by_kind(docs, "ConfigMap")


@requires_helm
def test_a_missing_policy_is_refused():
    err = render_error(policy="")
    assert "policy.inline" in err


@requires_helm
def test_the_rendered_policy_is_the_repository_policy(docs):
    cm = next(iter(by_kind(docs, "ConfigMap").values()))
    rendered = yaml.safe_load(cm["data"]["policy.yaml"])
    on_disk = yaml.safe_load((REPO / "policy.yaml").read_text())
    assert rendered == on_disk


@requires_helm
def test_a_policy_change_rolls_the_pods(docs):
    """Otherwise an edited policy is a config nobody picked up."""
    other = render(policy="mode: enforce\ndashboard:\n  auth:\n    mode: trusted_header\n")
    def sums(ds):
        return {
            d["metadata"]["name"]: (
                d["spec"]["template"] if d["kind"] == "Deployment"
                else d["spec"]["jobTemplate"]["spec"]["template"]
            )["metadata"]["annotations"]["checksum/policy"]
            for d in ds if d.get("kind") in ("Deployment", "CronJob")
        }
    a, b = sums(docs), sums(other)
    assert set(a) == set(b)
    assert all(a[k] != b[k] for k in a), "the checksum did not move with the policy"


# -- container hardening -------------------------------------------------

@requires_helm
def test_every_container_runs_unprivileged_as_the_image_user(docs):
    for name, spec in pod_specs(docs).items():
        assert spec["securityContext"]["runAsNonRoot"] is True, name
        # 10001 is the uid the Dockerfile creates; a mismatch means the
        # image's own directories are unwritable.
        assert spec["securityContext"]["runAsUser"] == 10001, name
        sc = spec["containers"][0]["securityContext"]
        assert sc["readOnlyRootFilesystem"] is True, name
        assert sc["allowPrivilegeEscalation"] is False, name
        assert sc["capabilities"]["drop"] == ["ALL"], name


@requires_helm
def test_a_read_only_root_still_has_the_paths_the_entrypoint_writes(docs):
    """gitleaksd's socket lives in /run/forgd; without it the app exits at start."""
    for name, spec in pod_specs(docs).items():
        mounts = {m["mountPath"] for m in spec["containers"][0]["volumeMounts"]}
        assert "/run/forgd" in mounts, name
        assert "/tmp" in mounts, name


@requires_helm
def test_the_roles_that_scan_on_a_waited_on_path_run_gitleaksd(docs):
    """477 ms of regex compile per exec against a 5,000 ms verdict timeout."""
    specs = pod_specs(docs)
    for role in ("verdict", "collector"):
        assert env_of(specs[role])["FORGD_GITLEAKS_SOCKET"]["value"] == "/run/forgd/gitleaksd.sock"
    # The intake renders only with its own values; asserted separately.
    # The dashboard scans nothing.
    assert "FORGD_GITLEAKS_SOCKET" not in env_of(specs["dashboard"])


@requires_helm
def test_every_role_given_the_socket_is_told_to_use_it(docs):
    """The socket alone does nothing.

    `daemon` is a policy field, set per profile, and it is what stops
    GitleaksDetector shelling out. The chart handed the collector the
    socket while only the `server` profile named it, so the collector
    started a daemon it never spoke to and paid the CLI's per-exec
    compile on every batch -- with an exporter waiting.
    """
    from forgd_verdict.policy import load_policy

    # The profile each role builds its detectors from. Asserted against
    # the shipped policy, which is what a deployment mounts.
    profiles = {"verdict": "server", "collector": "otel", "intake": "hook"}
    policy = load_policy(str(REPO / "policy.yaml"))

    specs = dict(pod_specs(docs))
    specs.update(pod_specs(render(*INTAKE)))
    for role, profile in profiles.items():
        assert "FORGD_GITLEAKS_SOCKET" in env_of(specs[role]), role
        section = (policy.raw.get(profile) or {}).get("detectors") or {}
        daemon = (section.get("gitleaks") or {}).get("daemon")
        assert daemon, (
            f"{role} is given the socket but the {profile!r} profile does "
            "not set detectors.gitleaks.daemon, so it will exec the CLI"
        )


@requires_helm
def test_the_collector_runs_the_base_image_unless_asked(docs):
    """The ingest image carries Presidio for sink redaction. It is
    opt-in: about a gigabyte of memory a deployment without a PII-redacting
    sink gains nothing from."""
    base = pod_specs(docs)["collector"]["containers"][0]["image"]
    assert not base.endswith("-ingest"), base
    on = pod_specs(render("--set", "collector.useIngestImage=true"))
    image = on["collector"]["containers"][0]["image"]
    assert image == on["ingest"]["containers"][0]["image"], image


@requires_helm
@pytest.mark.parametrize("role", ["verdict", "collector", "intake"])
def test_liveness_is_livez_and_readiness_stays_on_healthz(role):
    """/livez fails when the role's gitleaksd stops answering, so a restart
    brings the daemon back. /healthz stays 200 while the app is up; on it,
    a dead daemon would take the only verdict pod out of rotation."""
    c = pod_specs(render(*INTAKE))[role]["containers"][0]
    live = c["livenessProbe"]
    assert live["httpGet"] == {"path": "/livez", "port": "http"}
    # About a minute of consecutive failure: the probe shares the verdict
    # path's event loop, and a restart under load is an outage.
    assert (live["timeoutSeconds"], live["periodSeconds"], live["failureThreshold"]) \
        == (5, 10, 6)
    assert c["readinessProbe"]["httpGet"]["path"] == "/healthz"
    assert c["startupProbe"]["httpGet"]["path"] == "/healthz"


@requires_helm
def test_the_verdict_roll_never_goes_to_zero_available(docs):
    """A dropped frame mid-roll is a webhook failure, not a slow allow."""
    deploys = by_kind(docs, "Deployment")
    verdict = next(v for k, v in deploys.items() if k.endswith("-verdict"))
    ru = verdict["spec"]["strategy"]["rollingUpdate"]
    assert ru["maxUnavailable"] == 0
    assert ru["maxSurge"] == 1


# -- per-process state ---------------------------------------------------

@requires_helm
def test_the_single_replica_roles_default_to_one(docs):
    deploys = by_kind(docs, "Deployment")
    for suffix in ("-verdict", "-collector"):
        d = next(v for k, v in deploys.items() if k.endswith(suffix))
        assert d["spec"]["replicas"] == 1, suffix


@requires_helm
@pytest.mark.parametrize("role", ["verdict", "collector"])
def test_scaling_out_per_process_state_is_refused_until_acknowledged(role):
    """The session cache, the webhook-id dedupe store and the sink queue are
    all per-process. A second replica does not fail; it makes the latency
    numbers meaningless and breaks backpressure, quietly."""
    err = render_error("--set", f"{role}.replicas=2")
    assert "per-process" in err
    # And it is overridable, because the refusal is about knowing, not about
    # forbidding.
    docs = render("--set", f"{role}.replicas=2",
                  "--set", f"{role}.sharedStateAcknowledged=true")
    d = next(v for k, v in by_kind(docs, "Deployment").items() if k.endswith(f"-{role}"))
    assert d["spec"]["replicas"] == 2


@requires_helm
def test_no_pod_disruption_budget(docs):
    """Every role runs one replica by design: minAvailable 1 blocks drains
    forever and 0 does nothing. Drains are what observe mode is for."""
    assert not by_kind(docs, "PodDisruptionBudget")


# -- secrets -------------------------------------------------------------

@requires_helm
def test_no_secret_is_passed_as_a_literal_env_value(docs):
    """A literal is visible in `kubectl get deploy -o yaml` to anyone with read."""
    secretish = ("SECRET", "TOKEN", "KEY", "SALT")
    for name, spec in pod_specs(docs).items():
        for var, e in env_of(spec).items():
            if var in ("AZURE_CLIENT_ID",) or var.startswith("FORGD_ORG_ID_"):
                continue  # identifiers, not credentials
            if any(w in var for w in secretish):
                assert "valueFrom" in e, f"{name}/{var} is a literal"


@requires_helm
def test_an_external_secret_replaces_the_chart_managed_one(docs):
    """A real deployment points at external-secrets; the chart's own Secret
    lands in the release and `helm get values` shows it."""
    other = render("--set", "secrets.existingSecret=forgd-from-vault")
    assert not by_kind(other, "Secret")
    for name, spec in pod_specs(other).items():
        for e in env_of(spec).values():
            ref = e.get("valueFrom", {}).get("secretKeyRef")
            if ref:
                assert ref["name"] == "forgd-from-vault", name


@requires_helm
def test_the_otel_token_is_per_org(docs):
    """A leaked token attributes records to the org it was issued for and no other."""
    spec = pod_specs(docs)["collector"]
    env = env_of(spec)
    assert env["FORGD_OTEL_TOKEN_PRIMARY"]["valueFrom"]["secretKeyRef"]["key"] == "otel-token-primary"


@requires_helm
def test_org_ids_reach_every_role(docs):
    for name, spec in pod_specs(docs).items():
        env = env_of(spec)
        assert env["FORGD_ORG_ID_PRIMARY"]["value"] == "00000000-0000-0000-0000-000000000000", name


# -- the chart itself ----------------------------------------------------

def test_the_chart_app_version_matches_the_package():
    """A chart shipping an appVersion the repository never built is a
    deployment nobody can reproduce."""
    chart = yaml.safe_load((CHART / "Chart.yaml").read_text())
    import forgd_verdict
    assert chart["appVersion"] == forgd_verdict.__version__


def test_the_chart_carries_no_policy_of_its_own():
    """One policy.yaml in the repository. A copy here would be free to drift
    from the one the Container Apps module reads, and the drift would show up
    as two deployments disagreeing about a threshold with nothing saying why."""
    assert not (CHART / "policy.yaml").exists()


def test_no_organization_uuid_is_committed_under_deploy_helm():
    """Org UUIDs are sensitive; see CLAUDE.md.

    Scans the whole deploy/helm tree, not just the chart directory -- the
    README sits beside it and is exactly where a worked example would paste
    a real one. Case-insensitive, because a UUID copied from the portal is
    not always lowercase.
    """

    uuid = re.compile(
        r"\b[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\b",
        re.IGNORECASE,
    )
    root = CHART.parent
    assert (root / "README.md").exists(), "expected deploy/helm/README.md in scope"
    for f in root.rglob("*"):
        if not f.is_file():
            continue
        for m in uuid.findall(f.read_text()):
            assert set(m.lower()) <= set("0-"), f"{f}: {m}"


# -- the org id beside the token -----------------------------------------

@requires_helm
def test_an_otel_token_without_an_org_id_is_refused():
    """The collector would accept a batch from any organization.

    policy.yaml pairs each token with `otel.orgs[].id`, and the payload's
    `organization.id` is cross-checked against it. The check reads
    `if claimed and org["id"] and claimed != org["id"]` -- otel/app.py:217 --
    so an empty id cannot make it fire. Nothing reports the result: the
    records store successfully, attributed to the wrong org.
    """
    err = render_error("--set", "secrets.otelTokens.other=tok")
    assert "ANY organization" in err, err


@requires_helm
def test_an_empty_org_id_beside_a_token_is_refused():
    """Present-but-empty is the same failure as absent, and easier to do."""
    err = render_error("--set", "orgIds.primary=", "--set", "secrets.otelTokens.primary=tok")
    assert "cross-check" in err, err


@requires_helm
def test_an_org_with_no_otel_token_fails_closed():
    """Legitimate, and it must not become an open door.

    An org served only by the Compliance API or the inference hook has no
    OTel token. The variable is still generated -- names come from orgIds so
    that an existingSecret deployment needs no token values in values.yaml
    -- but the secret key is optional, so it resolves to nothing.

    That is safe only because _token_map SKIPS an org whose token is empty
    ("an org with no real token is simply not configured"), rather than
    registering it with an empty bearer. If that ever changed, this org
    would accept unauthenticated exports.
    """
    docs = render("--set", "orgIds.solo=00000000-0000-0000-0000-000000000009")
    env = env_of(pod_specs(docs)["collector"])
    assert env["FORGD_ORG_ID_SOLO"]["value"].endswith("0009")
    ref = env["FORGD_OTEL_TOKEN_SOLO"]["valueFrom"]["secretKeyRef"]
    assert ref["optional"] is True
    assert ref["key"] == "otel-token-solo"
    # The chart-managed secret carries no key for it.
    secret = next(iter(by_kind(docs, "Secret").values()))
    assert "otel-token-solo" not in secret["stringData"]

    # And the app drops such an org rather than configuring it with an
    # empty token -- the property the above depends on.
    src = (REPO / "src" / "forgd_verdict" / "otel" / "app.py").read_text()
    assert "if not token:\n            continue" in src


@requires_helm
def test_a_token_matches_its_org_case_insensitively():
    """orgIds.Primary and otelTokens.primary both become _PRIMARY, so the guard must
    compare the same way the env var names are built -- otherwise it refuses
    a correct configuration."""
    docs = render(
        "--set", "orgIds.Primary=00000000-0000-0000-0000-000000000003",
        "--set", "secrets.otelTokens.primary=tok",
    )
    env = env_of(pod_specs(docs)["collector"])
    assert "FORGD_ORG_ID_PRIMARY" in env
    assert "FORGD_OTEL_TOKEN_PRIMARY" in env


# -- rotating the signing secret -----------------------------------------

@requires_helm
def test_the_previous_webhook_secret_is_optional(docs):
    """Absent outside a rotation; a required key would stop the pod starting."""
    env = env_of(pod_specs(docs)["verdict"])
    ref = env["WEBHOOK_SECRET_PREVIOUS"]["valueFrom"]["secretKeyRef"]
    assert ref["optional"] is True
    assert ref["key"] == "webhook-secret-previous"
    # Not in the chart-managed secret unless asked for.
    secret = next(iter(by_kind(docs, "Secret").values()))
    assert "webhook-secret-previous" not in secret["stringData"]


@requires_helm
def test_a_rotation_can_carry_both_secrets():
    """policy.yaml accepts both, so a rotation has no window in which a
    frame signed with the outgoing secret is rejected -- and a rejected
    frame is a webhook failure, not a deny."""
    docs = render("--set", "secrets.webhookSecretPrevious=whsec_OLD")
    secret = next(iter(by_kind(docs, "Secret").values()))
    assert secret["stringData"]["webhook-secret-previous"] == "whsec_OLD"
    assert secret["stringData"]["webhook-secret"] != "whsec_OLD"


# -- nothing the chart sets is dead --------------------------------------

@requires_helm
def test_every_environment_variable_the_chart_sets_is_consumed(docs):
    """An env var nothing reads is a setting that looks configured.

    Several are consumed through policy.yaml's `$VAR` substitution rather
    than by name in code -- WEBHOOK_SECRET, FORGD_METRICS_TOKEN, and the
    per-org FORGD_ORG_ID_* / FORGD_OTEL_TOKEN_* -- so both places count.
    """
    names = {n for spec in pod_specs(docs).values() for n in env_of(spec)}
    haystack = (REPO / "policy.yaml").read_text()
    for path in (REPO / "src").rglob("*.py"):
        haystack += path.read_text()
    haystack += (REPO / "deploy" / "entrypoint.sh").read_text()

    unread = sorted(n for n in names if n not in haystack)
    assert not unread, f"nothing reads {unread}"


# -- the dashboard auth mode that does not port --------------------------

@requires_helm
def test_the_shipped_policy_is_refused_without_an_explicit_assertion():
    """The repository's own policy.yaml is the dangerous input here.

    It sets dashboard.auth.mode: trusted_header with
    header: x-ms-client-principal-name. That authenticates nothing unless
    the proxy in front strips inbound copies of that header. Container Apps
    EasyAuth strips it, which is why it is the default and why it is safe
    there. oauth2-proxy has no reason to strip an Azure-named header and
    does not -- so the same policy on Kubernetes lets a caller set the
    header and be whoever it claims, while signing in through the proxy
    also still works, so nothing looks wrong.

    A fork inherits our default. CLAUDE.md: a default that is only safe
    because we know about it is a bug.
    """
    out = subprocess.run(
        [helm, "template", "rel", str(CHART), *base_without("trustedHeaderStrippedBy")],
        capture_output=True, text=True, timeout=120,
    )
    assert out.returncode != 0, "the shipped policy rendered without the assertion"
    # Refused by the guard, not by a malformed command line.
    assert "has no value" not in out.stderr, out.stderr
    # The policy supplies the header as a $VAR now, so the message must
    # resolve it rather than quoting the placeholder -- naming
    # "$FORGD_DASHBOARD_HEADER" would tell an operator nothing about what a
    # caller would have to forge.
    assert "x-ms-client-principal-name" in out.stderr, out.stderr
    assert "$FORGD_DASHBOARD_HEADER" not in out.stderr, out.stderr
    assert "strips" in out.stderr


@requires_helm
def test_naming_the_proxy_that_strips_the_header_is_accepted(docs):
    """The guard records a claim rather than forbidding the mode.

    Someone running a proxy they have actually checked should not have to
    edit the chart.
    """
    assert pod_specs(docs)["dashboard"]  # rendered at all

    # It DOES reach the dashboard pod. The app enforces the trusted_header
    # guard itself, so every deployment path checks it, and the app can only
    # check an attestation it can see.
    dash_env = env_of(pod_specs(docs)["dashboard"])
    assert "FORGD_DASHBOARD_STRIPPED_BY" in dash_env

    # The dashboard only. No other role reads it.
    for role, spec in pod_specs(docs).items():
        if role == "dashboard":
            continue
        assert "FORGD_DASHBOARD_STRIPPED_BY" not in env_of(spec), role


@requires_helm
def test_a_policy_that_verifies_tokens_needs_no_assertion():
    """oidc_jwt verifies a signature against the issuer's JWKS, so it trusts
    an assertion rather than a network position. That is the mode that
    ports, and the chart asks nothing extra of it."""
    policy = (
        "mode: observe\n"
        "dashboard:\n"
        "  auth:\n"
        "    mode: oidc_jwt\n"
        "    jwks_url: https://issuer/keys\n"
        "    issuer: https://issuer/\n"
        "    audience: an-app-id\n"
    )
    with tempfile.NamedTemporaryFile("w", suffix=".yaml", delete=False) as f:
        f.write(policy)
        path = f.name
    out = subprocess.run(
        [
            helm, "template", "rel", str(CHART),
            *base_without("trustedHeaderStrippedBy", "policy.inline"),
            "--set-file", f"policy.inline={path}",
        ],
        capture_output=True, text=True, timeout=120,
    )
    assert out.returncode == 0, out.stderr


# -- against the Container Apps module -----------------------------------

ACA = REPO / "deploy" / "terraform" / "modules" / "app-aca" / "main.tf"

# Divergences that are meant. Anything else is an env var added to one
# deployment and forgotten on the other -- which does not fail either one,
# it just makes them behave differently for a reason nobody wrote down.
INTENDED_DIVERGENCE = {
    # Kubernetes supplies the policy as a mounted ConfigMap, so the
    # entrypoint's inline-decode branch is never entered. That branch is
    # where a deploy-breaking default lived.
    "FORGD_POLICY_INLINE_GZ": "aca-only: the chart mounts a ConfigMap instead",
    "FORGD_VERDICT_POLICY": "chart-only: the path of that mounted file",
    # Container Apps sets the listen port through its ingress block; the
    # chart sets containerPort and has to tell the app to match.
    "PORT": "chart-only: the entrypoint reads it, ACA relies on the default",
}


CONNECTOR_ALL = (
    "--set", "connector.enabled=true",
    "--set", "connector.auth.issuer=https://login.example.com/t/v2.0",
    "--set", "connector.auth.jwksUrl=https://login.example.com/t/keys",
    "--set", "connector.auth.audience={api-client-id}",
    "--set", "connector.auth.groupsClaim=roles",
    "--set", "connector.auth.issuers[0].issuer=https://login.example.com/t/v2.0",
    "--set", "connector.auth.issuers[0].jwksUrl=https://login.example.com/t/keys",
    "--set", "connector.auth.issuers[0].audience={api-client-id}",
    "--set", "connector.scopes={findings.read}",
    "--set", "connector.requiredScope=findings.read",
    "--set", "connector.allowedOrigins={https://claude.ai}",
)

DASHBOARD_OIDC = (
    "--set", "dashboard.auth.mode=oidc_jwt",
    "--set", "dashboard.auth.jwksUrl=https://login.example.com/t/discovery/v2.0/keys",
    "--set", "dashboard.auth.issuer=https://login.example.com/t/v2.0",
    "--set", "dashboard.auth.audience=dashboard-client-id",
)
ADMINS_ON = (
    "--set", "dashboard.admins.enabled=true",
    "--set", "serviceAccounts.control.clientId=33333333-3333-3333-3333-333333333333",
    "--set", "secrets.dashboardFormKey=a-form-key",
    "--set", "dashboard.admins.writerIdentities={00000000-0000-0000-0000-00000000000a}",
    "--set", "dashboard.admins.storageAccountId=/subscriptions/00000000-0000-0000-0000-000000000000/resourceGroups/rg/providers/Microsoft.Storage/storageAccounts/acct",
    "--set", "dashboard.admins.signingKey.secretName=forgd-overrides-signing",
    "--set", f"dashboard.admins.verifyKeys={{{overrides_verify_key()}}}",
)


def aca_env() -> dict[str, set[str]]:
    """Env var names per role in the Container Apps module."""

    text = ACA.read_text()
    base = set(re.findall(r"^\s{4}(FORGD_[A-Z_]+|AZURE_CLIENT_ID)\s*=", text, re.M))
    # The per-org variables are built by a `for` expression over var.org_ids
    # and merged into base_env, so they never appear as a literal env name.
    # Missing them made every role look divergent on the family.
    if 'FORGD_ORG_ID_${upper(replace(name, "-", "_"))}' in text:
        base.add("FORGD_ORG_ID_*")
    out = {}
    for m in re.finditer(
        r'resource "azurerm_container_app(?:_job)?" "(\w+)" \{(.*?)\n\}\n', text, re.S
    ):
        role, body = m.group(1), m.group(2)
        names = set(re.findall(r'env \{\s*\n\s*name\s*=\s*"([A-Z_]+)"', body))
        names |= set(re.findall(r'name\s*=\s*"([A-Z_]+)"\s*\n\s*secret_name', body))
        # A dynamic env block sets its name in `content`.
        names |= set(re.findall(r'content \{\s*\n\s*name\s*=\s*"([A-Z_]+)"', body))
        # The collector's per-org tokens are a dynamic block over otel_tokens,
        # and the intake's per-client ones one over intake_tokens.
        if '"FORGD_OTEL_TOKEN_${' in body:
            names.add("FORGD_OTEL_TOKEN_*")
        if '"FORGD_INTAKE_TOKEN_${' in body:
            names.add("FORGD_INTAKE_TOKEN_*")
        out[role] = names | base
    return out


@requires_helm
def test_the_two_deployments_set_the_same_environment_per_role(docs):
    """One image, two wrappers, and they must configure it the same way.

    An env var added to the Container Apps module and not here does not fail
    either deployment. It makes them behave differently -- a detector
    threshold, a token, an org id present in one and absent in the other --
    and the divergence surfaces as findings that disagree rather than as an
    error.
    """
    aca = aca_env()
    assert set(aca) == {"verdict", "collector", "dashboard", "ingest", "connector", "intake"}, sorted(aca)
    chart = {name: set(env_of(spec)) for name, spec in pod_specs(docs).items()}
    # Every connector setting, so each optional variable is rendered.
    connector = pod_specs(render(*CONNECTOR_ALL))["connector"]
    chart["connector"] = set(env_of(connector))
    # And the names dashboard admins add to each role, over the same render
    # without them.
    # The intake renders only when enabled; with the fleet token and a
    # client, so each of its token variables is rendered.
    intake = (*INTAKE, "--set", "intake.fleet.enabled=true", "--set", "secrets.intakeFleetToken=" + "f" * 32,
              "--set", "secrets.intakeFleetTokenPrevious=" + "p" * 32)
    chart["intake"] = set(env_of(pod_specs(render(*intake))["intake"]))
    without = pod_specs(render(*CONNECTOR_ALL, *DASHBOARD_OIDC, *intake))
    admins = pod_specs(render(*CONNECTOR_ALL, *DASHBOARD_OIDC, *ADMINS_ON, *intake))
    for role in chart:
        chart[role] |= set(env_of(admins[role])) - set(env_of(without[role]))

    def family(names: set[str]) -> set[str]:
        # Per-org variables are generated from a map on both sides, so
        # compare the family rather than the instances.
        out = set()
        for n in names:
            if n.startswith("FORGD_ORG_ID_"):
                out.add("FORGD_ORG_ID_*")
            elif n.startswith("FORGD_OTEL_TOKEN_"):
                out.add("FORGD_OTEL_TOKEN_*")
            elif n.startswith("FORGD_INTAKE_TOKEN_"):
                out.add("FORGD_INTAKE_TOKEN_*")
            else:
                out.add(n)
        return out

    unexplained = {}
    for role in aca:
        diff = family(aca[role]) ^ family(chart[role])
        gap = sorted(d for d in diff if d not in INTENDED_DIVERGENCE)
        if gap:
            unexplained[role] = gap
    assert not unexplained, (
        f"{unexplained} differ between app-aca and the chart with no entry in "
        "INTENDED_DIVERGENCE; add one saying why, or set it in both"
    )


def test_every_intended_divergence_is_still_a_divergence():
    """An allowlist that has stopped applying hides the next real one.

    If a name here is now set the same way on both sides, the entry should
    go -- otherwise it silently excuses a future mismatch on that name.
    """

    aca_text = ACA.read_text()
    # *.tpl too: commonEnv lives in _helpers.tpl, so a yaml-only glob
    # reported chart-only names as absent from both sides.
    chart_text = "".join(
        f.read_text()
        for f in (CHART / "templates").iterdir()
        if f.suffix in (".yaml", ".tpl")
    )
    for name, why in INTENDED_DIVERGENCE.items():
        in_aca = bool(re.search(rf'"{name}"', aca_text))
        in_chart = name in chart_text
        assert in_aca != in_chart, (
            f"{name} is now {'in both' if in_aca else 'in neither'} "
            f"({why}); drop it from INTENDED_DIVERGENCE"
        )

# -- the contract with Terraform -----------------------------------------
#
# The federated subject is `system:serviceaccount:<namespace>:<name>`, and
# Entra matches it exactly. A name the chart renders that the Terraform
# stack did not federate produces pods that authenticate as NOTHING, and the
# only place that says so is the pod's own log: the dashboard renders empty,
# and the collector accepts exports and then fails to store them. Neither
# looks like an auth failure from outside.
#
# So the two sides are asserted against each other rather than kept in step
# by hand.

AKS_LAB = REPO / "deploy" / "terraform" / "examples" / "aks"


def terraform_local(name: str) -> str:
    src = (AKS_LAB / "main.tf").read_text()
    m = re.search(rf'^\s*{name}\s*=\s*"([^"]+)"', src, re.MULTILINE)
    assert m, f"examples/aks/main.tf no longer defines a local named {name!r}"
    return m.group(1)


def terraform_default(name: str) -> str:
    src = (AKS_LAB / "variables.tf").read_text()
    m = re.search(
        rf'variable\s+"{name}"\s*\{{(.*?)\n\}}', src, re.DOTALL
    )
    assert m, f"examples/aks/variables.tf has no variable {name!r}"
    d = re.search(r'default\s*=\s*"([^"]+)"', m.group(1))
    assert d, f"variable {name!r} has no string default"
    return d.group(1)


@requires_helm
def test_the_chart_honours_the_service_account_names_it_is_given():
    """Narrow, and deliberately so: it proves the override reaches the pods.

    It cannot prove the two sides agree -- it takes the names FROM Terraform
    -- which is what the next test is for.
    """
    writer = terraform_local("writer_service_account")
    reader = terraform_local("reader_service_account")
    docs = render(
        "--set", f"serviceAccounts.writer.name={writer}",
        "--set", f"serviceAccounts.reader.name={reader}",
    )
    rendered = set(by_kind(docs, "ServiceAccount"))
    assert rendered == {writer, reader}, rendered

    # And every pod actually uses one of them -- a service account that is
    # federated and unused federates nothing.
    used = {s["serviceAccountName"] for s in pod_specs(docs).values()}
    assert used == {writer, reader}, used


def test_the_install_command_passes_the_names_it_federated():
    """The gap the test above cannot see.

    The chart's DEFAULT names are derived from the release name, so they do
    not match the federated subject. An install command that omits these two
    flags produces pods authenticating as nothing, and the stack that
    printed the command is the one that chose the subject.
    """
    src = (AKS_LAB / "outputs.tf").read_text()
    for role in ("writer", "reader"):
        flag = f"--set serviceAccounts.{role}.name=${{local.{role}_service_account}}"
        assert flag in src, f"the helm command does not pin the {role} service account name"
        # And the client id, or ManagedIdentityCredential picks whichever
        # identity the node offers.
        assert f"--set serviceAccounts.{role}.clientId=" in src, role


@requires_helm
def test_the_chart_default_names_would_not_satisfy_the_federation():
    """Why the flags above are mandatory rather than belt-and-braces.

    If the chart's defaults happened to match, the previous test would be
    guarding nothing and could be deleted without consequence. They do not.
    """
    default_names = set(by_kind(render(), "ServiceAccount"))
    federated = {
        terraform_local("writer_service_account"),
        terraform_local("reader_service_account"),
    }
    assert default_names.isdisjoint(federated), (
        "the chart's default service account names now match the federated "
        "subjects; either drop the --set flags deliberately or keep them, "
        "but do not leave this passing by coincidence"
    )


def test_the_two_federated_subjects_are_different():
    """One subject for both would federate the dashboard to the writer."""
    assert terraform_local("writer_service_account") != terraform_local(
        "reader_service_account"
    )


def test_the_aks_module_federates_the_reader_to_the_reader_identity():
    """Both credentials pointing at one identity would undo the read-only
    split without changing anything in the chart."""
    src = (REPO / "deploy" / "terraform" / "modules" / "cluster-aks" / "main.tf").read_text()
    creds = dict(
        re.findall(
            r'resource "azurerm_federated_identity_credential" "(\w+)" \{(.*?)\n\}',
            src,
            re.DOTALL,
        )
    )
    assert set(creds) == {"writer", "reader", "connector", "control"}, set(creds)
    assert "var.writer_identity_id" in creds["writer"]
    assert "var.reader_identity_id" in creds["reader"]
    assert "var.writer_identity_id" not in creds["reader"]
    assert "var.reader_identity_id" in creds["connector"]
    assert "var.writer_identity_id" not in creds["connector"]
    # The control identity's credential names the control identity; the
    # others appear only in the precondition that refuses them.
    assert "parent_id           = var.control_identity_id" in creds["control"]
    assert "var.control_identity_id" not in creds["reader"] + creds["connector"] + creds["writer"]


def test_no_two_root_stacks_share_a_store_or_an_identity():
    """Separate state is only separate if the resources are too.

    Written as the general property: whatever root stacks exist under
    deploy/terraform/examples, none may name the same storage account
    variable or the same managed identity. Two states in charge of one
    resource means each plan wants to take it back from the other, and a
    destroy in one reaches the other's findings.

    Trivially true while one stack remains, and still the right assertion
    the moment a second appears. It fails when it finds no stack, so a
    root that moves cannot leave it checking nothing.
    """
    import re as _re

    accounts: dict[str, set[str]] = {}
    identities: dict[str, set[str]] = {}
    roots = REPO / "deploy" / "terraform" / "examples"
    for root in sorted(d for d in roots.iterdir() if (d / "main.tf").is_file()):
        src = "".join(f.read_text() for f in root.glob("*.tf"))
        accounts[root.name] = set(_re.findall(r'storage_account_name\s*=\s*(\S+)', src))
        identities[root.name] = set(_re.findall(r'identity_name\s*=\s*"([^"]+)"', src))

    stacks = sorted(accounts)
    assert stacks, f"no root stack under {roots}"
    assert all(identities[s] for s in stacks), identities
    for i, a in enumerate(stacks):
        for b in stacks[i + 1:]:
            assert identities[a].isdisjoint(identities[b]), (
                a, b, identities[a] & identities[b]
            )


# -- values whose absence is silent rather than loud ---------------------

@requires_helm
def test_a_missing_store_is_refused():
    """Refused at render time rather than at pod start.

    _apply_env_overrides skips an empty string (policy.py), so an empty
    value leaves policy.yaml's `store: $FORGD_VERDICT_STORE` unresolved.
    open_store refuses that, so every role would crash-loop -- caught
    here instead, where the message can say which value to set. The
    Terraform path has always required it: app-aca declares store_url
    with no default.
    """
    err = render_error_without("store.url")
    assert "store.url is required" in err, err
    assert "refuses to start" in err, err


@requires_helm
def test_a_missing_image_repository_is_refused():
    """Empty renders `image: :<tag>`.

    helm lint and kubectl --dry-run=client both accept that; the kubelet
    rejects it with InvalidImageName, so the first sign is a pod that never
    starts.
    """
    err = render_error_without("image.repository")
    assert "InvalidImageName" in err, err


def test_the_values_comments_name_no_release_version():
    values = (CHART / "values.yaml").read_text(encoding="utf-8")
    assert "`image: :<version>`" in values
    assert not re.search(r"image: :\d", values)


# -- TLS -----------------------------------------------------------------

@requires_helm
def test_one_certificate_per_hostname(docs):
    """cert-manager wants a unique tls.secretName per Ingress.

    Three objects sharing a hostname once named one secret between them,
    which is three Certificates racing for the same secret. TLS is per
    server rather than per location, so exactly one object declares it.
    """
    ingresses = by_kind(docs, "Ingress")
    with_tls = {k: v for k, v in ingresses.items() if v["spec"].get("tls")}
    assert len(with_tls) == 1, sorted(with_tls)
    public = next(iter(with_tls))
    assert public.endswith("-public")

    issuers = [
        k for k, v in ingresses.items()
        if "cert-manager.io/cluster-issuer" in (v["metadata"].get("annotations") or {})
    ]
    assert issuers == [public], issuers


@requires_helm
def test_a_dashboard_on_its_own_host_gets_its_own_certificate():
    """A different hostname is a different server, so it needs its own."""
    docs = render("--set", "ingress.dashboard.host=dash.example.test")
    ingresses = by_kind(docs, "Ingress")
    with_tls = {k: v["spec"]["tls"][0]["secretName"]
                for k, v in ingresses.items() if v["spec"].get("tls")}
    assert len(with_tls) == 2, with_tls
    assert len(set(with_tls.values())) == 2, with_tls


@requires_helm
def test_tls_without_an_issuer_or_a_secret_is_refused():
    """Otherwise nginx serves its own self-signed certificate.

    On the dashboard that is a browser warning someone clicks through. On
    the collector it is a TLS verification failure inside Anthropic's
    exporter, which it reports as a delivery failure rather than as a
    certificate problem.
    """
    err = render_error_without("ingress.tls.clusterIssuer")
    assert "self-signed" in err, err


@requires_helm
def test_an_existing_certificate_needs_no_issuer():
    """cert-manager is not a requirement, only a way of getting one."""
    docs = render(
        *base_without("ingress.tls.clusterIssuer"),
        "--set", "ingress.tls.secretName=brought-my-own",
    )
    public = next(v for k, v in by_kind(docs, "Ingress").items() if k.endswith("-public"))
    assert public["spec"]["tls"][0]["secretName"] == "brought-my-own"


# -- the cluster-wide switches the object split cannot reach -------------

@requires_helm
def test_modsecurity_is_opted_out_on_the_paths_anthropic_uses(docs):
    """A cluster running the OWASP core rule set inspects request bodies.

    The bodies here are prompt text and telemetry, which is exactly what
    that rule set is built to find suspicious -- and the frames most likely
    to trip it are the ones carrying content worth scanning. A 403 is a
    webhook failure, not a deny.
    """
    ingresses = by_kind(docs, "Ingress")
    key = "nginx.ingress.kubernetes.io/enable-modsecurity"
    for suffix in ("-public", "-diagnostics"):
        ing = next(v for k, v in ingresses.items() if k.endswith(suffix))
        assert ing["metadata"]["annotations"][key] == "false", suffix


# -- secrets kept out of the release -------------------------------------

@requires_helm
def test_an_external_secret_needs_no_token_values_in_the_release():
    """The variable names come from orgIds, not from secrets.otelTokens.

    Generating them from the token map meant a deployment using
    existingSecret still had to list token-shaped values in values.yaml just
    to get the names -- putting the secrets back into the release that
    existingSecret was chosen to keep them out of.
    """
    docs = render(
        "--set", "secrets.existingSecret=from-vault",
        "--set", "orgIds.extra=00000000-0000-0000-0000-000000000007",
    )
    assert not by_kind(docs, "Secret")
    env = env_of(pod_specs(docs)["collector"])
    ref = env["FORGD_OTEL_TOKEN_EXTRA"]["valueFrom"]["secretKeyRef"]
    assert ref == {"name": "from-vault", "key": "otel-token-extra", "optional": True}


# -- several names for one deployment ------------------------------------

EXTRA = "verdict.forgd.example"


@requires_helm
def test_every_public_name_serves_the_same_rules():
    """Adding a name must not create a second, differently-routed surface.

    The cutover case is to stand up on the Azure-issued
    <label>.<region>.cloudapp.azure.com, which needs no domain ownership,
    and add a vanity name later -- rather than re-pointing Anthropic twice.
    A name that served /hook and not /v1, or vice versa, would be a
    half-working endpoint that looks configured.
    """
    docs = render("--set", f"ingress.extraHosts[0]={EXTRA}")
    ingresses = by_kind(docs, "Ingress")
    for suffix in ("-public", "-diagnostics"):
        ing = next(v for k, v in ingresses.items() if k.endswith(suffix))
        by_host = {
            r["host"]: sorted(p["path"] for p in r["http"]["paths"])
            for r in ing["spec"]["rules"]
        }
        assert set(by_host) == {"verdict.example.test", EXTRA}, (suffix, by_host)
        assert len(set(map(tuple, by_host.values()))) == 1, (suffix, by_host)


@requires_helm
def test_the_primary_host_stays_first():
    """NOTES.txt and the deploy gate report rules[0], so adding a name must
    not silently change which one they name."""
    docs = render("--set", f"ingress.extraHosts[0]={EXTRA}")
    public = next(
        v for k, v in by_kind(docs, "Ingress").items() if k.endswith("-public")
    )
    assert public["spec"]["rules"][0]["host"] == "verdict.example.test"


@requires_helm
def test_one_certificate_covers_every_name():
    """Separate tls entries would be separate certificates for one server."""
    docs = render("--set", f"ingress.extraHosts[0]={EXTRA}")
    ingresses = by_kind(docs, "Ingress")
    with_tls = [v for v in ingresses.values() if v["spec"].get("tls")]
    assert len(with_tls) == 1
    tls = with_tls[0]["spec"]["tls"]
    assert len(tls) == 1, tls
    assert sorted(tls[0]["hosts"]) == sorted(["verdict.example.test", EXTRA])


@requires_helm
def test_a_repeated_host_is_refused():
    """Two rules for one server, and a certificate with a duplicate SAN."""
    err = render_error("--set", "ingress.extraHosts[0]=verdict.example.test")
    assert "repeats ingress.host" in err, err


@requires_helm
def test_the_dashboard_host_cannot_also_be_a_public_name():
    """It is either a name of its own or one of the public ones.

    Both would mean the dashboard object and the public object claiming the
    same server for different purposes, and the server-scoped annotation
    guard would then be lifted on a hostname that still carries /hook.
    """
    err = render_error(
        "--set", f"ingress.extraHosts[0]={EXTRA}",
        "--set", f"ingress.dashboard.host={EXTRA}",
    )
    assert "not both" in err, err


@requires_helm
def test_a_dashboard_on_its_own_name_does_not_answer_on_the_public_ones():
    docs = render(
        "--set", f"ingress.extraHosts[0]={EXTRA}",
        "--set", "ingress.dashboard.host=dash.example.test",
    )
    dash = next(
        v for k, v in by_kind(docs, "Ingress").items() if k.endswith("-dashboard")
    )
    assert [r["host"] for r in dash["spec"]["rules"]] == ["dash.example.test"]


# -- the bootstrap between terraform and helm ----------------------------

BOOTSTRAP = REPO / "scripts" / "bootstrap_aks.sh"
CLUSTER_AKS = REPO / "deploy" / "terraform" / "modules" / "cluster-aks"


def test_the_bootstrap_discovers_the_ingress_class_rather_than_guessing():
    """Two copies of a guess agreeing with each other is not a check.

    Asserting that the bootstrap's default and the Terraform output agree
    passes when both say "webapprouting.kubernetes.io", and the real name
    is "webapprouting.kubernetes.azure.com".

    The failure that lets through is the quietest kind. The controller logs
    "Ignoring ingress because of error while validating ingress class" for
    every Ingress -- including cert-manager's own solver -- and serves its
    DEFAULT BACKEND, which answers 200 with an empty body. So /healthz
    returned 200, the deployment looked healthy, and the only symptom was
    the ACME challenge getting a 404 on a path whose Ingress was also being
    ignored.
    """
    script = BOOTSTRAP.read_text()
    assert "kubectl get nginxingresscontroller default" in script
    assert "jsonpath='{.spec.ingressClassName}'" in script
    m = re.search(r'INGRESS_CLASS="\$\{INGRESS_CLASS:-([^}]*)\}"', script)
    assert m, "bootstrap_aks.sh no longer sets INGRESS_CLASS the way this reads it"
    assert m.group(1) == "", (
        f"INGRESS_CLASS defaults to {m.group(1)!r}; it must be discovered, "
        "because a wrong value is served as an empty 200 rather than an error"
    )
    # And it refuses when the class does not exist, rather than proceeding.
    assert "no IngressClass named" in script


def test_the_module_reports_the_add_ons_real_ingress_class():
    """Asserted against the known value, not against another copy of it.

    `kubectl get ingressclass` on an AKS cluster with app routing enabled
    shows webapprouting.kubernetes.azure.com. The .io form does not exist.
    """
    outputs = (CLUSTER_AKS / "outputs.tf").read_text()
    m = re.search(r'value\s*=\s*var\.app_routing_enabled \? "([^"]+)"', outputs)
    assert m, "cluster-aks no longer reports an ingress class the way this reads it"
    assert m.group(1) == "webapprouting.kubernetes.azure.com", m.group(1)


def test_the_bootstrap_pins_cert_manager():
    """An unpinned install is a third party deciding what runs in the
    cluster holding the findings, and cert-manager's CRDs move between
    minors."""

    script = BOOTSTRAP.read_text()
    assert re.search(r'(?m)^PINNED_CERT_MANAGER_VERSION=v[\d.]+$', script), \
        "cert-manager is not pinned in bootstrap_aks.sh"
    assert re.search(r'(?m)^PINNED_CERT_MANAGER_DIGEST=sha256:[0-9a-f]{64}$', script), \
        "cert-manager's chart digest is not pinned in bootstrap_aks.sh"


def test_the_bootstrap_sets_the_dns_label_on_the_controller_not_the_service():
    """The add-on reconciles that Service, so an annotation written straight
    onto it is reverted -- usually after it has appeared to work."""
    script = BOOTSTRAP.read_text()
    assert "kubectl patch nginxingresscontroller" in script
    assert "azure-dns-label-name" in script


# -- a writable working directory ----------------------------------------

@requires_helm
def test_every_role_has_a_writable_working_directory(docs):
    """policy.yaml carries RELATIVE paths, and /app is read-only here.

    `server.csv_path: ./timings.csv` resolves against the image's WORKDIR of
    /app, so the verdict server died on start with

      OSError: [Errno 30] Read-only file system: './timings.csv'

    and crash-looped while the collector came up fine, because only the
    verdict server opens that file. readOnlyRootFilesystem was already
    asserted; nothing checked that what the app writes had anywhere to go.
    """
    docs_wd = None
    for name, spec in pod_specs(docs).items():
        c = spec["containers"][0]
        wd = c.get("workingDir")
        assert wd, f"{name} has no workingDir, so relative paths land in /app"
        mounts = {m["mountPath"] for m in c["volumeMounts"]}
        assert wd in mounts, f"{name}: workingDir {wd} is not mounted"
        docs_wd = wd if docs_wd is None else docs_wd
        assert wd == docs_wd, "roles disagree about the working directory"

    # And the volume behind it is writable rather than a projected config.
    for name, spec in pod_specs(docs).items():
        mount = next(
            m for m in spec["containers"][0]["volumeMounts"]
            if m["mountPath"] == docs_wd
        )
        vol = next(v for v in spec["volumes"] if v["name"] == mount["name"])
        assert "emptyDir" in vol, (name, vol)
        assert not mount.get("readOnly"), name


def test_the_policy_still_uses_relative_paths_for_what_it_writes():
    """The reason the working directory has to be writable.

    If these became absolute the mount would be pointing at the wrong place
    and nothing would say so -- the verdict server would crash-loop again on
    a path nobody had mounted.
    """
    policy = yaml.safe_load((REPO / "policy.yaml").read_text())
    csv_path = policy["server"]["csv_path"]
    assert csv_path.startswith("./"), (
        f"server.csv_path is {csv_path!r}, no longer relative; the chart "
        "mounts a writable working directory on the assumption that it is"
    )


@requires_helm
def test_the_working_directory_is_not_a_path_the_image_owns(docs):
    """Mounting over /app would shadow the installed package, and over
    /run/forgd would put diagnostic output beside the gitleaksd socket."""
    wd = pod_specs(docs)["verdict"]["containers"][0]["workingDir"]
    assert not wd.startswith("/app"), wd
    assert wd != "/run/forgd", wd


# -- what the operator is told to paste ----------------------------------

def test_the_notes_give_a_base_otlp_endpoint_not_signal_paths():
    """An OTLP exporter appends the signal path itself.

    `OTEL_EXPORTER_OTLP_ENDPOINT` is a base URL. The chart's notes
    listed `/v1/logs` and `/v1/traces` as things to configure, which yields
    `/v1/logs/v1/logs` and a 404 that the exporter reports as a DELIVERY
    FAILURE rather than as a bad URL -- so the telemetry silently never
    arrives and the collector's own counters stay at zero, which looks
    exactly like a surface that is not sending.

    The paths are still right for the ingress; they are what the collector
    serves. They are just not what anyone pastes into an admin console.
    """
    notes = (CHART / "templates" / "NOTES.txt").read_text()
    block = notes.split("Configure Anthropic against:")[1].split("Check the roll")[0]

    assert "OTLP endpoint" in block
    lines = [ln for ln in block.splitlines() if "https://" in ln and "{{" in ln]
    otlp = [ln for ln in lines if "OTLP" in ln]
    assert otlp, block
    for ln in otlp:
        assert "/v1/logs" not in ln, ln
        assert "/v1/traces" not in ln, ln
    # The hook keeps its path, because that one IS the full URL.
    assert any("/hook" in ln for ln in lines), block


# -- per-deployment dashboard auth ---------------------------------------

OIDC = [
    "--set", "dashboard.auth.mode=oidc_jwt",
    "--set", "dashboard.auth.jwksUrl=https://idp/keys",
    "--set", "dashboard.auth.issuer=https://idp/",
    "--set", "dashboard.auth.audience=an-app-id",
]


@requires_helm
def test_oidc_mode_needs_no_trusted_header_assertion():
    """The guard is about trusted_header, not about the dashboard.

    oidc_jwt verifies a signature against the issuer's JWKS, so it trusts an
    assertion rather than a network position -- there is no header to strip
    and nothing to promise about a proxy.
    """
    docs = render(*base_without("dashboard.trustedHeaderStrippedBy"), *OIDC)
    env = env_of(pod_specs(docs)["dashboard"])
    assert env["FORGD_DASHBOARD_AUTH_MODE"]["value"] == "oidc_jwt"
    assert env["FORGD_DASHBOARD_JWKS_URL"]["value"] == "https://idp/keys"
    assert env["FORGD_DASHBOARD_AUDIENCE"]["value"] == "an-app-id"


@requires_helm
@pytest.mark.parametrize("missing", ["jwksUrl", "issuer", "audience"])
def test_oidc_mode_without_all_three_values_is_refused(missing):
    """The app refuses at startup, so catching it here turns a crash-looping
    pod into a render error. An unset audience would accept tokens minted
    for a DIFFERENT application."""
    # Drop the flag/value PAIR for `missing` -- dropping the value alone
    # leaves an orphan --set and helm fails with "key has no value", which
    # reads exactly like the refusal this asserts.
    out: list[str] = []
    for flag, value in zip(OIDC[::2], OIDC[1::2], strict=True):
        if not value.startswith(f"dashboard.auth.{missing}="):
            out += [flag, value]
    err = render_error(*base_without("dashboard.trustedHeaderStrippedBy"), *out)
    assert "has no value" not in err, err
    assert f"dashboard.auth.{missing} is empty" in err, err


@requires_helm
def test_the_policys_mode_still_governs_when_the_chart_says_nothing(docs):
    """Default render uses the shipped policy, which is trusted_header --
    and the base values carry the assertion, so it renders."""
    env = env_of(pod_specs(docs)["dashboard"])
    assert "FORGD_DASHBOARD_AUTH_MODE" not in env


def _policy_without_dashboard_auth() -> str:
    policy = yaml.safe_load((REPO / "policy.yaml").read_text())
    del policy["dashboard"]["auth"]
    return yaml.safe_dump(policy)


@requires_helm
@pytest.mark.parametrize("how", ["chart-mode-none", "policy-without-auth"])
def test_an_open_dashboard_is_refused_without_serve_open(how):
    """Mode none makes the dashboard refuse to bind 0.0.0.0 unless the
    entrypoint passes --serve-open, so the pod would restart in a loop."""
    if how == "chart-mode-none":
        err = render_error("--set", "dashboard.auth.mode=none")
    else:
        err = render_error(policy=_policy_without_dashboard_auth())
    assert "has no value" not in err, err
    assert "effective dashboard.auth.mode is none" in err, err
    assert "dashboard.serveOpen: true" in err and "dashboard.enabled: false" in err, err


# No Ingress routes the dashboard, which dashboard.serveOpen requires.
UNROUTED = ("--set", "ingress.dashboard.enabled=false")


@requires_helm
@pytest.mark.parametrize("how", ["chart-mode-none", "policy-without-auth"])
def test_serve_open_under_mode_none_reaches_the_dashboard_only(how):
    if how == "chart-mode-none":
        docs = render("--set", "dashboard.auth.mode=none", "--set", "dashboard.serveOpen=true",
                      *UNROUTED)
    else:
        docs = render("--set", "dashboard.serveOpen=true", *UNROUTED,
                      policy=_policy_without_dashboard_auth())
    specs = pod_specs(docs)
    assert env_of(specs["dashboard"])["FORGD_DASHBOARD_SERVE_OPEN"] == {
        "name": "FORGD_DASHBOARD_SERVE_OPEN", "value": "true"}
    for role, spec in specs.items():
        if role != "dashboard":
            assert "FORGD_DASHBOARD_SERVE_OPEN" not in env_of(spec), role


@requires_helm
@pytest.mark.parametrize("extra", [
    (*OIDC,),
    ("--set", "dashboard.trustedHeaderStrippedBy=a proxy checked in this test"),
], ids=["oidc_jwt", "trusted_header"])
def test_serve_open_under_another_mode_is_refused(extra):
    err = render_error(*base_without("dashboard.trustedHeaderStrippedBy"), *extra,
                       "--set", "dashboard.serveOpen=true", *UNROUTED)
    assert "has no value" not in err, err
    assert "dashboard.serveOpen is true but the effective dashboard.auth.mode is" in err, err


@requires_helm
@pytest.mark.parametrize("key", ["FORGD_DASHBOARD_SERVE_OPEN", "forgd_dashboard_serve_open"])
def test_extra_env_cannot_serve_the_dashboard_open(key):
    err = render_error("--set", "dashboard.auth.mode=none", "--set", "dashboard.serveOpen=true",
                       *UNROUTED, "--set-string", f"extraEnv.{key}=true")
    assert f"extraEnv.{key} would serve the dashboard with no sign-in" in err, err
    assert "Set dashboard.serveOpen instead." in err, err


@requires_helm
def test_serve_open_with_the_dashboard_disabled_is_refused():
    err = render_error("--set", "dashboard.enabled=false", "--set", "dashboard.serveOpen=true")
    assert "dashboard.serveOpen is true but dashboard.enabled is false" in err, err


@requires_helm
def test_serve_open_is_off_by_default(docs):
    values = yaml.safe_load((CHART / "values.yaml").read_text())
    assert values["dashboard"]["serveOpen"] is False
    for role, spec in pod_specs(docs).items():
        assert "FORGD_DASHBOARD_SERVE_OPEN" not in env_of(spec), role


@requires_helm
def test_the_dashboard_auth_override_reaches_only_the_dashboard():
    """No other role reads it, and shipping it wider would be noise that
    looks like configuration."""
    docs = render(*base_without("dashboard.trustedHeaderStrippedBy"), *OIDC)
    for name, spec in pod_specs(docs).items():
        if name == "dashboard":
            continue
        env = env_of(spec)
        assert not any(k.startswith("FORGD_DASHBOARD_") for k in env), (name, env.keys())


# -- adapter 2's receiving end -------------------------------------------

# A token comes with it, because the chart refuses the endpoint without
# one: intake with no clients starts and 401s every developer, which looks
# exactly like a laptop pointed at the wrong URL.
INTAKE = ["--set", "intake.enabled=true",
          "--set", "intake.clients={dev-laptop}"]


@requires_helm
def test_the_intake_is_off_by_default(docs):
    """It needs a per-developer token each. A deployment that has issued
    none would expose an endpoint refusing everything."""
    assert "intake" not in pod_specs(docs)
    public = next(
        v for k, v in by_kind(docs, "Ingress").items() if k.endswith("-public")
    )
    paths = [p["path"] for r in public["spec"]["rules"] for p in r["http"]["paths"]]
    assert "/intake" not in paths


@requires_helm
def test_the_intake_hashes_with_the_deployment_salt():
    """/scan hashes HERE, so an empty salt is a brute-forceable record.

    Records arriving on /intake are already hashed with the sending
    laptop's per-device salt and this does not touch them. Records
    written on /scan are hashed in this pod, and while the role had no
    salt they were bare sha256 -- about a billion guesses for an SSN.
    """
    docs = render(*INTAKE)
    e = env_of(pod_specs(docs)["intake"])["FORGD_HASH_SALT"]
    assert e["valueFrom"]["secretKeyRef"]["key"] == "hash-salt"
    assert "value" not in e, "the salt must be a secret reference, not a literal"


@requires_helm
def test_the_intake_runs_gitleaksd_because_a_laptop_is_waiting():
    """The CLI's per-exec compile measured 1.12 s in this container.

    Against adapter 2's 200 ms budget that is not a slow scan, it is a
    timeout: every remote scan failed and the laptop fell back to
    scanning locally, which is the outcome /scan exists to avoid.
    """
    spec = pod_specs(render(*INTAKE))["intake"]
    assert env_of(spec)["FORGD_GITLEAKS_SOCKET"]["value"] == "/run/forgd/gitleaksd.sock"
    assert "/run/forgd" in {m["mountPath"] for m in spec["containers"][0]["volumeMounts"]}
    # The entrypoint waits for the socket and exits if it never appears,
    # so readiness alone would report a crash loop as a failing pod
    # rather than a slow start.
    assert spec["containers"][0]["startupProbe"]["httpGet"]["path"] == "/healthz"


@requires_helm
def test_the_intake_writes_with_the_writer_identity():
    docs = render(*INTAKE)
    spec = pod_specs(docs)["intake"]
    assert spec["serviceAccountName"].endswith("-writer")
    assert env_of(spec)["AZURE_CLIENT_ID"]["value"] == WRITER_ID


@requires_helm
def test_the_intake_path_does_not_collide_with_the_collector():
    """`/v1` is a PREFIX rule, so /v1/findings would be routed to the
    collector -- which answers 404 for a path it does not serve, and a hook
    shipping there would park every batch forever against an endpoint that
    exists. Longest-prefix would in fact save it, but that is a property of
    the controller rather than of this chart.
    """
    docs = render(*INTAKE)
    public = next(
        v for k, v in by_kind(docs, "Ingress").items() if k.endswith("-public")
    )
    routes = {
        p["path"]: p["backend"]["service"]["name"]
        for r in public["spec"]["rules"] for p in r["http"]["paths"]
    }
    assert routes["/intake"].endswith("-intake")
    assert not any(p.startswith("/v1") and p != "/v1" for p in routes), routes


@requires_helm
def test_the_intake_is_not_behind_the_dashboard_auth():
    """It authenticates itself with a bearer token. Behind an auth proxy a
    laptop would be redirected to a sign-in page it cannot complete, and
    ship.py would park every batch."""
    docs = render(
        *INTAKE,
        "--set",
        "ingress.dashboard.annotations.nginx\\.ingress\\.kubernetes\\.io/auth-url=https://p/auth",
    )
    ingresses = by_kind(docs, "Ingress")
    public = next(v for k, v in ingresses.items() if k.endswith("-public"))
    assert "/intake" in [
        p["path"] for r in public["spec"]["rules"] for p in r["http"]["paths"]
    ]
    # Not a bare "auth" substring: enable-global-auth: "false" lives here
    # deliberately and is the OPPOSITE of fronting the path.
    for key in public["metadata"].get("annotations") or {}:
        leaf = key.rsplit("/", 1)[-1]
        assert not leaf.startswith("auth-"), leaf


def test_ci_renders_the_chart_rather_than_only_linting_it():
    """`helm lint` is not a gate on whether the chart renders.

    A failed `required` comes out of lint as

        level=WARN msg="missing required values"

    and lint still exits 0 and reports "0 chart(s) failed". A lint-only
    step stays green against a values set the chart refuses -- one missing
    `ingest.image.repository`, `dashboard.trustedHeaderStrippedBy` and
    `ingress.tls.clusterIssuer`, any one of which stops a render.

    So the step must also `helm template`, and against the same values:
    linting one configuration and rendering another would prove neither.
    """
    import yaml as _yaml

    doc = _yaml.safe_load(
        (REPO / ".github" / "workflows" / "ci.yml").read_text(encoding="utf-8")
    )
    step = next(
        s
        for job in doc["jobs"].values()
        for s in job.get("steps", [])
        if s.get("name") == "Lint the Helm chart"
    )
    script = step["run"]
    assert "helm template" in script, script
    # One values list, used by both -- not two that can drift apart.
    assert script.count("VALUES=(") == 1, script
    assert script.count('"${VALUES[@]}"') == 2, script


@requires_helm
def test_enabling_intake_without_a_token_is_refused():
    """It would start and 401 every developer.

    That failure reads as a laptop with the wrong URL or a bad token, and
    the developer debugging it has no access to the thing that would say
    otherwise. Refusing at render puts the answer where the mistake is.
    """
    out = subprocess.run(
        [helm, "template", "rel", str(CHART), *BASE,
         "--set", "intake.enabled=true"],
        capture_output=True, text=True, timeout=120,
    )
    assert out.returncode != 0
    assert "neither intake.fleet.enabled nor intake.clients" in out.stderr


@requires_helm
def test_each_client_gets_its_own_intake_token(docs):
    """One per client, so one can be revoked without reissuing the rest."""
    rendered = subprocess.run(
        [helm, "template", "rel", str(CHART), *BASE,
         "--set", "intake.enabled=true",
         "--set", "intake.clients={alice,bob}"],
        capture_output=True, text=True, timeout=120,
    )
    assert rendered.returncode == 0, rendered.stderr
    assert "FORGD_INTAKE_TOKEN_ALICE" in rendered.stdout
    assert "FORGD_INTAKE_TOKEN_BOB" in rendered.stdout
    assert "intake-token-alice" in rendered.stdout
    assert "intake-token-bob" in rendered.stdout


@requires_helm
def test_intake_variables_come_from_names_not_from_token_values():
    """The same rule the collector's org tokens follow.

    Iterating `secrets.intakeTokens` to build the env meant an
    `existingSecret` deployment rendered NO variables at all -- the loop
    had nothing to walk, the pod came up with no tokens, and every
    developer got a 401 from an endpoint that logged "no intake tokens
    configured".

    Names drive the variables; the values stay in the secret.
    """
    out = subprocess.run(
        [helm, "template", "rel", str(CHART), *base_without("secrets."),
         "--set", "secrets.existingSecret=forgd-verdict",
         "--set", "intake.enabled=true",
         "--set", "intake.clients={alice-laptop}"],
        capture_output=True, text=True, timeout=120,
    )
    assert out.returncode == 0, out.stderr
    assert "FORGD_INTAKE_TOKEN_ALICE_LAPTOP" in out.stdout
    assert "intake-token-alice-laptop" in out.stdout
    # And no token value went into the release to get there.
    assert "intakeTokens" not in out.stdout


@requires_helm
def test_the_fleet_token_and_its_predecessor_come_from_the_secret():
    out = subprocess.run(
        [helm, "template", "rel", str(CHART), *base_without("secrets."),
         "--set", "secrets.existingSecret=forgd-verdict",
         "--set", "intake.enabled=true", "--set", "intake.fleet.enabled=true"],
        capture_output=True, text=True, timeout=120,
    )
    assert out.returncode == 0, out.stderr
    env = env_of(pod_specs([d for d in yaml.safe_load_all(out.stdout) if d])["intake"])
    assert env["FORGD_INTAKE_FLEET_TOKEN"]["valueFrom"]["secretKeyRef"] == {
        "name": "forgd-verdict", "key": "intake-fleet-token"}
    assert env["FORGD_INTAKE_FLEET_TOKEN_PREVIOUS"]["valueFrom"]["secretKeyRef"] == {
        "name": "forgd-verdict", "key": "intake-fleet-token-previous", "optional": True}
    assert not any(n.startswith("FORGD_INTAKE_TOKEN_") for n in env)


@requires_helm
def test_a_chart_managed_secret_holds_the_fleet_token():
    docs = render("--set", "intake.enabled=true", "--set", "intake.fleet.enabled=true",
                  "--set", "secrets.intakeFleetToken=fleet-token-value-for-the-render")
    (secret,) = [d for d in docs if d.get("kind") == "Secret"
                 and "intake-fleet-token" in (d.get("stringData") or d.get("data") or {})]
    assert "intake-fleet-token-previous" not in (secret.get("stringData") or secret.get("data"))


def _env_names(docs):
    """Every container env name in the release, by workload kind."""
    out = []
    for d in docs:
        spec = (d.get("spec", {}).get("template", {}).get("spec")
                or d.get("spec", {}).get("jobTemplate", {}).get("spec", {})
                     .get("template", {}).get("spec"))
        if not spec:
            continue
        for c in spec.get("containers", []):
            out.append({e["name"] for e in c.get("env", [])})
    return out


def test_extra_env_reaches_every_role():
    """`sinks[].endpoint` is an $ENV_VAR because the URI names this
    deployment's own data collection rule, and committing it would point
    every fork at a rule they hold no grant on.

    Every role, because a sink is built wherever findings are produced and
    the collector is not the only one.
    """
    docs = render("--set-string",
                  "extraEnv.FORGD_SINK_ENDPOINT_AZMON=https://x/dataCollectionRules/d/streams/s")
    envs = _env_names(docs)
    # A count would pin whichever roles happen to be enabled in BASE --
    # intake is not one of them -- so this asserts the property instead:
    # anything that gets the store URL gets this too, because both come
    # from commonEnv.
    assert envs, "nothing rendered"
    for names in envs:
        if "FORGD_VERDICT_STORE" not in names:
            continue  # a sidecar that runs no forgd code
        assert "FORGD_SINK_ENDPOINT_AZMON" in names, sorted(names)


def test_extra_env_is_absent_by_default():
    """An empty map renders nothing, not an empty entry."""
    docs = render()
    assert not [e for e in _env_names(docs)
                if "FORGD_SINK_ENDPOINT_AZMON" in e]


def test_the_attestation_reaches_the_pod():
    """The chart refuses trusted_header without `trustedHeaderStrippedBy`,
    and the app now requires the same thing. Passing it through keeps that
    one setting instead of two.

    It must sit OUTSIDE the `with .Values.dashboard.auth.header` block:
    inside it `.` is the header string, so `.Values` does not resolve --
    and `helm template` renders anyway in a fixture that leaves the
    header unset, because the whole block is skipped. A render with the
    header set fails.
    """
    for extra in ([], ["--set-string", "dashboard.auth.header=authorization"]):
        docs = render(*extra)
        for d in docs:
            meta = d.get("metadata", {}).get("name", "")
            if d.get("kind") != "Deployment" or "dashboard" not in meta:
                continue
            names = {e["name"] for e in
                     d["spec"]["template"]["spec"]["containers"][0]["env"]}
            assert "FORGD_DASHBOARD_STRIPPED_BY" in names, extra
            break
        else:
            raise AssertionError("no dashboard deployment rendered")


def test_the_fallback_threshold_matches_the_shipped_cron():
    """Belt and braces for the derived late threshold.

    The dashboard DERIVES its late threshold from the cadence the job
    measures for itself, so a fork on any schedule is right without
    configuring anything. But that needs three runs before it has a
    cadence, and until then the fallback constant applies -- so the
    constant still has to agree with the schedule this chart ships.

    Nothing connected them before. That is the finding.
    """
    from forgd_verdict.dashboard.topology import (
        LATE_AFTER_MIN,
        LATE_AFTER_SLACK_MIN,
    )
    from forgd_verdict.store.base import SOURCE_COMPLIANCE_SCAN

    values = yaml.safe_load((CHART / "values.yaml").read_text())
    schedule = values["ingest"]["schedule"]

    # Only the `0 */N * * *` form, which is what ships. Anything else is a
    # deliberate change and should come with a look at the constant.
    m = re.fullmatch(r"\s*0 \*/(\d+) \* \* \*\s*", schedule)
    assert m, (
        f"ingest.schedule is {schedule!r}, which this test cannot read. "
        "Check LATE_AFTER_MIN[compliance_scan] by hand and widen this."
    )
    hours = int(m.group(1))
    expected = 2 * hours * 60 + LATE_AFTER_SLACK_MIN
    assert LATE_AFTER_MIN[SOURCE_COMPLIANCE_SCAN] == expected, (
        f"the chart runs the scan every {hours}h, so the fallback "
        f"threshold should be {expected} minutes (two intervals plus "
        f"slack), not {LATE_AFTER_MIN[SOURCE_COMPLIANCE_SCAN]}"
    )


def test_the_scan_route_is_routed_to_the_intake_service():
    """Without its own rule `/scan` falls through to `/` -- the dashboard
    -- where oauth2-proxy answers a 302 to a login page. A hook reads that
    as unreachable and silently falls back to scanning locally, which is
    the coverage it was configured to stop doing.

    There is no shared prefix with `/intake` to inherit, which is why this
    is not covered by that rule.
    """
    # The chart refuses intake.enabled with no clients, on purpose: an
    # endpoint that 401s every developer looks exactly like a bad URL.
    # `intake.clients` is a list of NAMES; the tokens live in the secret
    # as intake-token-<name>. And the chart refuses intake.enabled with no
    # clients, on purpose: an endpoint that 401s every developer looks
    # exactly like a bad URL.
    docs = render("--set", "intake.enabled=true",
                  "--set", "intake.clients={alice}",
                  "--set", "secrets.intakeTokens.alice=a-token-long-enough-here")
    paths = {}
    for d in docs:
        if d.get("kind") != "Ingress":
            continue
        for rule in d["spec"].get("rules", []):
            for path in rule.get("http", {}).get("paths", []):
                paths[path["path"]] = path["backend"]["service"]["name"]
    assert "/scan" in paths, sorted(paths)
    assert paths["/scan"] == paths["/intake"], paths


def _ingest_env(docs):
    return {e["name"]: e for e in pod_specs(docs)["ingest"]["containers"][0]["env"]}


@requires_helm
def test_a_managed_agents_key_reaches_the_ingest_job():
    env = _ingest_env(render("--set", "secrets.managedAgentsKeys.support-agents=k"))
    ref = env["FORGD_MANAGED_AGENTS_KEY_SUPPORT_AGENTS"]["valueFrom"]["secretKeyRef"]
    assert ref["key"] == "managed-agents-key-support-agents"
    # Beside Managed Agents, the Compliance key may be absent.
    assert env["ANTHROPIC_COMPLIANCE_ACCESS_KEY"]["valueFrom"]["secretKeyRef"]["optional"]


@requires_helm
def test_without_managed_agents_the_compliance_key_is_still_required(docs):
    ref = _ingest_env(docs)["ANTHROPIC_COMPLIANCE_ACCESS_KEY"]["valueFrom"]["secretKeyRef"]
    assert "optional" not in ref
    assert not any(n.startswith("FORGD_MANAGED_AGENTS_KEY_") for n in _ingest_env(docs))


def _dash_env(docs):
    return {e["name"]: e.get("value") for e in
            pod_specs(docs)["dashboard"]["containers"][0]["env"]}


def _secret_wired_env_names() -> list[str]:
    """Every env name a template wires from a secretKeyRef. A templated
    suffix is cut off and the name keeps its trailing `_` as a prefix."""
    names = []
    for tmpl in (CHART / "templates").glob("*.yaml"):
        lines = tmpl.read_text().splitlines()
        for i, line in enumerate(lines):
            m = re.match(r"\s*- name: ([A-Z0-9_]+)(\{\{)?", line)
            if m and any("secretKeyRef" in nxt for nxt in lines[i + 1:i + 4]):
                names.append(m.group(1))
    names += re.findall(r"- name: ([A-Z0-9_]+)\n\s+valueFrom:\n\s+secretKeyRef:",
                        (CHART / "templates" / "_helpers.tpl").read_text())
    return sorted(set(names))


# A value nothing else in the chart or its errors could contain.
EXTRA_ENV_CANARY = "canary-7f3e1d9b"


@requires_helm
def test_extra_env_refuses_the_hash_salt_and_never_prints_the_value():
    err = render_error("--set-string", f"extraEnv.FORGD_HASH_SALT={EXTRA_ENV_CANARY}")
    assert "extraEnv.FORGD_HASH_SALT" in err
    assert "secrets.hashSalt" in err
    assert EXTRA_ENV_CANARY not in err


@requires_helm
@pytest.mark.parametrize("key", [
    "forgd_hash_salt",
    "Webhook_Secret",
    "FORGD_OTEL_TOKEN_PRIMARY",
    "forgd_intake_token_alice_laptop",
    "FORGD_MANAGED_AGENTS_KEY_WS1",
    "forgd_overrides_signing_key",
])
def test_extra_env_refuses_credentials_whatever_the_case_or_suffix(key):
    err = render_error("--set-string", f"extraEnv.{key}={EXTRA_ENV_CANARY}")
    assert f"extraEnv.{key}" in err
    assert EXTRA_ENV_CANARY not in err


@requires_helm
def test_extra_env_refuses_every_variable_the_chart_wires_from_a_secret():
    names = _secret_wired_env_names()
    assert "FORGD_HASH_SALT" in names and "FORGD_OTEL_TOKEN_" in names, names
    for name in names:
        key = name + "X" if name.endswith("_") else name
        err = render_error("--set-string", f"extraEnv.{key}={EXTRA_ENV_CANARY}")
        assert f"extraEnv.{key}" in err, (name, err)


@requires_helm
def test_a_benign_extra_env_key_still_reaches_the_dashboard():
    env = _dash_env(render("--set-string", "extraEnv.FORGD_SINK_ENDPOINT_AZMON=https://x/s"))
    assert env["FORGD_SINK_ENDPOINT_AZMON"] == "https://x/s"
    assert "FORGD_HASH_SALT" not in env


def _render_values(values: str) -> subprocess.CompletedProcess:
    """Render with a values file, so a key can hold a newline or `: `."""
    f = tempfile.NamedTemporaryFile("w", suffix=".yaml", delete=False)
    f.write(values)
    f.close()
    return subprocess.run(
        _argv(("--values", f.name), None), capture_output=True, text=True, timeout=120
    )


@requires_helm
@pytest.mark.parametrize("extra_env", [
    pytest.param('{"SAFE\\n- name: FORGD_HASH_SALT": "%s"}', id="newline-key"),
    pytest.param('{"SAFE: %s": "x"}', id="colon-key"),
    pytest.param('[{"name": "SAFE", "value": "%s"}]', id="list-form"),
    pytest.param('{"SAFE": {"nested": "%s"}}', id="map-value"),
])
def test_extra_env_that_is_not_a_map_of_names_to_scalars_is_refused(extra_env):
    canary = f"CANARY-{secrets.token_hex(8)}"
    out = _render_values("extraEnv: " + extra_env % canary + "\n")
    assert out.returncode != 0, out.stdout
    assert canary not in out.stdout
    assert canary not in out.stderr
    assert "FORGD_HASH_SALT" not in out.stderr


@requires_helm
def test_an_extra_env_key_injecting_an_entry_is_refused_as_an_invalid_key():
    out = _render_values('extraEnv: {"SAFE\\n- name: FORGD_HASH_SALT": "x"}\n')
    assert out.returncode != 0, out.stdout
    assert "an invalid key" in out.stderr


@requires_helm
def test_a_valid_extra_env_key_renders_quoted():
    out = _render_values("extraEnv:\n  FORGD_SINK_ENDPOINT_AZMON: https://x/s\n")
    assert out.returncode == 0, out.stderr
    assert '- name: "FORGD_SINK_ENDPOINT_AZMON"\n' in out.stdout
    assert 'value: "https://x/s"' in out.stdout


@requires_helm
def test_issuers_alone_render_and_the_app_reads_them(monkeypatch):
    """The chart required jwksUrl/issuer/audience even when every IdP was in
    an issuers list. Rendered, then fed to the real policy loader."""
    from forgd_verdict.dashboard.auth import AuthConfig
    from forgd_verdict.policy import load_policy

    env = _dash_env(render(
        "--set", "dashboard.auth.mode=oidc_jwt",
        "--set", "dashboard.auth.platform=oauth2_proxy",
        "--set", "dashboard.auth.groupsClaim=roles",
        "--set-json", 'dashboard.auth.issuers=[{"issuer":"https://a.example/",'
                      '"jwksUrl":"https://a.example/keys","audience":["x","y"]}]'))
    for k in ("FORGD_DASHBOARD_JWKS_URL", "FORGD_DASHBOARD_ISSUER", "FORGD_DASHBOARD_AUDIENCE"):
        monkeypatch.delenv(k, raising=False)
    for k, v in env.items():
        if k.startswith("FORGD_DASHBOARD_") and v is not None:
            monkeypatch.setenv(k, v)
    cfg = AuthConfig.parse(load_policy(str(REPO / "policy.yaml")).dashboard["auth"])
    assert cfg.header == "authorization"
    assert [(i.issuer, i.audience, i.groups_claim) for i in cfg.issuers] == [
        ("https://a.example/", ("x", "y"), "roles")]


@requires_helm
def test_an_incomplete_issuer_entry_is_a_render_error():
    err = render_error("--set", "dashboard.auth.mode=oidc_jwt",
                       "--set-json", 'dashboard.auth.issuers=[{"issuer":"https://a.example/"}]')
    assert "issuers[0].jwksUrl" in err


@requires_helm
def test_alb_needs_its_arn_at_render_time():
    err = render_error("--set", "dashboard.auth.mode=oidc_jwt",
                       "--set", "dashboard.auth.platform=alb_oidc",
                       "--set", "dashboard.auth.issuer=https://idp/",
                       "--set", "dashboard.auth.audience=client")
    assert "albArn" in err


@requires_helm
def test_a_platform_under_trusted_header_is_a_render_error():
    err = render_error("--set", "dashboard.auth.platform=oauth2_proxy")
    assert "only for oidc_jwt" in err


@requires_helm
@pytest.mark.parametrize("extra", [
    ("--set", "dashboard.auth.albArn=notanarn"),
    ("--set", "dashboard.auth.albArn=arn:aws:elasticloadbalancing:eu-west-1:123456789012:"
              "loadbalancer/app/d/0123abcd",
     "--set-json", 'dashboard.auth.issuers=[{"issuer":"a","jwksUrl":"b","audience":"c"}]'),
])
def test_alb_configs_the_app_refuses_are_render_errors(extra):
    render_error("--set", "dashboard.auth.mode=oidc_jwt", "--set", "dashboard.auth.platform=alb_oidc",
                 "--set", "dashboard.auth.issuer=https://idp/", "--set", "dashboard.auth.audience=c",
                 *extra)


IAP_AUD = "/projects/123456789012/global/backendServices/9876543210"


@requires_helm
def test_iap_renders_with_its_audience_alone_and_the_app_reads_it(monkeypatch):
    from forgd_verdict.dashboard.auth import IAP_ISSUER, AuthConfig
    from forgd_verdict.policy import load_policy

    env = _dash_env(render("--set", "dashboard.auth.mode=oidc_jwt",
                           "--set", "dashboard.auth.platform=iap",
                           "--set", f"dashboard.auth.audience={IAP_AUD}"))
    for k in ("FORGD_DASHBOARD_JWKS_URL", "FORGD_DASHBOARD_ISSUER", "FORGD_DASHBOARD_HEADER"):
        monkeypatch.delenv(k, raising=False)
    for k, v in env.items():
        if k.startswith("FORGD_DASHBOARD_") and v is not None:
            monkeypatch.setenv(k, v)
    cfg = AuthConfig.parse(load_policy(str(REPO / "policy.yaml")).dashboard["auth"])
    assert cfg.header == "x-goog-iap-jwt-assertion"
    assert [(i.issuer, i.audience) for i in cfg.issuers] == [(IAP_ISSUER, (IAP_AUD,))]


@requires_helm
@pytest.mark.parametrize("extra", [
    (),
    ("--set", "dashboard.auth.audience=123-abc.apps.googleusercontent.com"),
    ("--set", f"dashboard.auth.audience={IAP_AUD}", "--set", "dashboard.auth.issuer=https://x/"),
    ("--set", f"dashboard.auth.audience={IAP_AUD}", "--set", "dashboard.auth.jwksUrl=https://x/"),
])
def test_iap_configs_the_app_refuses_are_render_errors(extra):
    err = render_error("--set", "dashboard.auth.mode=oidc_jwt",
                       "--set", "dashboard.auth.platform=iap", *extra)
    assert "platform is iap" in err or "not an IAP audience" in err, err


@requires_helm
def test_iap_with_an_entitlements_map_is_a_render_error():
    policy = (REPO / "policy.yaml").read_text().replace(
        "  # entitlements:\n  #   map:\n  #     - group: <Entra ID group object id>\n"
        "  #       orgs: [$FORGD_ORG_ID_PRIMARY]\n",
        "  entitlements:\n    map:\n      - group: g1\n        orgs: [$FORGD_ORG_ID_PRIMARY]\n")
    assert "\n  entitlements:\n" in policy, "the fixture must actually set a map"
    args = ("--set", "dashboard.auth.mode=oidc_jwt", "--set", "dashboard.auth.platform=iap",
            "--set", f"dashboard.auth.audience={IAP_AUD}")
    render(*args, policy=(REPO / "policy.yaml").read_text())
    err = render_error(*args, policy=policy)
    assert "entitlements.map" in err and "platform is iap" in err, err


# -- EKS -----------------------------------------------------------------
#
# Rendered from the shipped example alone, not on top of BASE: BASE is the
# Azure configuration, and a test layered on it would pass with Azure
# settings the example does not carry.

EKS_VALUES = CHART / "values-eks.example.yaml"


def render_eks(*extra: str) -> list[dict]:
    out = subprocess.run(
        [helm, "template", "rel", str(CHART), "-f", str(EKS_VALUES),
         "--set-file", f"policy.inline={REPO / 'policy.yaml'}", *extra],
        capture_output=True, text=True, timeout=120,
    )
    if out.returncode != 0:
        raise AssertionError(out.stderr.strip())
    return [d for d in yaml.safe_load_all(out.stdout) if d]


@pytest.fixture(scope="module")
def eks_values() -> dict:
    return yaml.safe_load(EKS_VALUES.read_text(encoding="utf-8"))


@pytest.fixture(scope="module", params=[False, True], ids=["intake-off", "intake-on"])
def eks_docs(request) -> list[dict]:
    # Intake is off in the example; rendered both ways so its template is
    # held to the same rules.
    extra = ("--set", "intake.enabled=true", "--set", "intake.clients={alice}") if request.param else ()
    return render_eks(*extra)


def _keys(node) -> set[str]:
    if isinstance(node, dict):
        return set(node) | {k for v in node.values() for k in _keys(v)}
    if isinstance(node, list):
        return {k for v in node for k in _keys(v)}
    return set()


def _containers(spec: dict) -> list[dict]:
    return spec.get("initContainers", []) + spec["containers"]


def test_the_eks_example_uses_placeholder_accounts_only():
    text = EKS_VALUES.read_text(encoding="utf-8")
    accounts = set(re.findall(r"arn:aws:iam::(\d+):", text)) | set(re.findall(r"(\d{12})\.dkr\.ecr\.", text))
    assert accounts == {"123456789012"}, accounts


@requires_helm
def test_the_eks_example_renders_no_azure_workload_identity(eks_docs):
    """Neither the webhook's pod label nor the service account annotations.
    On a cluster without the Azure webhook they do nothing, and they say the
    pods authenticate a way they do not."""
    leaked = sorted(k for k in _keys(eks_docs) if k.startswith("azure.workload.identity/"))
    assert not leaked, leaked


@requires_helm
def test_the_eks_example_renders_no_role_annotation(eks_docs):
    """Under cluster-eks's default Pod Identity, an eks.amazonaws.com/role-arn
    annotation makes the EKS webhook inject a web identity token that the AWS
    SDK tries first, and no pod reaches S3."""
    assert by_kind(eks_docs, "ServiceAccount")
    leaked = sorted(k for k in _keys(eks_docs) if k.startswith("eks.amazonaws.com/"))
    assert not leaked, leaked


@requires_helm
def test_the_eks_pods_run_on_the_annotated_service_accounts(eks_docs):
    """Pod Identity and IRSA are keyed on the service account, so the reader/writer split
    holds only if each pod names the right one."""
    sas = {name: s["serviceAccountName"] for name, s in pod_specs(eks_docs).items()}
    assert sas["dashboard"].endswith("-reader"), sas
    for role, sa in sas.items():
        if role != "dashboard":
            assert sa.endswith("-writer"), sas


@requires_helm
def test_no_eks_pod_gets_an_azure_client_id(eks_docs):
    """There is no Azure identity to name on EKS, so the variable should not
    be there at all -- empty, it tells whoever reads the pod spec that the
    pod signs in to Azure."""
    for role, spec in pod_specs(eks_docs).items():
        for c in _containers(spec):
            names = [e["name"] for e in c.get("env", [])]
            assert "AZURE_CLIENT_ID" not in names, (role, c["name"])


@requires_helm
def test_the_s3_store_url_reaches_every_eks_pod(eks_docs, eks_values):
    want = eks_values["store"]["url"]
    assert want.startswith("s3://")
    specs = pod_specs(eks_docs)
    assert {"verdict", "collector", "dashboard", "ingest"} <= set(specs), set(specs)
    for role, spec in specs.items():
        assert env_of(spec)["FORGD_VERDICT_STORE"]["value"] == want, role


@requires_helm
def test_the_eks_example_leaves_the_alb_name_to_the_controller(eks_docs):
    """ALB names are unique per account and region. A fixed name in the
    example is the same name in every deployment made from it."""
    ingresses = by_kind(eks_docs, "Ingress")
    assert len(ingresses) == 3, sorted(ingresses)
    named = sorted(n for n, i in ingresses.items()
                   if "alb.ingress.kubernetes.io/load-balancer-name" in (i["metadata"].get("annotations") or {}))
    assert not named, named


@requires_helm
def test_every_eks_ingress_names_the_same_certificate_and_tls_policy(eks_docs):
    """The HTTPS listener is shared by the group, and the controller builds
    it from every member's annotations."""
    ingresses = by_kind(eks_docs, "Ingress")
    assert len(ingresses) == 3, sorted(ingresses)
    for key in ("certificate-arn", "ssl-policy"):
        values = {n: (i["metadata"].get("annotations") or {}).get(f"alb.ingress.kubernetes.io/{key}")
                  for n, i in ingresses.items()}
        assert None not in values.values() and len(set(values.values())) == 1, (key, values)


@requires_helm
def test_the_eks_alb_signs_in_on_the_dashboard_only_and_evaluates_it_last(eks_docs):
    """ALB matches rules in priority order, not by longest prefix, and the
    dashboard's `/` becomes `/*`. Ahead of the public object's rules it
    would put /hook and /v1 behind the ALB's sign-in, and Anthropic reads
    the redirect as a webhook failure. At equal group.order the controller
    orders by name, and `-dashboard` sorts first."""
    ingresses = {d["metadata"]["labels"]["app.kubernetes.io/component"]: d
                 for d in by_kind(eks_docs, "Ingress").values()}
    assert sorted(ingresses) == ["dashboard", "diagnostics", "public"], sorted(ingresses)
    alb = {c: {k.removeprefix("alb.ingress.kubernetes.io/"): v
               for k, v in (i["metadata"].get("annotations") or {}).items()
               if k.startswith("alb.ingress.kubernetes.io/")}
           for c, i in ingresses.items()}

    for component, ingress in ingresses.items():
        assert ingress["spec"]["ingressClassName"] == "alb", component
    # One ALB: the one whose ARN the dashboard verifies tokens against.
    assert len({a.get("group.name") for a in alb.values()}) == 1 and alb["public"]["group.name"]

    signs_in = {c for c, a in alb.items() if any(k.startswith("auth-") for k in a)}
    assert signs_in == {"dashboard"}, signs_in
    assert alb["dashboard"]["auth-type"] == "oidc"

    order = {c: int(a["group.order"]) for c, a in alb.items()}
    assert order["dashboard"] > max(order["public"], order["diagnostics"]), order


# -- GKE -----------------------------------------------------------------
#
# Rendered from the shipped example alone, for the reason the EKS section
# gives. The example signs in to the dashboard through IAP; it is also
# rendered with a generic OIDC issuer, to hold the reader pod to the same
# rules under either, and with intake on, as for EKS. GKE mode's ingress is
# tested in test_helm_gke.py.

GKE_VALUES = CHART / "values-gke.example.yaml"
GKE_WRITER = "forgd-verdict-writer@example-project.iam.gserviceaccount.com"
GKE_READER = "forgd-dashboard-reader@example-project.iam.gserviceaccount.com"
GKE_ANNOTATION = "iam.gke.io/gcp-service-account"
GKE_DASHBOARD_ON = (
    "--set", "dashboard.enabled=true",
    "--set", "dashboard.auth.mode=oidc_jwt",
    "--set", "dashboard.auth.platform=iap",
    "--set", "dashboard.auth.audience=/projects/0/global/backendServices/0",
)
GKE_INTAKE_ON = ("--set", "intake.enabled=true", "--set", "intake.clients={alice}")


def render_gke(*extra: str) -> list[dict]:
    out = subprocess.run(
        [helm, "template", "rel", str(CHART), "-f", str(GKE_VALUES),
         "--set-file", f"policy.inline={REPO / 'policy.yaml'}", *extra],
        capture_output=True, text=True, timeout=120,
    )
    if out.returncode != 0:
        raise AssertionError(out.stderr.strip())
    return [d for d in yaml.safe_load_all(out.stdout) if d]


@pytest.fixture(scope="module")
def gke_values() -> dict:
    return yaml.safe_load(GKE_VALUES.read_text(encoding="utf-8"))


@pytest.fixture(scope="module", params=["example", "dashboard-on", "intake-on"])
def gke_docs(request) -> list[dict]:
    extra = {"example": (), "dashboard-on": GKE_DASHBOARD_ON, "intake-on": GKE_INTAKE_ON}
    return render_gke(*extra[request.param])


def _service_accounts(docs: list[dict]) -> dict[str, dict]:
    """"writer" / "reader" -> the ServiceAccount, by the chart's label."""
    return {d["metadata"]["labels"]["forgd.ai/store-access"]: d
            for d in by_kind(docs, "ServiceAccount").values()}


def test_the_gke_example_uses_placeholder_projects_only():
    text = GKE_VALUES.read_text(encoding="utf-8")
    projects = (set(re.findall(r"@([a-z][a-z0-9-]+)\.iam\.gserviceaccount\.com", text))
                | set(re.findall(r"docker\.pkg\.dev/([a-z][a-z0-9-]+)/", text))
                | set(re.findall(r"serviceAccount:([a-z][a-z0-9-]+)\.svc\.id\.goog", text)))
    assert projects == {"example-project"}, projects


def test_the_gke_example_is_gke_mode_with_iap_and_no_azure_identity(gke_values):
    assert gke_values["ingress"]["enabled"] is True
    assert gke_values["ingress"]["className"] == "gce"
    assert gke_values["dashboard"]["enabled"] is True
    assert gke_values["dashboard"]["auth"]["platform"] == "iap"
    assert gke_values["workloadIdentity"]["enabled"] is False


@requires_helm
def test_the_gke_example_renders_no_azure_workload_identity(gke_docs):
    leaked = sorted(k for k in _keys(gke_docs) if k.startswith("azure.workload.identity/"))
    assert not leaked, leaked


@requires_helm
def test_no_gke_pod_gets_an_azure_client_id(gke_docs):
    specs = pod_specs(gke_docs)
    assert specs
    for role, spec in specs.items():
        for c in _containers(spec):
            names = [e["name"] for e in c.get("env", [])]
            assert not [n for n in names if n.startswith("AZURE_")], (role, c["name"], names)


@requires_helm
def test_each_gke_service_account_names_its_own_google_account(gke_docs):
    """Exactly one annotation each, and different: the reader's is what keeps
    the dashboard from holding the writer's create and delete."""
    sas = _service_accounts(gke_docs)
    assert sorted(sas) == ["reader", "writer"], sorted(sas)
    assert sas["writer"]["metadata"]["annotations"] == {GKE_ANNOTATION: GKE_WRITER}
    assert sas["reader"]["metadata"]["annotations"] == {GKE_ANNOTATION: GKE_READER}
    assert GKE_WRITER != GKE_READER


@requires_helm
def test_the_gke_pods_run_on_the_annotated_service_accounts(gke_docs):
    """Workload Identity is keyed on the Kubernetes service account, so the
    reader/writer split holds only if each pod names the right one."""
    sas = _service_accounts(gke_docs)
    writer, reader = sas["writer"]["metadata"]["name"], sas["reader"]["metadata"]["name"]
    assert writer != reader
    by_role = {name: s["serviceAccountName"] for name, s in pod_specs(gke_docs).items()}
    assert {"verdict", "collector", "ingest"} <= set(by_role), by_role
    for role, sa in by_role.items():
        assert sa == (reader if role == "dashboard" else writer), by_role


@requires_helm
def test_the_dashboard_rendered_on_runs_as_the_gke_reader():
    """The example leaves the dashboard off, so the fixture above sees it
    only in one of its three renders. Pinned here on its own."""
    docs = render_gke(*GKE_DASHBOARD_ON)
    sas = _service_accounts(docs)
    assert pod_specs(docs)["dashboard"]["serviceAccountName"] == sas["reader"]["metadata"]["name"]


@requires_helm
def test_the_gs_store_url_reaches_every_gke_pod(gke_docs, gke_values):
    want = gke_values["store"]["url"]
    assert want.startswith("gs://")
    specs = pod_specs(gke_docs)
    assert {"verdict", "collector", "ingest"} <= set(specs), set(specs)
    for role, spec in specs.items():
        for c in _containers(spec):
            env = {e["name"]: e for e in c.get("env", [])}
            assert env["FORGD_VERDICT_STORE"]["value"] == want, (role, c["name"])


@requires_helm
def test_the_gke_example_renders_one_ingress(gke_docs):
    assert len(by_kind(gke_docs, "Ingress")) == 1


# The install commands the docs and the aks stack print, rendered as written
# against the policy they name, with only shell and Terraform substitutions
# filled in. Placeholders such as `<tls-secret>` render as literal strings.

PLACEHOLDER_VALUES = {
    "store.url": "https://acct.blob.core.windows.net/findings",
    "ingress.className": "webapprouting.kubernetes.azure.com",
}


def _readme_install_command() -> list[str]:
    text = (REPO / "deploy" / "helm" / "README.md").read_text(encoding="utf-8")
    section = text.split("\n## Installing\n", 1)[1].split("\n## ", 1)[0]
    m = re.search(r"```sh\n(helm upgrade --install .*?)\n```", section, re.DOTALL)
    assert m, "deploy/helm/README.md § Installing has no helm upgrade --install block"
    return shlex.split(m.group(1).replace("\\\n", " "))


def _aks_install_command() -> list[str]:
    src = (AKS_LAB / "outputs.tf").read_text(encoding="utf-8")
    m = re.search(r'output "helm_install_command" \{(.*?)\n\}', src, re.DOTALL)
    assert m, "examples/aks/outputs.tf has no helm_install_command output"
    parts = re.findall(r'^\s*"([^"]*)",?\s*$', m.group(1), re.MULTILINE)
    return " ".join(parts).split()


def _as_template(argv: list[str]) -> list[str]:
    assert argv[:3] == ["helm", "upgrade", "--install"], argv[:3]
    out = [helm, "template", argv[3], str(REPO / argv[4])]
    rest = argv[5:]
    i = 0
    while i < len(rest):
        flag = rest[i]
        if flag == "--create-namespace":
            i += 1
            continue
        value = rest[i + 1]
        if flag == "--set-string" and value.startswith("orgIds."):
            key, _, v = value.partition("=")
            if v == "<organization-uuid>":
                value = f"{key}=00000000-0000-0000-0000-000000000000"
        if flag in ("--set", "--set-file"):
            key, _, v = value.partition("=")
            if "$" in v:
                v = PLACEHOLDER_VALUES.get(key, f"placeholder-{key}")
            if flag == "--set-file":
                v = str(REPO / v)
            value = f"{key}={v}"
        out += [flag, value]
        i += 2
    return out


@requires_helm
@pytest.mark.parametrize("command", [_readme_install_command, _aks_install_command],
                         ids=["helm-readme", "aks-output"])
def test_the_documented_install_command_renders(command):
    argv = _as_template(command())
    proc = subprocess.run(argv, capture_output=True, text=True, timeout=120, cwd=REPO)
    assert proc.returncode == 0, proc.stderr
    assert "kind: Ingress" in proc.stdout


# -- ModSecurity and service account tokens ------------------------------------

@requires_helm
@pytest.mark.parametrize("key,value", [
    ("ingress.annotations", "true"),
    ("ingress.annotations", "false"),
    ("ingress.connector.annotations", "true"),
], ids=["public-on", "public-off", "connector-on"])
def test_a_user_annotation_cannot_turn_modsecurity_back_on(key, value):
    """The chart sets enable-modsecurity: "false" on /hook, /v1 and /mcp,
    and a user annotation with the same key would be emitted after it, as a
    duplicate key whose last value wins."""
    connector = ("--set", "connector.enabled=true",
                 "--set", "connector.auth.issuer=https://login.example.com/t/v2.0",
                 "--set", "connector.auth.jwksUrl=https://login.example.com/t/keys",
                 "--set", "connector.auth.audience={api-client-id}",
                 "--set", "connector.requiredScope=findings.read")
    err = render_error(*connector, "--set", f"{key}.nginx\\.ingress\\.kubernetes\\.io/enable-modsecurity={value}")
    assert "enable-modsecurity" in err and "ModSecurity" in err, err


@requires_helm
@pytest.mark.parametrize("extra", [
    (),
    ("--set", "intake.enabled=true", "--set", "intake.clients={dev-laptop}",
     "--set", "connector.enabled=true",
     "--set", "connector.auth.issuer=https://login.example.com/t/v2.0",
     "--set", "connector.auth.jwksUrl=https://login.example.com/t/keys",
     "--set", "connector.auth.audience={api-client-id}",
     "--set", "connector.requiredScope=findings.read"),
], ids=["default", "intake-connector"])
def test_no_pod_mounts_a_kubernetes_api_token(extra):
    """No role calls the Kubernetes API. Workload identity mounts its own
    projected token, which this setting does not affect."""
    specs = pod_specs(render(*extra))
    assert set(specs) >= {"verdict", "collector", "dashboard", "ingest"} | (
        {"intake", "connector"} if extra else set())
    for role, spec in specs.items():
        assert spec.get("automountServiceAccountToken") is False, role


def _ci_lint_values() -> list[str]:
    """The VALUES array of ci.yml's "Lint the Helm chart" step, as argv."""
    doc = yaml.safe_load((REPO / ".github" / "workflows" / "ci.yml").read_text(encoding="utf-8"))
    script = next(s["run"] for job in doc["jobs"].values() for s in job.get("steps", [])
                  if s.get("name") == "Lint the Helm chart")
    body = script[script.index("VALUES=(") + len("VALUES=("):]
    body = body[:body.index("\n)")]
    return shlex.split("\n".join(ln.split("#")[0] for ln in body.splitlines()))


@requires_helm
def test_the_values_ci_lints_with_render():
    """The step runs `helm template` with these values; a chart guard added
    without updating them fails CI on main rather than here."""
    out = subprocess.run([helm, "template", "ci", str(CHART), *_ci_lint_values()],
                         capture_output=True, text=True, timeout=120, cwd=REPO)
    assert out.returncode == 0, out.stderr


# -- org ids are UUIDs, whatever supplies the tokens ----------------------

NOT_A_UUID = "not-a-uuid-SENTINEL"


def _render_external_secret_error(*extra: str) -> str:
    """Tokens from secrets.existingSecret: no secrets.otelTokens at all."""
    out = subprocess.run(
        [helm, "template", "rel", str(CHART), *base_without("secrets.otelTokens"),
         "--set", "secrets.existingSecret=from-vault", *extra],
        capture_output=True, text=True, timeout=120,
    )
    assert out.returncode != 0, "expected the render to be refused, and it was not"
    return out.stderr


@requires_helm
def test_an_empty_org_id_is_refused_under_an_external_secret():
    err = _render_external_secret_error("--set-string", "orgIds.primary=")
    assert "orgIds.primary is not an organization UUID" in err, err


@requires_helm
@pytest.mark.parametrize("collector", ["true", "false"])
def test_an_org_id_that_is_not_a_uuid_is_refused_without_echoing_it(collector):
    err = render_error("--set", f"collector.enabled={collector}",
                       "--set-string", f"orgIds.primary={NOT_A_UUID}")
    assert "orgIds.primary is not an organization UUID" in err, err
    assert "SENTINEL" not in err, err


@requires_helm
@pytest.mark.parametrize("org_id", ["00000000-0000-0000-0000-000000000000",
                                    "00000000-0000-4000-8000-00000000C0de"],
                         ids=["documented-zero", "mixed-case"])
def test_a_uuid_org_id_renders(org_id):
    docs = render("--set-string", f"orgIds.primary={org_id}")
    assert env_of(pod_specs(docs)["collector"])["FORGD_ORG_ID_PRIMARY"]["value"] == org_id


# -- the store roles values.yaml names --------------------------------------


def _service_account_comment(role: str) -> str:
    """The comment lines directly above serviceAccounts.<role> in values.yaml."""
    lines = (CHART / "values.yaml").read_text(encoding="utf-8").splitlines()
    start = lines.index("serviceAccounts:")
    at = lines.index(f"  {role}:", start)
    above: list[str] = []
    for line in reversed(lines[start + 1:at]):
        if not line.lstrip().startswith("#"):
            break
        above.insert(0, line.strip().lstrip("#").strip())
    return " ".join(above)


@pytest.mark.parametrize(("role", "built_in"), [("writer", "Storage Blob Data Contributor"),
                                                ("reader", "Storage Blob Data Reader")])
def test_values_names_the_azure_role_store_azure_assigns(role, built_in):
    """store-azure assigns the built-in role unless control_enabled, and its
    custom role only with it."""
    main = (REPO / "deploy" / "terraform" / "modules" / "store-azure" / "main.tf").read_text()
    assert f'var.control_enabled ? null : "{built_in}"' in main
    comment = _service_account_comment(role)
    assert built_in in comment, comment
    assert "control_enabled" in comment and "custom" in comment, comment


CUSTOM_ROLE = re.compile(r"custom (writer|reader) role")


def test_every_mention_of_a_store_azure_custom_role_names_control_enabled():
    """The custom roles exist only while control_enabled is true."""
    tracked = subprocess.run(["git", "ls-files", "deploy", "docs", "README.md"], cwd=REPO,
                             capture_output=True, text=True, check=True).stdout.split()
    bad = []
    for path in tracked:
        if not path.endswith((".md", ".tf", ".yaml", ".tpl")):
            continue
        text = " ".join((REPO / path).read_text(encoding="utf-8").split())
        for m in CUSTOM_ROLE.finditer(text):
            if "control_enabled" not in text[max(0, m.start() - 200):m.end() + 200]:
                bad.append(f"{path}: …{text[max(0, m.start() - 60):m.end()]}")
    assert not bad, bad


# -- third-party charts in the README ------------------------------------------

_OCI_DIGEST = re.compile(r"oci://[^@\s]+@sha256:[0-9a-f]{64}")


def _readme_helm_installs() -> list[list[str]]:
    """Every `helm upgrade --install` / `helm install` in the README's sh blocks."""
    text = (REPO / "deploy" / "helm" / "README.md").read_text(encoding="utf-8")
    out = []
    for block in re.findall(r"```sh\n(.*?)\n```", text, re.DOTALL):
        for line in block.replace("\\\n", " ").splitlines():
            argv = shlex.split(line, comments=True)
            if argv[:2] == ["helm", "install"] or argv[:3] == ["helm", "upgrade", "--install"]:
                out.append(argv)
    return out


def test_the_readme_installs_every_third_party_chart_by_digest():
    """A chart named by repo and version is whatever the repo serves under
    that version on the day. The README's own chart is a local path; any
    other must be an OCI reference pinned to a sha256 digest."""
    text = (REPO / "deploy" / "helm" / "README.md").read_text(encoding="utf-8")
    assert "helm repo add" not in text
    installs = _readme_helm_installs()
    third_party = {}
    for argv in installs:
        positional = [a for a in argv[3 if argv[1] == "upgrade" else 2:] if not a.startswith("-")]
        release, chart = positional[0], positional[1]
        if chart.startswith("deploy/helm/"):
            continue
        third_party[release] = chart
        assert _OCI_DIGEST.fullmatch(chart), f"{release} is installed from {chart!r}"
        assert "--version" in argv, f"{release}: --version lets helm 3.19 check the digest"
    assert "oauth2-proxy" in third_party, sorted(third_party)
