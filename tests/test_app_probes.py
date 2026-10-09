"""Readiness gating on every platform, over the full rendering.

Every service that takes traffic is held out of it while its readiness path
answers 503 (docs/OVERRIDES.md, "Readiness"). The readiness path is
`/readyz` with runtime overrides on (the deployment's admins flag) and
`/healthz` with them off, where the rendering is the pinned baseline's.
`/livez` is liveness only: it fails when gitleaksd stops answering, never
for a store outage or an unproven lockout.

- app-aca: with admins, an HTTP readiness probe on the readiness path, at
  the ingress port, on every container app with ingress. Without them,
  only the connector's, as before admins.
- app-ecs: the ALB target group checks the readiness path for every
  service. With admins, every service container's health check requests it
  (after `/livez` on the roles that run gitleaksd); without them, the daemon
  roles request `/livez` alone and the others have no check, as before.
- app-cloudrun: a startup probe on the readiness path on every service,
  and with admins a readiness probe on it too.
- Helm: a readiness probe on the readiness path on every Deployment, a
  startup probe, where there is one, on it too, and in GKE mode each
  BackendConfig's health check.

An image from before `/readyz` answers it with a status every one of these
probes counts as a failure (tests/test_overrides_ready.py), so with
overrides on such an image never takes traffic.

Each checker returns its problems, and a mutation test proves it finds a
probe moved to `/livez`, a probe left out, and the readiness path chosen
the wrong way round.
"""

from __future__ import annotations

import re
import shutil
import subprocess
from pathlib import Path

import pytest
import terraform_render
import test_app_aca_admins as aca_admins
import test_app_cloudrun_admins as cloudrun_admins
import test_app_ecs_admins as ecs_admins
import yaml
from test_app_aca import requires_terraform
from test_helm_admins import ADMINS, CONNECTOR, CONTROL_ID, VERIFY_KEYS
from test_helm_chart import CHART, INTAKE, _argv, render, requires_helm

HEALTHZ = "/healthz"
READYZ = "/readyz"
LIVEZ = "/livez"
READY_LOCAL = 'ready_path = var.dashboard_admins_enabled ? "/readyz" : "/healthz"'
# The readiness path chosen the wrong way round: (id, then, render on).
BACKWARDS = [("on-healthz", READY_LOCAL.replace('"/readyz"', '"/healthz"'), True),
             ("off-readyz", READY_LOCAL.replace('"/healthz"', '"/readyz"'), False)]
DAEMON_ROLES = {"verdict", "collector", "intake"}


def _render_mutated(tmp: Path, name: str, variables: dict, now: str, then: str,
                    also: tuple[tuple[str, str], ...] = ()) -> dict:
    """Module `name` with the FIRST `now` in main.tf replaced by `then`, and
    each (now, then) in `also`, which must occur once, replaced."""
    src = tmp / "module"
    src.mkdir(parents=True)
    for f in terraform_render.module(name).glob("*.tf"):
        shutil.copy(f, src / f.name)
    main = (src / "main.tf").read_text(encoding="utf-8")
    assert now in main, now
    main = main.replace(now, then, 1)
    for once, then_once in also:
        assert main.count(once) == 1, once
        main = main.replace(once, then_once)
    (src / "main.tf").write_text(main, encoding="utf-8")
    return terraform_render.render_once(
        tmp / "render", src, variables, **terraform_render.MODULES[name],
        plugins=terraform_render.plugin_dir(terraform_render.module(name)))


def _instances(rendered: dict, address: str) -> dict[str, dict]:
    """`address`'s attributes by instance key: a for_each's keys, a count's
    indexes, or '' for a single instance. A count of 0 has none."""
    value = rendered.get(address)
    if value is None:
        return {}
    if isinstance(value, list):
        return {str(i): v for i, v in enumerate(value)}
    if value and all(isinstance(v, dict) for v in value.values()) and "id" not in value:
        return value
    return {"": value}


def _by_name(rendered: dict, kind: str) -> dict[str, dict]:
    """Each resource of `kind` that exists, by resource name."""
    out = {}
    for address in rendered:
        if address.startswith(kind + "."):
            name = address.split(".", 1)[1]
            for key, attrs in _instances(rendered, address).items():
                out[name if key in ("", "0") else f"{name}[{key}]"] = attrs
    return out


# --- app-ecs ---------------------------------------------------------------------


def ecs_problems(rendered: dict, on: bool = False) -> list[str]:
    ready = READYZ if on else HEALTHZ
    problems = []
    groups = _instances(rendered, "aws_lb_target_group.this")
    if not groups:
        problems.append("no target groups")
    for service, tg in groups.items():
        [check] = tg["health_check"] or [{}]
        if check.get("path") != ready or check.get("matcher") != "200":
            problems.append(f"target group {service}: {check.get('path')} {check.get('matcher')}")
    containers = {c["name"]: c for c in ecs_admins._containers(rendered).values()}
    for service in groups:
        c = containers.get(service)
        if c is None:
            problems.append(f"{service}: no container")
            continue
        port = c["portMappings"][0]["containerPort"]
        command = " ".join((c.get("healthCheck") or {}).get("command", []))
        urls = re.findall(r"http://127\.0\.0\.1:(\d+)(/\w+)", command)
        daemon = [(str(port), LIVEZ)] if service in DAEMON_ROLES else []
        want = daemon + [(str(port), ready)] if on else daemon
        if urls != want:
            problems.append(f"{service}: container health check requests {urls}, want {want}")
    if "healthCheck" in containers.get("ingest", {}):
        problems.append("ingest: has a health check")
    return problems


@requires_terraform
@pytest.mark.parametrize("variables,services", [
    (ecs_admins.RENDER, {"verdict", "collector", "dashboard", "intake", "connector"}),
    (ecs_admins.NO_INTAKE, {"verdict", "collector", "dashboard", "connector"}),
], ids=["intake", "no-intake"])
@pytest.mark.parametrize("on", [False, True], ids=["off", "on"])
def test_ecs_gates_every_service_on_its_readiness_path(tmp_path, variables, services, on):
    rendered = terraform_render.render_module(tmp_path, "app-ecs",
                                              {**variables, **(ecs_admins.ON if on else {})})
    assert set(_instances(rendered, "aws_lb_target_group.this")) == services
    assert ecs_problems(rendered, on) == []


@requires_terraform
@pytest.mark.parametrize("now,then,on", [
    ('["/livez", local.ready_path] : [local.ready_path]', '["/livez"] : ["/livez"]', True),
    ('    healthCheck = local.container_check["dashboard"]\n', "", True),
    ('    path                = local.ready_path', '    path                = "/livez"', False),
    ('var.dashboard_admins_enabled ? local.container_check["verdict"] : local.livez_check["verdict"]',
     'local.container_check["verdict"]', False),
], ids=["container-livez", "dashboard-check-omitted", "target-group-livez", "check-unconditional"])
def test_ecs_checker_catches_a_livez_path_or_an_omitted_check(tmp_path, now, then, on):
    variables = {**ecs_admins.RENDER, **(ecs_admins.ON if on else {})}
    rendered = _render_mutated(tmp_path, "app-ecs", variables, now, then)
    assert ecs_problems(rendered, on)


@requires_terraform
@pytest.mark.parametrize("then,on", [(t, o) for _, t, o in BACKWARDS],
                         ids=[i for i, _, _ in BACKWARDS])
def test_ecs_checker_catches_the_readiness_path_the_wrong_way_round(tmp_path, then, on):
    variables = {**ecs_admins.RENDER, **(ecs_admins.ON if on else {})}
    rendered = _render_mutated(tmp_path, "app-ecs", variables, READY_LOCAL, then)
    assert ecs_problems(rendered, on)


# --- app-aca ---------------------------------------------------------------------


def aca_problems(rendered: dict, on: bool = False) -> list[str]:
    ready = READYZ if on else HEALTHZ
    problems = []
    apps = _by_name(rendered, "azurerm_container_app")
    for name, app in apps.items():
        if not app.get("ingress"):
            continue
        port = app["ingress"][0]["target_port"]
        [container] = app["template"][0]["container"]
        probes = container.get("readiness_probe") or []
        want = [("HTTP", ready, port)] if on or name == "connector" else []
        if [(p.get("transport"), p.get("path"), p.get("port")) for p in probes] != want:
            problems.append(f"{name}: readiness {probes}")
        for probe in container.get("liveness_probe") or []:
            if probe.get("path") != LIVEZ:
                problems.append(f"{name}: liveness on {probe.get('path')}")
    if not apps:
        problems.append("no container apps")
    return problems


@requires_terraform
@pytest.mark.parametrize("on", [False, True], ids=["off", "on"])
def test_aca_gates_every_container_app_with_ingress_on_its_readiness_path(tmp_path, on):
    variables = {**aca_admins.RENDER, **(aca_admins.RENDER_ON if on else {})}
    rendered = terraform_render.render_module(tmp_path, "app-aca", variables)
    served = {n for n, v in _by_name(rendered, "azurerm_container_app").items() if v.get("ingress")}
    assert served == {"verdict", "collector", "dashboard", "connector"}
    assert aca_problems(rendered, on) == []


_ACA_READY_DASHBOARD = '          port      = 8080\n          path      = local.ready_path'
_ACA_READY_VERDICT = ('      dynamic "readiness_probe" {\n'
                      '        for_each = toset(var.dashboard_admins_enabled ? ["admins"] : [])\n'
                      '        content {\n          transport = "HTTP"\n          port      = 8000\n'
                      '          path      = local.ready_path\n        }\n      }\n')


@requires_terraform
@pytest.mark.parametrize("now,then,on", [
    (_ACA_READY_DASHBOARD, _ACA_READY_DASHBOARD.replace("local.ready_path", f'"{LIVEZ}"'), True),
    (_ACA_READY_VERDICT, "", True),
    (_ACA_READY_VERDICT, _ACA_READY_VERDICT.replace('var.dashboard_admins_enabled ? ["admins"] : []',
                                                    '["admins"]'), False),
], ids=["dashboard-livez", "verdict-omitted", "verdict-unconditional"])
def test_aca_checker_catches_a_livez_path_or_an_omitted_probe(tmp_path, now, then, on):
    variables = {**aca_admins.RENDER, **(aca_admins.RENDER_ON if on else {})}
    rendered = _render_mutated(tmp_path, "app-aca", variables, now, then)
    assert aca_problems(rendered, on)


@requires_terraform
@pytest.mark.parametrize("then,on", [(t, o) for _, t, o in BACKWARDS],
                         ids=[i for i, _, _ in BACKWARDS])
def test_aca_checker_catches_the_readiness_path_the_wrong_way_round(tmp_path, then, on):
    variables = {**aca_admins.RENDER, **(aca_admins.RENDER_ON if on else {})}
    rendered = _render_mutated(tmp_path, "app-aca", variables, READY_LOCAL, then)
    assert aca_problems(rendered, on)


# --- app-cloudrun ----------------------------------------------------------------


def cloudrun_problems(rendered: dict, on: bool = False) -> list[str]:
    ready = READYZ if on else HEALTHZ
    problems = []
    services = _by_name(rendered, "google_cloud_run_v2_service")
    for name, svc in services.items():
        [container] = svc["template"][0]["containers"]
        for kind in ("startup_probe", "readiness_probe"):
            paths = [g.get("path") for p in container.get(kind) or [] for g in p.get("http_get") or []]
            if paths != ([ready] if on or kind == "startup_probe" else []):
                problems.append(f"{name}: {kind} on {paths}")
        for probe in container.get("liveness_probe") or []:
            paths = [g.get("path") for g in probe.get("http_get") or []]
            if paths != [LIVEZ]:
                problems.append(f"{name}: liveness on {paths}")
    if not services:
        problems.append("no services")
    return problems


@requires_terraform
@pytest.mark.parametrize("variables,services", [
    (cloudrun_admins.RENDER, {"verdict", "collector", "dashboard", "intake", "connector"}),
    (cloudrun_admins.NO_INTAKE, {"verdict", "collector", "dashboard", "connector"}),
], ids=["intake", "no-intake"])
def test_cloudrun_gates_every_service_on_healthz(tmp_path, variables, services):
    rendered = terraform_render.render_module(tmp_path, "app-cloudrun", variables)
    found = set(_by_name(rendered, "google_cloud_run_v2_service"))
    assert found == services
    assert cloudrun_problems(rendered) == []


# The module refuses admins at plan (its dashboard signs in through IAP);
# rendering them on means lifting that one refusal.
_CLOUDRUN_IAP_REFUSAL = ("      condition     = !var.dashboard_admins_enabled\n",
                         "      condition     = var.dashboard_admins_enabled == var.dashboard_admins_enabled\n")


def _cloudrun_on(tmp_path, edits=()):
    return terraform_render.render_edited(
        tmp_path, "app-cloudrun", {**cloudrun_admins.RENDER, **cloudrun_admins.ON},
        [_CLOUDRUN_IAP_REFUSAL, *edits])


@requires_terraform
def test_cloudrun_on_gates_every_service_on_readyz(tmp_path):
    rendered = _cloudrun_on(tmp_path)
    assert set(_by_name(rendered, "google_cloud_run_v2_service")) == {
        "verdict", "collector", "dashboard", "intake", "connector"}
    assert cloudrun_problems(rendered, on=True) == []


@requires_terraform
@pytest.mark.parametrize("then,on", [(t, o) for _, t, o in BACKWARDS],
                         ids=[i for i, _, _ in BACKWARDS])
def test_cloudrun_checker_catches_the_readiness_path_the_wrong_way_round(tmp_path, then, on):
    if on:
        rendered = _cloudrun_on(tmp_path, [(READY_LOCAL, then)])
    else:
        rendered = _render_mutated(tmp_path, "app-cloudrun", cloudrun_admins.RENDER,
                                   READY_LOCAL, then)
    assert cloudrun_problems(rendered, on)


_CLOUDRUN_READY = ('      dynamic "readiness_probe" {\n'
                   '        for_each = toset(var.dashboard_admins_enabled ? ["admins"] : [])\n'
                   '        content {\n          http_get {\n            path = local.ready_path\n'
                   '          }\n')
_CLOUDRUN_READY_ALL = (_CLOUDRUN_READY + "          period_seconds    = 10\n          timeout_seconds   = 4\n"
                       "          failure_threshold = 3\n        }\n      }\n")


@requires_terraform
@pytest.mark.parametrize("now,then,on", [
    (_CLOUDRUN_READY, _CLOUDRUN_READY.replace("local.ready_path", f'"{LIVEZ}"'), True),
    (_CLOUDRUN_READY_ALL, "", True),
    (_CLOUDRUN_READY, _CLOUDRUN_READY.replace('var.dashboard_admins_enabled ? ["admins"] : []',
                                              '["admins"]'), False),
], ids=["readiness-livez", "readiness-omitted", "readiness-unconditional"])
def test_cloudrun_checker_catches_a_livez_path_or_an_omitted_probe(tmp_path, now, then, on):
    variables = {**cloudrun_admins.RENDER, **(cloudrun_admins.ON if on else {})}
    rendered = _render_mutated(tmp_path, "app-cloudrun", variables, now, then,
                               (_CLOUDRUN_IAP_REFUSAL,) if on else ())
    assert cloudrun_problems(rendered, on)


# --- Helm ------------------------------------------------------------------------


def helm_problems(docs: list[dict], ready: str = HEALTHZ) -> list[str]:
    problems = []
    deployments = [d for d in docs if d.get("kind") == "Deployment"]
    for d in deployments:
        name = d["metadata"]["labels"]["app.kubernetes.io/component"]
        [container] = d["spec"]["template"]["spec"]["containers"]
        path = (container.get("readinessProbe") or {}).get("httpGet", {}).get("path")
        if path != ready:
            problems.append(f"{name}: readinessProbe on {path}")
        if "startupProbe" in container and container["startupProbe"]["httpGet"]["path"] != ready:
            problems.append(f"{name}: startupProbe on {container['startupProbe']['httpGet']['path']}")
        if "livenessProbe" in container and container["livenessProbe"]["httpGet"]["path"] != LIVEZ:
            problems.append(f"{name}: livenessProbe on {container['livenessProbe']['httpGet']['path']}")
    for config in (d for d in docs if d.get("kind") == "BackendConfig"):
        path = config["spec"]["healthCheck"]["requestPath"]
        if path != ready:
            problems.append(f"{config['metadata']['name']}: health check on {path}")
    if not deployments:
        problems.append("no deployments")
    return problems


@requires_helm
@pytest.mark.parametrize("on", [False, True], ids=["off", "on"])
def test_helm_gates_every_deployment_on_its_readiness_path(on):
    docs = render(*CONNECTOR, *INTAKE, *(ADMINS if on else ()))
    components = {d["metadata"]["labels"]["app.kubernetes.io/component"]
                  for d in docs if d.get("kind") == "Deployment"}
    assert components == {"verdict", "collector", "dashboard", "intake", "connector"}
    assert helm_problems(docs, READYZ if on else HEALTHZ) == []


def _render_chart(tmp_path, edits, argv):
    """helm template of a copy of the chart, each (template, now, then)
    replaced once."""
    chart = tmp_path / "chart"
    shutil.copytree(CHART, chart)
    for template, now, then in edits:
        path = chart / "templates" / template
        text = path.read_text(encoding="utf-8")
        assert text.count(now) == 1, now
        path.write_text(text.replace(now, then), encoding="utf-8")
    argv = [str(chart) if a == str(CHART) else a for a in argv]
    out = subprocess.run(argv, capture_output=True, text=True, timeout=120)
    assert out.returncode == 0, out.stderr
    return [d for d in yaml.safe_load_all(out.stdout) if d]


ADMINS_ON_GKE = ("--set", "dashboard.admins.enabled=true",
                 "--set", f"serviceAccounts.control.clientId={CONTROL_ID}",
                 "--set", "secrets.dashboardFormKey=a-form-key",
                 "--set", "dashboard.admins.writerIdentities={serviceAccount:forgd-verdict-writer@example-project.iam.gserviceaccount.com}",
                 "--set", f"dashboard.admins.verifyKeys={{{VERIFY_KEYS[0]}}}")
# GKE mode needs the dashboard behind IAP, and admins refuse IAP, so GKE
# with admins on renders only with that refusal lifted.
_GKE_ADMINS_REFUSAL = ("dashboard.yaml", '{{- if eq $platform "iap" }}\n{{- fail "dashboard.admins.enabled',
                       '{{- if false }}\n{{- fail "dashboard.admins.enabled')


@requires_helm
@pytest.mark.parametrize("on", [False, True], ids=["off", "on"])
def test_helm_gke_health_checks_request_the_readiness_path(tmp_path, on):
    from test_helm_gke import ALL_ON, _gke_argv

    extra = (*ALL_ON, *(ADMINS_ON_GKE if on else ()))
    argv = ["helm", "template", "rel", str(CHART), *_gke_argv(extra)]
    docs = _render_chart(tmp_path, [_GKE_ADMINS_REFUSAL] if on else [], argv)
    assert [d for d in docs if d.get("kind") == "BackendConfig"]
    assert helm_problems(docs, READYZ if on else HEALTHZ) == []


_HELM_READY = ("_helpers.tpl", "/readyz{{- else -}}/healthz")


@requires_helm
@pytest.mark.parametrize("then,on", [("/healthz{{- else -}}/healthz", True),
                                     ("/readyz{{- else -}}/readyz", False)],
                         ids=["on-healthz", "off-readyz"])
def test_helm_checker_catches_the_readiness_path_the_wrong_way_round(tmp_path, then, on):
    argv = _argv((*CONNECTOR, *INTAKE, *(ADMINS if on else ())), None)
    docs = _render_chart(tmp_path, [(*_HELM_READY, then)], argv)
    assert helm_problems(docs, READYZ if on else HEALTHZ)


_READY_PROBE = 'readinessProbe:\n            httpGet: { path: {{ include "forgd-verdict.readyPath" . }}, port: http }'


@requires_helm
@pytest.mark.parametrize("template,now,then", [
    ("dashboard.yaml", _READY_PROBE, "readinessProbe:\n            httpGet: { path: /livez, port: http }"),
    ("connector.yaml", f"          {_READY_PROBE}\n            periodSeconds: 10\n", ""),
], ids=["dashboard-livez", "connector-omitted"])
def test_helm_checker_catches_a_livez_path_or_an_omitted_probe(tmp_path, template, now, then):
    docs = _render_chart(tmp_path, [(template, now, then)], _argv((*CONNECTOR, *INTAKE), None))
    assert helm_problems(docs)
