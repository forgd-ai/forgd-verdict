"""The intake serves /stats behind the metrics token, so every deployment
layer hands it FORGD_METRICS_TOKEN from the same secret the verdict server
and the collector read. Without it /stats does not exist and a fleet's
refused batches cannot be counted."""

from __future__ import annotations

import json

import pytest
import terraform_render
from test_app_aca import requires_terraform
from test_helm_chart import env_of, helm, pod_specs, render

requires_helm = pytest.mark.skipif(helm is None, reason="helm is not installed")

INTAKE = ("--set", "intake.enabled=true", "--set", "intake.fleet.enabled=true",
          "--set", "secrets.intakeFleetToken=" + "f" * 32)


@requires_helm
@pytest.mark.parametrize("extra", [(), ("--set", "secrets.existingSecret=forgd-from-vault")],
                         ids=["inline", "existing-secret"])
def test_the_chart_gives_the_intake_the_verdict_servers_metrics_token(extra):
    specs = pod_specs(render(*INTAKE, *extra))
    intake = env_of(specs["intake"])["FORGD_METRICS_TOKEN"]["valueFrom"]["secretKeyRef"]
    verdict = env_of(specs["verdict"])["FORGD_METRICS_TOKEN"]["valueFrom"]["secretKeyRef"]
    assert intake == verdict


@requires_helm
def test_the_chart_gives_the_intake_no_metrics_token_when_there_is_none():
    specs = pod_specs(render(*INTAKE, "--set", "secrets.metricsToken="))
    assert "FORGD_METRICS_TOKEN" not in env_of(specs["intake"])
    assert "FORGD_METRICS_TOKEN" not in env_of(specs["verdict"])


@requires_terraform
def test_ecs_gives_the_intake_the_metrics_token_secret(tmp_path):
    from test_app_ecs import ARN, _intake_secrets
    secrets = _intake_secrets(tmp_path, metrics_token_secret_arn=ARN + "metrics-AbCdEf",
                              intake_fleet_token_secret_arn=ARN + "fleet-AbCdEf")
    assert secrets["FORGD_METRICS_TOKEN"] == ARN + "metrics-AbCdEf"


@requires_terraform
def test_cloudrun_gives_the_intake_the_metrics_token_secret(tmp_path):
    from test_app_cloudrun import SECRET, _intake_env
    env = _intake_env(tmp_path, metrics_token_secret_id=SECRET + "metrics",
                      intake_fleet_token_secret_id=SECRET + "fleet")
    [ref] = env["FORGD_METRICS_TOKEN"]["value_source"][0]["secret_key_ref"]
    assert ref["secret"] == SECRET + "metrics"


@requires_terraform
def test_aca_gives_the_intake_the_metrics_token(tmp_path):
    from test_app_aca_admins import RENDER
    from test_app_aca_intake import _intake
    rendered = terraform_render.render_module(tmp_path, "app-aca", {
        **RENDER, "enable_intake": True, "intake_fleet_token": "f" * 32, "metrics_token": "m" * 32})
    _, env, secrets = _intake(rendered)
    assert secrets[env["FORGD_METRICS_TOKEN"]["secret_name"]] == "m" * 32


@requires_terraform
def test_aca_gives_the_intake_no_metrics_token_when_there_is_none(tmp_path):
    from test_app_aca_admins import RENDER
    from test_app_aca_intake import _intake
    rendered = terraform_render.render_module(tmp_path, "app-aca", {
        **RENDER, "enable_intake": True, "intake_fleet_token": "f" * 32, "metrics_token": ""})
    _, env, _ = _intake(rendered)
    assert "FORGD_METRICS_TOKEN" not in env


# -- every role that serves /metrics or /stats holds the metrics token ---------

# /metrics on the verdict server, /stats on the collector and the intake.
# The dashboard and the connector serve neither.
SERVES_STATS = {"verdict", "collector", "intake"}
NO_STATS = {"dashboard", "connector"}


@requires_helm
def test_every_chart_role_that_serves_stats_holds_the_metrics_token():
    from test_helm_chart import CONNECTOR_ALL
    specs = pod_specs(render(*INTAKE, *CONNECTOR_ALL))
    holds = {role for role, spec in specs.items() if "FORGD_METRICS_TOKEN" in env_of(spec)}
    assert holds >= SERVES_STATS, sorted(SERVES_STATS - holds)
    assert not holds & NO_STATS, sorted(holds & NO_STATS)


def test_every_aca_role_that_serves_stats_holds_the_metrics_token():
    from test_helm_chart import aca_env
    env = aca_env()
    assert {r for r in SERVES_STATS if "FORGD_METRICS_TOKEN" not in env[r]} == set()
    assert {r for r in NO_STATS if "FORGD_METRICS_TOKEN" in env[r]} == set()


@requires_terraform
def test_every_ecs_role_that_serves_stats_holds_the_metrics_token(tmp_path):
    from test_app_ecs import ARN, INTAKE, ON, REQUIRED, _task_secrets
    rendered = terraform_render.render_module(tmp_path, "app-ecs", {
        **REQUIRED, **INTAKE, **ON, "metrics_token_secret_arn": ARN + "metrics-AbCdEf",
        "intake_fleet_token_secret_arn": ARN + "fleet-AbCdEf"})
    for role in SERVES_STATS:
        assert _task_secrets(rendered, role)["FORGD_METRICS_TOKEN"] == ARN + "metrics-AbCdEf", role
    [dashboard] = [rendered["aws_ecs_task_definition.dashboard"]] \
        if isinstance(rendered["aws_ecs_task_definition.dashboard"], dict) else rendered["aws_ecs_task_definition.dashboard"]
    names = {s["name"] for c in json.loads(dashboard["container_definitions"]) for s in c.get("secrets", [])}
    assert "FORGD_METRICS_TOKEN" not in names


@requires_terraform
def test_every_cloudrun_role_that_serves_stats_holds_the_metrics_token(tmp_path):
    from test_app_cloudrun import ON, REQUIRED, SECRET, _secret_env
    rendered = terraform_render.render_module(tmp_path, "app-cloudrun", {
        **REQUIRED, **ON, "enable_intake": True, "metrics_token_secret_id": SECRET + "metrics",
        "intake_fleet_token_secret_id": SECRET + "fleet"})
    for role in SERVES_STATS:
        env = _secret_env(rendered, f"google_cloud_run_v2_service.{role}")
        assert env["FORGD_METRICS_TOKEN"] == SECRET + "metrics", role
    service = rendered["google_cloud_run_v2_service.dashboard"]
    [template] = (service[0] if isinstance(service, list) else service)["template"]
    names = {e["name"] for c in template["containers"] for e in c.get("env", [])}
    assert "FORGD_METRICS_TOKEN" not in names
