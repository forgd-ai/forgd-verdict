"""A fleet OTel exporter token: one bearer valid for a set of orgs, for an
`otel.orgs[]` entry with `ids:` instead of `id:`. The deployment layers wire
it as FORGD_OTEL_TOKEN_<FLEET>, named from a non-secret map of the fleet's
org names, and refuse a fleet whose orgs are not all configured org ids:
the collector can only bound a fleet token to orgs it has ids for."""

from __future__ import annotations

import json

import pytest
import terraform_render
from test_app_aca import requires_terraform
from test_helm_chart import env_of, helm, pod_specs, render, render_error

requires_helm = pytest.mark.skipif(helm is None, reason="helm is not installed")

PROD = "00000000-0000-0000-0000-00000000000a"
DEV = "00000000-0000-0000-0000-00000000000b"
TOKEN = "t" * 32


# -- Helm ---------------------------------------------------------------------

HELM_ORGS = ("--set", f"orgIds.prod={PROD}", "--set", f"orgIds.dev={DEV}")


def _helm_fleet(*members: str) -> tuple[str, ...]:
    return ("--set", f"otelFleets.laptops={{{','.join(members)}}}")


@requires_helm
def test_a_helm_fleet_token_renders_one_variable_for_its_orgs():
    docs = render(*HELM_ORGS, *_helm_fleet("prod", "dev"),
                  "--set", f"secrets.otelTokens.laptops={TOKEN}")
    env = env_of(pod_specs(docs)["collector"])
    ref = env["FORGD_OTEL_TOKEN_LAPTOPS"]["valueFrom"]["secretKeyRef"]
    assert ref["key"] == "otel-token-laptops" and ref["optional"] is True
    assert {"FORGD_ORG_ID_PROD", "FORGD_ORG_ID_DEV"} <= set(env)
    [secret] = [d for d in docs if d["kind"] == "Secret"]
    assert secret["stringData"]["otel-token-laptops"] == TOKEN


@requires_helm
def test_a_helm_fleet_on_an_existing_secret_needs_no_token_value():
    docs = render(*HELM_ORGS, *_helm_fleet("prod", "dev"),
                  "--set", "secrets.existingSecret=forgd-from-vault")
    env = env_of(pod_specs(docs)["collector"])
    assert env["FORGD_OTEL_TOKEN_LAPTOPS"]["valueFrom"]["secretKeyRef"]["name"] == "forgd-from-vault"


@requires_helm
@pytest.mark.parametrize(("extra", "message"), [
    (_helm_fleet("prod", "eu"), "otelFleets.laptops names eu, which has no entry in orgIds"),
    (_helm_fleet("prod", PROD), "otelFleets.laptops lists an org id"),
    (("--set", "otelFleets.prod={dev}"), "otelFleets.prod has the name of an orgIds entry"),
    (("--set", "otelFleets.laptops=null", "--set", "otelFleets.laptops={}"), "otelFleets.laptops names no org"),
], ids=["unknown-org", "uuid-literal", "named-like-an-org", "empty"])
def test_a_helm_fleet_not_bound_to_configured_orgs_is_refused(extra, message):
    assert message in render_error(*HELM_ORGS, *extra)


@requires_helm
def test_a_helm_token_for_neither_an_org_nor_a_fleet_is_still_refused():
    err = render_error(*HELM_ORGS, "--set", f"secrets.otelTokens.laptops={TOKEN}")
    assert "secrets.otelTokens.laptops has no matching entry in orgIds or otelFleets" in err


# -- the Terraform modules ----------------------------------------------------

def _aca(tmp_path, **variables):
    from test_app_aca_admins import RENDER
    rendered = terraform_render.render_module(tmp_path, "app-aca", {**RENDER, **variables})
    [template] = rendered["azurerm_container_app.collector"]["template"]
    [container] = template["container"]
    return {e["name"] for e in container["env"]}


def _cloudrun(tmp_path, **variables):
    from test_app_cloudrun import REQUIRED
    rendered = terraform_render.render_module(tmp_path, "app-cloudrun", {**REQUIRED, **variables})
    [template] = rendered["google_cloud_run_v2_service.collector"]["template"]
    [container] = template["containers"]
    return {e["name"] for e in container["env"]}


def _ecs(tmp_path, **variables):
    from test_app_ecs import REQUIRED
    rendered = terraform_render.render_module(tmp_path, "app-ecs", {**REQUIRED, **variables})
    [container] = json.loads(rendered["aws_ecs_task_definition.collector"]["container_definitions"])
    return {s["name"] for s in container["secrets"]} | {e["name"] for e in container["environment"]}


MODULES = {
    "app-aca": (_aca, "otel_tokens", lambda name: TOKEN),
    "app-cloudrun": (_cloudrun, "otel_token_secret_ids", lambda name: f"projects/p/secrets/otel-{name}"),
    "app-ecs": (_ecs, "otel_token_secret_arns",
                lambda name: f"arn:aws:secretsmanager:us-east-1:123456789012:secret:otel-{name}-AbCdEf"),
}


def _module(module, tmp_path, tokens, fleets, org_ids=None):
    render_, var, value = MODULES[module]
    return render_(tmp_path, org_ids=org_ids if org_ids is not None else {"prod": PROD, "dev": DEV},
                   **{var: {n: value(n) for n in tokens}}, otel_fleets=fleets)


@requires_terraform
@pytest.mark.parametrize("module", MODULES)
def test_a_module_fleet_token_renders_one_variable_for_its_orgs(tmp_path, module):
    names = _module(module, tmp_path, ["prod", "laptops"], {"laptops": ["prod", "dev"]})
    assert {"FORGD_OTEL_TOKEN_LAPTOPS", "FORGD_OTEL_TOKEN_PROD",
            "FORGD_ORG_ID_PROD", "FORGD_ORG_ID_DEV"} <= names


@requires_terraform
@pytest.mark.parametrize("module", MODULES)
@pytest.mark.parametrize(("tokens", "fleets", "message"), [
    (["laptops"], {"laptops": ["prod", "eu"]}, "otel_fleets.laptops names eu, which has no non-empty org_ids entry"),
    (["laptops"], {"laptops": [PROD]}, "otel_fleets.laptops lists an org id"),
    (["prod"], {"laptops": ["prod"]}, "otel_fleets.laptops has no token in"),
    (["prod"], {"prod": ["dev"]}, "otel_fleets.prod has the name of an org_ids entry"),
    (["laptops"], {"laptops": []}, "otel_fleets.laptops names no org"),
], ids=["unknown-org", "uuid-literal", "no-token", "named-like-an-org", "empty"])
def test_a_module_fleet_not_bound_to_configured_orgs_is_refused(tmp_path, module, tokens, fleets, message):
    with pytest.raises(AssertionError, match=message):
        _module(module, tmp_path, tokens, fleets)


@requires_terraform
@pytest.mark.parametrize("module", MODULES)
def test_a_module_token_for_neither_an_org_nor_a_fleet_is_still_refused(tmp_path, module):
    with pytest.raises(AssertionError, match=r"\.laptops has no non-empty org_ids entry"):
        _module(module, tmp_path, ["laptops"], {})
