"""Each secret reaches only the workloads that read it, on every deployment path.

One table, checked against the Helm chart and the three Terraform app
modules rendered with every role on. A secret-backed variable the table
does not list fails until it is given a scope.
"""

from __future__ import annotations

import json

import pytest
import terraform_render
import test_app_aca_admins as aca
import test_app_cloudrun_admins as cloudrun
import test_app_ecs_admins as ecs
from test_app_aca import requires_terraform
from test_helm_chart import env_of, pod_specs, render, requires_helm
from test_helm_env_ownership import EVERYTHING, SINK_POLICY

# Variable name, or prefix ending in "_", -> the only roles it may reach.
ENV_SCOPE = {
    "FORGD_HASH_SALT": {"verdict", "collector", "intake", "ingest"},
    "WEBHOOK_SECRET": {"verdict"},
    "WEBHOOK_SECRET_": {"verdict"},
    "FORGD_SHARED_HEADER": {"verdict"},
    "FORGD_SHARED_HEADER_": {"verdict"},
    "FORGD_OTEL_TOKEN_": {"collector"},
    "FORGD_SINK_TOKEN_": {"collector"},
    "FORGD_METRICS_TOKEN": {"verdict", "collector", "intake"},
    "FORGD_INTAKE_FLEET_TOKEN": {"intake"},
    "FORGD_INTAKE_FLEET_TOKEN_": {"intake"},
    "FORGD_INTAKE_TOKEN_": {"intake"},
    "ANTHROPIC_COMPLIANCE_ACCESS_KEY": {"ingest"},
    "ANTHROPIC_COMPLIANCE_ACCESS_KEY_": {"ingest"},
    "FORGD_MANAGED_AGENTS_KEY_": {"ingest"},
    "FORGD_DASHBOARD_FORM_KEY": {"dashboard"},
    "FORGD_OVERRIDES_SIGNING_KEY": {"dashboard"},
}


def scope(name: str) -> set[str] | None:
    if name in ENV_SCOPE:
        return ENV_SCOPE[name]
    prefixes = [p for p in ENV_SCOPE if p.endswith("_") and name.startswith(p)]
    return ENV_SCOPE[max(prefixes, key=len)] if prefixes else None


def check(found: list[tuple[str, str]]) -> None:
    """`found` is (role, variable) for every secret-backed variable."""
    assert found, "no secret-backed variable found: the walk matched nothing"
    unlisted = sorted({n for _, n in found if scope(n) is None})
    assert not unlisted, f"give these a scope in ENV_SCOPE: {unlisted}"
    spread = sorted((r, n) for r, n in found if r not in scope(n))
    assert not spread, spread


@requires_helm
def test_the_chart():
    found = []
    for role, spec in pod_specs(render(*EVERYTHING, policy=SINK_POLICY)).items():
        for name, entry in env_of(spec).items():
            if (entry.get("valueFrom") or {}).get("secretKeyRef"):
                found.append((role, name))
    assert {r for r, _ in found} >= {"verdict", "collector", "intake", "ingest", "dashboard"}
    check(found)


def _walk(value, path, visit) -> None:
    if isinstance(value, dict):
        visit(value, path)
        for k, v in value.items():
            _walk(v, (*path, k), visit)
    elif isinstance(value, list):
        for i, v in enumerate(value):
            _walk(v, (*path, i), visit)


def _secret_env(rendered: dict) -> list[tuple[str, str]]:
    """(role, variable) for each secret-backed variable in any container:
    ACA's `secret_name`, Cloud Run's `value_source`, ECS's `secrets`. The
    role is the resource name of the address the container sits under."""
    found = []

    def visit(node: dict, path: tuple) -> None:
        role = str(path[0]).split(".")[1] if path else ""
        for entry in node.get("env") or []:
            if isinstance(entry, dict) and (entry.get("secret_name") or entry.get("value_source")):
                found.append((role, entry["name"]))
        defs = node.get("container_definitions")
        if isinstance(defs, str):
            for c in json.loads(defs):
                found.extend((role, s["name"]) for s in c.get("secrets") or [])

    _walk(rendered, (), lambda node, path: visit(node, path))
    return found


MODULES = {
    "app-aca": {**aca.RENDER, **aca.RENDER_ON, "enable_intake": True,
                "intake_tokens": {"dev": "i" * 32}, "metrics_token": "m" * 32},
    "app-ecs": {**ecs.RENDER, **ecs.ON},
    "app-cloudrun": cloudrun.RENDER,
}


@requires_terraform
@pytest.mark.parametrize("name", sorted(MODULES))
def test_the_terraform_app_modules(tmp_path, name):
    found = _secret_env(terraform_render.render_module(tmp_path, name, MODULES[name]))
    roles = {r for r, _ in found}
    assert {"verdict", "collector", "intake", "ingest"} <= roles, sorted(roles)
    check(found)
