"""The findings connector in the app-aca module.

Off by default, and then nothing in the plan changes. On, it runs the same
image on the READER identity, public with no auth provider, with no salt and
no secret, and every refusal the chart makes at render time is a
precondition here.

The refusals are evaluated by terraform itself: each precondition is copied
verbatim onto a `terraform_data` resource, which needs no provider, so
nothing here calls Azure.
"""

from __future__ import annotations

import json
import re
import shutil
import subprocess
from pathlib import Path

import pytest
from test_app_ecs import _attr, _blocks, _close, _walk

from forgd_verdict.policy import ENV_OVERRIDES

ROOT = Path(__file__).resolve().parent.parent
MODULE = ROOT / "deploy" / "terraform" / "modules" / "app-aca"
MAIN = MODULE / "main.tf"

terraform = shutil.which("terraform")
requires_terraform = pytest.mark.skipif(terraform is None, reason="terraform is not installed")

DOMAIN = "happy-rock-1234.uksouth.azurecontainerapps.io"
DERIVED = f"https://ca-forgd-connector.{DOMAIN}/mcp"
CUSTOM = "mcp.example.com"
CONNECTOR_LOCALS = {"connector_default_host", "connector_host", "connector_resource"}

REQUIRED = {
    "resource_group_name": "rg", "location": "uksouth", "environment_name": "cae",
    "registry_server": "example.azurecr.io", "image": "example.azurecr.io/fv:1",
    "ingest_image": "example.azurecr.io/fv:1-ingest",
    "identity_id": "/subscriptions/0/rg/writer", "identity_client_id": "writer-client",
    "identity_principal_id": "writer-principal",
    "reader_identity_id": "/subscriptions/0/rg/reader", "reader_identity_client_id": "reader-client",
    "reader_identity_principal_id": "reader-principal",
    "registry_id": "/subscriptions/0/rg/acr", "store_url": "azblob://acct/findings",
    "hash_salt": "0123456789abcdef0123", "policy_yaml": "version: 1\n",
}

ON = {
    "connector_enabled": True,
    "connector_issuer": "https://login.example.com/tenant/v2.0",
    "connector_jwks_url": "https://login.example.com/tenant/discovery/v2.0/keys",
    "connector_audience": ["api-client-id"],
    "connector_required_scope": "findings.read",
}

# Every value a secret reaches the other roles through.
SECRET_VARS = ("hash_salt", "webhook_secret", "compliance_api_key", "otel_tokens",
               "metrics_token", "dashboard_auth_client_secret")


def _text() -> str:
    return MAIN.read_text(encoding="utf-8")


def _top() -> list[tuple[str, list[str], str]]:
    return _blocks(_text())


def _connector() -> str:
    [body] = [inner for k, labels, inner in _top()
              if k == "resource" and labels == ["azurerm_container_app", "connector"]]
    return body


def _container() -> str:
    [template] = _walk(_connector(), "template")
    [container] = _walk(template, "container")
    return container


def _connector_locals() -> dict[str, str]:
    out = {}
    for k, _, body in _top():
        if k == "locals":
            for m in re.finditer(r"^  (connector_\w+)\s*=\s*(.+)$", body, re.M):
                out[m.group(1)] = m.group(2).strip()
    assert set(out) == CONNECTOR_LOCALS, sorted(out)
    return out


def _preconditions() -> list[tuple[str, str]]:
    [lifecycle] = _walk(_connector(), "lifecycle")
    out = [(_attr(b, "condition"), _attr(b, "error_message")) for b in _walk(lifecycle, "precondition")]
    assert len(out) == 11, out
    return out


def _env() -> dict[str, str]:
    """name -> the value expression, static or behind a dynamic block's for_each."""
    container = _container()
    out = {}
    for k, labels, inner in _blocks(container):
        if k == "env":
            out[_attr(inner, "name").strip('"')] = _attr(inner, "value")
        elif k == "dynamic" and labels == ["env"]:
            [content] = _walk(inner, "content")
            name = _attr(content, "name")
            out[name.strip('"') if name.startswith('"') else "*base_env"] = _attr(inner, "for_each")
    return out


def _variable(name: str) -> str:
    text = (MODULE / "variables.tf").read_text(encoding="utf-8")
    return {labels[0]: inner for k, labels, inner in _blocks(text) if k == "variable"}[name]


# --- off ----------------------------------------------------------------------

def test_the_connector_is_off_by_default_and_every_setting_has_a_default():
    assert _attr(_variable("connector_enabled"), "default") == "false"
    assert _attr(_variable("connector_source_ranges"), "default") == "[]"
    text = (MODULE / "variables.tf").read_text(encoding="utf-8")
    names = [labels[0] for k, labels, _ in _blocks(text) if k == "variable"]
    connector = [n for n in names if n.startswith("connector_")]
    assert len(connector) == 13, connector
    for name in connector:
        assert _attr(_variable(name), "default") is not None, name


def test_nothing_outside_the_connector_depends_on_it():
    """With the connector off, the module's plan is that of the module with
    the connector left out: the only blocks that mention it are its own,
    each produces nothing when off (checked below), and no other block
    reads a connector variable, local or resource."""
    ref = re.compile(r"var\.connector_|local\.connector_|azurerm_container_app\.connector\b")
    own = []
    for k, labels, inner in _top():
        if k == "locals":
            for name, expr in _assignments(inner).items():
                if not name.startswith("connector_"):
                    assert not ref.search(expr), name
            continue
        if ref.search(inner):
            own.append((k, labels))
    assert own == [("resource", ["azurerm_container_app", "connector"])], own
    assert _attr(_connector(), "count") == "var.connector_enabled ? 1 : 0"

    outputs = {labels[0]: inner for k, labels, inner in
               _blocks((MODULE / "outputs.tf").read_text(encoding="utf-8")) if k == "output"}
    uses = sorted(n for n, body in outputs.items() if ref.search(body))
    assert uses == ["connector_app_name", "connector_url"], uses
    assert _attr(outputs["connector_app_name"], "value") == (
        "var.connector_enabled ? azurerm_container_app.connector[0].name : null")
    # A null output is not stored, so it adds nothing to a plan.
    assert _attr(outputs["connector_url"], "value") == "var.connector_enabled ? local.connector_resource : null"


def test_the_reader_already_pulls_images_so_no_grant_is_added():
    grants = [labels[1] for k, labels, _ in _top()
              if k == "resource" and labels[0] == "azurerm_role_assignment"]
    assert grants == ["writer_pulls_images", "reader_pulls_images"], grants
    assert "azurerm_role_assignment.reader_pulls_images" in _connector()


_HEADER = re.compile(r'^(\w+)((?:\s+"[^"]*")*)\s*\{', re.M)
_REF = re.compile(r"\b(?:azurerm|azapi)_\w+\.\w+(?:\[\d+\])?(?:\.\w+(?:\[\d+\])?)*")


def _without(text: str, drop) -> str:
    """`text` with every top-level block for which drop(kind, labels, inner) holds removed."""
    out, i = [], 0
    for m in _HEADER.finditer(text):
        if m.start() < i:
            continue
        end = _close(text, m.end() - 1, "{", "}")
        kind, labels = m.group(1), re.findall(r'"([^"]*)"', m.group(2))
        if drop(kind, labels, text[m.end():end - 1]):
            out.append(text[i:m.start()])
            i = end
    return "".join(out) + text[i:]


def _left_out() -> dict[str, str]:
    """The module's three files with the connector's blocks and settings removed."""
    def locals_only_connector(k, _, inner):
        return k == "locals" and set(re.findall(r"^  (\w+)\s*=", inner, re.M)) <= CONNECTOR_LOCALS
    return {
        "main.tf": _without(_text(), lambda k, labels, inner: locals_only_connector(k, labels, inner)
                            or (k == "resource" and labels == ["azurerm_container_app", "connector"])),
        "variables.tf": _without((MODULE / "variables.tf").read_text(encoding="utf-8"),
                                 lambda k, labels, _: k == "variable" and labels[0].startswith("connector_")),
        "outputs.tf": _without((MODULE / "outputs.tf").read_text(encoding="utf-8"),
                               lambda k, labels, _: k == "output" and labels in (["connector_url"],
                                                                                 ["connector_app_name"])),
    }


def _assignments(body: str) -> dict[str, str]:
    """name -> expression for every `name = ...` at two spaces, multi-line included."""
    starts = list(re.finditer(r"^  (\w+)\s*=\s*", body, re.M))
    return {m.group(1): body[m.end():starts[j + 1].start() if j + 1 < len(starts) else len(body)].strip()
            for j, m in enumerate(starts)}


def _evaluate(root: Path, files: dict[str, str], required: dict | None = None,
              ref: re.Pattern = _REF, **variables) -> dict:
    """Every resource the files would create with its instance keys, every
    local, and every output that is not null, evaluated by terraform with no
    provider. A resource or data attribute an expression reads, whatever
    `ref` matches, becomes the string "ref", and a bare resource its
    instances, each an object whose attributes are "ref"."""
    root.mkdir(parents=True)
    (root / "variables.tf").write_text(files["variables.tf"], encoding="utf-8")
    locals_, resources, outputs, bare = {}, {}, {}, {}
    for k, labels, inner in _blocks(files["main.tf"]):
        if k == "locals":
            locals_ |= _assignments(inner)
        elif k == "resource":
            count, for_each = _attr(inner, "count"), _attr(inner, "for_each")
            resources[".".join(labels)] = (
                f"[for i in range({count}) : tostring(i)]" if count
                else f"sort([for k, v in ({for_each}) : k])" if for_each else '["-"]')
            obj = "{ " + ", ".join(f'{a} = "ref"' for a in ("id", "arn", "name", "family", "email", "member")) + " }"
            bare[".".join(labels)] = (f"[for i in range({count}) : {obj}]" if count
                                      else f"{{ for k, v in ({for_each}) : k => {obj} }}" if for_each else obj)
    for k, labels, inner in _blocks(files["outputs.tf"]):
        if k == "output":
            outputs[labels[0]] = _assignments(inner)["value"]
    def sub(expr: str) -> str:
        def one(m: re.Match) -> str:
            text = m.group(0)
            if text in bare:
                return "(" + sub(bare[text]) + ")"
            return '"ref"'
        return ref.sub(one, expr)
    main = "locals {\n" + "".join(f"  {n} = {sub(e)}\n" for n, e in locals_.items()) + "}\n"
    main += 'output "resources" {\n  value = {\n' + "".join(
        f'    "{a}" = {sub(c)}\n' for a, c in resources.items()) + "  }\n}\n"
    main += ('output "locals" {\n  sensitive = true\n  value = {\n'
             + "".join(f"    {n} = local.{n}\n" for n in locals_) + "  }\n}\n")
    main += "".join(f'output "o_{n}" {{\n  sensitive = true\n  value = {sub(e)}\n}}\n'
                    for n, e in outputs.items())
    (root / "main.tf").write_text(main, encoding="utf-8")
    (root / "terraform.tfvars.json").write_text(json.dumps({**(REQUIRED if required is None else required), **variables}),
                                                   encoding="utf-8")
    for cmd in (["init", "-input=false", "-no-color"],
                ["apply", "-auto-approve", "-input=false", "-no-color"]):
        out = subprocess.run([terraform, f"-chdir={root}", *cmd], capture_output=True, text=True, timeout=120)
        assert out.returncode == 0, out.stderr
    out = subprocess.run([terraform, f"-chdir={root}", "output", "-json"],
                         capture_output=True, text=True, timeout=60, check=True)
    return {n: v["value"] for n, v in json.loads(out.stdout).items()}


def test_leaving_the_connector_out_removes_every_mention_of_it():
    """Outside comments and heredoc descriptions."""
    for name, text in _left_out().items():
        text = re.sub(r"<<-D\n.*?^\s*D$", "<<-D", text, flags=re.S | re.M)
        code = "\n".join(line for line in text.splitlines() if not line.lstrip().startswith("#"))
        assert "connector" not in code, name


@requires_terraform
def test_off_evaluates_exactly_as_the_module_with_the_connector_left_out(tmp_path):
    files = {n: (MODULE / n).read_text(encoding="utf-8") for n in ("main.tf", "variables.tf", "outputs.tf")}
    got = _evaluate(tmp_path / "off", files, org_ids={"prod": "00000000-0000-0000-0000-00000000000b"})
    before = _evaluate(tmp_path / "left-out", _left_out(), org_ids={"prod": "00000000-0000-0000-0000-00000000000b"})
    connector_locals = CONNECTOR_LOCALS
    assert {k: v for k, v in got["locals"].items() if k not in connector_locals} == before["locals"]
    assert {k: v for k, v in got["resources"].items() if k != "azurerm_container_app.connector"} \
        == before["resources"]
    assert got["resources"]["azurerm_container_app.connector"] == []
    assert {k: v for k, v in got.items() if k not in ("locals", "resources")} == \
        {k: v for k, v in before.items() if k not in ("locals", "resources")}
    assert "o_connector_url" not in got and "o_connector_app_name" not in got


@requires_terraform
def test_on_adds_the_connector_and_its_url_and_nothing_else(tmp_path):
    files = {n: (MODULE / n).read_text(encoding="utf-8") for n in ("main.tf", "variables.tf", "outputs.tf")}
    got = _evaluate(tmp_path / "on", files, **ON)
    before = _evaluate(tmp_path / "left-out", _left_out())
    assert got["resources"] == {**before["resources"], "azurerm_container_app.connector": ["0"]}
    assert {k: v for k, v in got.items() if k not in ("locals", "resources")} == {
        **{k: v for k, v in before.items() if k not in ("locals", "resources")},
        "o_connector_url": "https://ca-forgd-connector.ref/mcp", "o_connector_app_name": "ref"}


# --- on -------------------------------------------------------------------------

def test_it_runs_on_the_reader_identity_only():
    body = _connector()
    [identity] = _walk(body, "identity")
    assert _attr(identity, "identity_ids") == "[var.reader_identity_id]"
    [registry] = _walk(body, "registry")
    assert _attr(registry, "identity") == "var.reader_identity_id"
    env = _env()
    assert env["AZURE_CLIENT_ID"] == "var.reader_identity_client_id"
    # base_env carries the writer's client id; the connector drops it.
    assert env["*base_env"] == '{ for k, v in local.base_env : k => v if k != "AZURE_CLIENT_ID" }'
    assert "var.identity_id" not in body and "var.identity_client_id" not in body


def test_it_is_public_with_no_auth_provider():
    body = _connector()
    [ingress] = _walk(body, "ingress")
    assert _attr(ingress, "external_enabled") == "true"
    port = _attr(ingress, "target_port")
    [probe] = _walk(_container(), "readiness_probe")
    assert (_attr(probe, "port"), _attr(probe, "path")) == (port, "local.ready_path")
    # The one authConfigs resource hangs off the dashboard.
    auth = [inner for k, labels, inner in _top()
            if k == "resource" and labels[0] == "azapi_resource"]
    assert len(auth) == 1 and "azurerm_container_app.dashboard.id" in auth[0]
    assert "azurerm_container_app.connector" not in auth[0]


def test_the_source_allowlist_is_empty_unless_given():
    [ingress] = _walk(_connector(), "ingress")
    [(labels, inner)] = [(labels, inner) for k, labels, inner in _blocks(ingress) if k == "dynamic"]
    assert labels == ["ip_security_restriction"]
    assert _attr(inner, "for_each") == "var.connector_source_ranges"
    [content] = _walk(inner, "content")
    assert _attr(content, "action") == '"Allow"'
    assert _attr(content, "ip_address_range") == "ip_security_restriction.value"


def test_it_carries_no_salt_and_no_secret():
    body = _connector()
    assert not _walk(body, "secret"), "the connector holds no secret"
    assert "secret_name" not in body
    assert "FORGD_HASH_SALT" not in _env()
    for name in SECRET_VARS:
        assert f"var.{name}" not in body, name


def test_it_runs_the_same_image_as_the_connector_role_and_leaves_it_to_ci():
    assert _attr(_container(), "image") == "var.image"
    assert _env()["FORGD_ROLE"] == '"connector"'
    assert re.search(r"^\s*connector\)", (ROOT / "deploy" / "entrypoint.sh").read_text(), re.M)
    [lifecycle] = _walk(_connector(), "lifecycle")
    assert _attr(lifecycle, "ignore_changes") == "[template[0].container[0].image]"


def test_every_connector_setting_reaches_the_app_under_a_name_it_reads():
    env = _env()
    names = {n for n in env if n.startswith("FORGD_CONNECTOR_")}
    assert names == {n for n in ENV_OVERRIDES if n.startswith("FORGD_CONNECTOR_")}, names
    assert env["FORGD_CONNECTOR_ENABLED"] == '"true"'
    assert env["FORGD_CONNECTOR_AUTH_MODE"] == '"oidc_jwt"'
    assert env["FORGD_CONNECTOR_RESOURCE"] == "local.connector_resource"
    # Lists travel as JSON, which is what the app's json_list parses.
    for name, var in (("SCOPES", "scopes"), ("ALLOWED_ORIGINS", "allowed_origins"),
                      ("AUDIENCE", "audience"), ("ISSUERS", "issuers")):
        assert env[f"FORGD_CONNECTOR_{name}"] == (
            f"length(var.connector_{var}) == 0 ? [] : [jsonencode(var.connector_{var})]")
    for name, var in (("REQUIRED_SCOPE", "required_scope"), ("ISSUER", "issuer"),
                      ("JWKS_URL", "jwks_url"), ("GROUPS_CLAIM", "groups_claim")):
        assert env[f"FORGD_CONNECTOR_{name}"] == (
            f'var.connector_{var} == "" ? [] : [var.connector_{var}]')


# --- the refusals, evaluated by terraform ----------------------------------------

def _harness(root: Path, preconditions: list[tuple[str, str]], new_environment: bool) -> Path:
    """variables.tf, the connector's locals and its preconditions, on a
    terraform_data resource with the connector's own count.

    `new_environment` takes the default domain from a resource not yet
    created, so it is unknown at plan as on the first apply of a real
    environment."""
    root.mkdir(parents=True, exist_ok=True)
    shutil.copy(MODULE / "variables.tf", root / "variables.tf")
    domain = "terraform_data.environment.output" if new_environment else "var.test_default_domain"
    defs = {n: e.replace("azurerm_container_app_environment.this.default_domain", domain)
            for n, e in _connector_locals().items()}
    checks = "".join(
        f"    precondition {{\n      condition     = {c}\n      error_message = {m}\n    }}\n"
        for c, m in preconditions)
    (root / "main.tf").write_text(
        'variable "test_default_domain" { type = string }\n'
        # timestamp() is unknown until apply, so the output is too; from
        # Terraform 1.9 a terraform_data output with a known input is known.
        'resource "terraform_data" "environment" {\n'
        '  input = "${var.test_default_domain}${substr(timestamp(), 0, 0)}"\n'
        '}\n'
        "locals {\n" + "".join(f"  {n} = {e}\n" for n, e in defs.items()) + "}\n"
        'resource "terraform_data" "connector" {\n'
        f"  count = {_attr(_connector(), 'count')}\n"
        "  lifecycle {\n" + checks + "  }\n}\n"
        'output "resource" { value = local.connector_resource }\n',
        encoding="utf-8")
    out = subprocess.run([terraform, f"-chdir={root}", "init", "-input=false", "-no-color"],
                         capture_output=True, text=True, timeout=120)
    assert out.returncode == 0, out.stderr
    return root


def _plan(root: Path, **variables) -> subprocess.CompletedProcess:
    (root / "terraform.tfvars.json").write_text(
        json.dumps({**REQUIRED, "test_default_domain": DOMAIN, **variables}), encoding="utf-8")
    return subprocess.run([terraform, f"-chdir={root}", "plan", "-input=false", "-no-color",
                           "-lock=false", "-refresh=false"],
                          capture_output=True, text=True, timeout=120)


def _flat(text: str) -> str:
    return " ".join(text.split())


@pytest.fixture(scope="module")
def harnesses(tmp_path_factory):
    root = tmp_path_factory.mktemp("aca")
    return {new: _harness(root / ("new" if new else "existing"), _preconditions(), new)
            for new in (False, True)}


@requires_terraform
@pytest.mark.parametrize("new", [False, True])
def test_the_connector_off_plans_with_nothing_set(harnesses, new):
    out = _plan(harnesses[new])
    assert out.returncode == 0, out.stderr
    assert "terraform_data.connector" not in out.stdout


@requires_terraform
@pytest.mark.parametrize("new", [False, True])
def test_the_connector_on_plans_and_derives_the_resource(harnesses, new):
    out = _plan(harnesses[new], **ON)
    assert out.returncode == 0, out.stderr
    assert "terraform_data.connector[0] will be created" in out.stdout
    if not new:
        assert f'resource = "{DERIVED}"' in out.stdout


@requires_terraform
def test_the_resource_may_be_given_when_it_matches(harnesses):
    out = _plan(harnesses[False], **ON, connector_resource=DERIVED)
    assert out.returncode == 0, out.stderr


@requires_terraform
def test_issuers_stand_in_for_the_single_issuer(harnesses):
    out = _plan(harnesses[False], **{
        **ON, "connector_issuer": "", "connector_jwks_url": "", "connector_audience": [],
        "connector_issuers": [{"issuer": ON["connector_issuer"],
                               "jwks_url": ON["connector_jwks_url"], "audience": ["a"]}]})
    assert out.returncode == 0, out.stderr


@requires_terraform
def test_the_required_scope_may_come_from_policy_yaml(harnesses):
    out = _plan(harnesses[False], **{**ON, "connector_required_scope": ""},
                policy_yaml="version: 1\nconnector:\n  required_scope: findings.read\n")
    assert out.returncode == 0, out.stderr


# Each case trips exactly one precondition, named by a fragment of its
# message. `new` is whether the environment's domain is still unknown.
REFUSALS = {
    "no issuer": (False, {"connector_issuer": ""}, "connector_issuer is empty"),
    "no jwks url": (False, {"connector_jwks_url": ""}, "connector_jwks_url is empty"),
    "no audience": (False, {"connector_audience": []}, "connector_audience is empty"),
    "an issuers entry without an audience": (False, {
        "connector_issuer": "", "connector_jwks_url": "", "connector_audience": [],
        "connector_issuers": [
        {"issuer": "https://i.example", "jwks_url": "https://i.example/keys", "audience": []}]},
        "A connector_issuers entry has an empty"),
    "a single issuer beside a list": (False, {"connector_issuers": [{"issuer": "https://i.example", "jwks_url": "https://i.example/keys", "audience": ["a"]}]},
                                      "Set either connector_issuers"),
    "a policy scope placeholder": (False, {
        "connector_required_scope": "",
        "policy_yaml": "connector:\n  required_scope: $FORGD_CONNECTOR_REQUIRED_SCOPE\n"},
        "connector_required_scope is empty"),
    "no required scope": (False, {"connector_required_scope": ""}, "connector_required_scope is empty"),
    "a policy scope that is empty": (False, {
        "connector_required_scope": "", "policy_yaml": "connector:\n  required_scope: ''\n"},
        "connector_required_scope is empty"),
    "not https": (True, {"connector_resource": f"http://ca-forgd-connector.{DOMAIN}/mcp"},
                  "must be an https URL"),
    "not lowercase": (True, {"connector_resource": DERIVED.replace("connector", "Connector")},
                      "must be lowercase"),
    "a derived name not lowercase": (True, {"connector_app_name": "ca-forgd-Connector"},
                                     "must be lowercase"),
    "not /mcp": (True, {"connector_resource": DERIVED + "/"}, "must end in /mcp"),
    "another host": (False, {"connector_resource": "https://mcp.example.com/mcp"},
                     "does not match the host"),
    "not the custom host": (True, {"connector_custom_host": CUSTOM, "connector_resource": DERIVED},
                            "does not match the host"),
    "a custom host with no resource": (True, {"connector_custom_host": CUSTOM},
                                       "connector_custom_host is set but connector_resource is empty"),
}


@requires_terraform
@pytest.mark.parametrize("new", [False, True])
def test_a_resource_on_the_custom_host_is_accepted_and_is_the_url(harnesses, new):
    resource = f"https://{CUSTOM}/mcp"
    out = _plan(harnesses[new], **ON, connector_custom_host=CUSTOM, connector_resource=resource)
    assert out.returncode == 0, out.stderr
    assert f'resource = "{resource}"' in out.stdout


@requires_terraform
@pytest.mark.parametrize("host", ["https://mcp.example.com", "MCP.example.com", "mcp.example.com/mcp",
                                  "mcp.example.com:443", "mcp"])
def test_the_custom_host_must_be_a_bare_lowercase_hostname(harnesses, host):
    out = _plan(harnesses[False], **ON, connector_custom_host=host,
                connector_resource=f"https://{host}/mcp")
    assert out.returncode != 0, out.stdout
    assert "must be a lowercase hostname" in _flat(out.stderr), out.stderr


@requires_terraform
def test_an_explicit_resource_is_matched_at_apply_while_the_domain_is_unknown(harnesses):
    """On a new environment the default domain is unknown at plan, so the
    mismatch that `another host` refuses at plan is left to apply."""
    out = _plan(harnesses[True], **ON, connector_resource="https://mcp.example.com/mcp")
    assert out.returncode == 0, out.stderr


@requires_terraform
@pytest.mark.parametrize("case", sorted(REFUSALS))
def test_each_refusal_fires(harnesses, case):
    new, variables, fragment = REFUSALS[case]
    out = _plan(harnesses[new], **{**ON, **variables})
    assert out.returncode != 0, out.stdout
    assert fragment in _flat(out.stderr), out.stderr


@requires_terraform
@pytest.mark.parametrize("case", sorted(REFUSALS))
def test_each_refusal_is_its_own_precondition(tmp_path, case):
    """Drop the precondition the case names and the same plan goes through,
    so no case passes on the back of a different guard."""
    new, variables, fragment = REFUSALS[case]
    kept = [(c, m) for c, m in _preconditions() if fragment not in m]
    assert len(kept) == 10, case
    out = _plan(_harness(tmp_path, kept, new), **{**ON, **variables})
    assert out.returncode == 0, out.stderr


def test_every_precondition_has_a_refusal():
    fragments = {f for _, _, f in REFUSALS.values()}
    for _, message in _preconditions():
        assert sum(f in message for f in fragments) == 1, message


def test_the_readme_names_every_secret_app_aca_writes_into_state():
    """Every sensitive variable written into a Container Apps secret lands
    in the Terraform state in plaintext."""
    readme = " ".join((ROOT / "deploy" / "terraform" / "README.md").read_text(encoding="utf-8").split())
    paragraph = readme[readme.index("`app-aca` differs"):readme.index("`app-ecs` takes Secrets Manager ARNs")]
    sensitive = set(re.findall(r'^variable "(\w+)" \{(?:(?!^\}).)*?^\s*sensitive\s*=\s*true',
                               (MODULE / "variables.tf").read_text(), re.M | re.S))
    written = sensitive & (set(re.findall(r'value\s*=\s*(?:var\.\w+_secret_id == "" \? )?var\.(\w+)', _text()))
                           | set(re.findall(r"try\(var\.(\w+)\[", _text())))
    assert written >= {"metrics_token", "dashboard_auth_client_secret", "dashboard_form_key", "otel_tokens",
                       "webhook_secrets", "intake_tokens", "intake_fleet_tokens"}, written
    assert [v for v in sorted(written) if f"`{v}`" not in paragraph] == []
    # Every Key Vault alternative is named too.
    variables = (MODULE / "variables.tf").read_text(encoding="utf-8")
    section = variables[variables.index("# --- the same secrets, named in Key Vault"):variables.index("# --- behaviour")]
    ids = set(re.findall(r'^variable "(\w+)"', section, re.M))
    assert len(ids) == 14, ids
    assert [v for v in sorted(ids) if f"`{v}`" not in paragraph] == []


def test_an_unfronted_trusted_header_dashboard_is_said_to_refuse_to_start():
    description = " ".join(_variable("dashboard_auth_client_id").split())
    assert "401" not in description
    assert "refuses to start" in description
