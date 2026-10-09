"""scripts/bootstrap_tfstate.sh and scripts/bootstrap_target_rg.sh refuse
to start without the names of the resources they act on.

`az` and `gh` are fakes first on PATH that log their argv, so a refusal can
be shown to happen before either is called.
"""

from __future__ import annotations

import json
import os
import re
import stat
import subprocess
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
TFSTATE = ROOT / "scripts" / "bootstrap_tfstate.sh"
TARGET_RG = ROOT / "scripts" / "bootstrap_target_rg.sh"

FAKE = r'''
import json, os, sys
tool, argv = os.path.basename(sys.argv[0]), sys.argv[1:]
with open(os.environ["FAKE_LOG"], "a") as f:
    f.write(json.dumps({"tool": tool, "argv": argv}) + "\n")
for rule in json.loads(os.environ.get("FAKE_RULES", "[]")):
    if rule["tool"] == tool and argv[:len(rule["argv"])] == rule["argv"]:
        sys.stdout.write(rule.get("out", ""))
        sys.stderr.write(rule.get("err", ""))
        sys.exit(rule.get("code", 0))
'''

TFSTATE_ENV = {
    "INFRA_IDENTITY": "id-infra",
    "GH_REPO": "example/verdict",
    "GH_ENV": "acme-infra",
    "AKS_RESOURCE_GROUP": "rg-stack",
    "AKS_FINDINGS_ACCOUNT": "stfindings",
    "AZURE_ACR": "acrexample",
}
TARGET_RG_ENV = {"IDENTITY_RG": "rg-identity", "IDENTITY": "id-infra", "GH_ENV": "acme-infra"}


@pytest.fixture
def bin_dir(tmp_path):
    d = tmp_path / "bin"
    d.mkdir()
    for tool in ("az", "gh"):
        p = d / tool
        p.write_text(f"#!{sys.executable}\n{FAKE}", encoding="utf-8")
        p.chmod(p.stat().st_mode | stat.S_IXUSR)
    return d


def _run(bin_dir: Path, script: Path, args: list[str], env: dict[str, str], rules: list[dict] = ()):
    log = bin_dir.parent / "log.jsonl"
    proc = subprocess.run(
        ["bash", str(script), *args],
        env={"PATH": f"{bin_dir}:{os.environ['PATH']}", "HOME": str(bin_dir.parent),
             "FAKE_LOG": str(log), "FAKE_RULES": json.dumps(list(rules)), **env},
        capture_output=True, text=True, timeout=60,
    )
    calls = [json.loads(line) for line in log.read_text().splitlines()] if log.exists() else []
    return proc, calls


@pytest.mark.parametrize("name", sorted(TFSTATE_ENV))
def test_tfstate_refuses_each_missing_input_before_any_call(bin_dir, name):
    env = {k: v for k, v in TFSTATE_ENV.items() if k != name}
    proc, calls = _run(bin_dir, TFSTATE, ["rg-state", "ststate"], env)
    assert proc.returncode == 2
    assert name in proc.stderr and "usage:" in proc.stderr
    assert calls == []


def test_tfstate_names_every_missing_input_at_once(bin_dir):
    proc, calls = _run(bin_dir, TFSTATE, ["rg-state", "ststate"], {})
    assert proc.returncode == 2
    for name in TFSTATE_ENV:
        assert name in proc.stderr, name
    assert calls == []


def test_tfstate_refuses_a_repo_without_an_owner(bin_dir):
    proc, calls = _run(bin_dir, TFSTATE, ["rg-state", "ststate"], {**TFSTATE_ENV, "GH_REPO": "verdict"})
    assert proc.returncode == 2 and "GH_REPO" in proc.stderr
    assert calls == []


@pytest.mark.parametrize("args", [[], ["rg-state"]])
def test_tfstate_refuses_missing_arguments(bin_dir, args):
    proc, calls = _run(bin_dir, TFSTATE, args, TFSTATE_ENV)
    assert proc.returncode == 2 and "usage:" in proc.stderr
    assert calls == []


def test_tfstate_starts_once_given_every_input(bin_dir):
    proc, calls = _run(bin_dir, TFSTATE, ["rg-state", "ststate"], TFSTATE_ENV)
    assert "usage:" not in proc.stderr
    assert calls and calls[0]["tool"] == "az"


@pytest.mark.parametrize("name", sorted(TARGET_RG_ENV))
def test_target_rg_refuses_each_missing_input_before_any_call(bin_dir, name):
    env = {k: v for k, v in TARGET_RG_ENV.items() if k != name}
    proc, calls = _run(bin_dir, TARGET_RG, ["rg-stack", "westeurope"], env)
    assert proc.returncode == 2
    assert name in proc.stderr and "usage:" in proc.stderr
    assert calls == []


def test_target_rg_requires_a_location(bin_dir):
    proc, calls = _run(bin_dir, TARGET_RG, ["rg-stack"], TARGET_RG_ENV)
    assert proc.returncode == 2 and "<location>" in proc.stderr
    assert calls == []


def test_target_rg_starts_once_given_every_input(bin_dir):
    proc, calls = _run(bin_dir, TARGET_RG, ["rg-stack", "westeurope"], TARGET_RG_ENV)
    assert "usage:" not in proc.stderr
    identity = [c for c in calls if c["argv"][:2] == ["identity", "show"]]
    assert identity and identity[0]["argv"][identity[0]["argv"].index("-g") + 1] == "rg-identity"


@pytest.mark.parametrize(("script", "required"), [(TFSTATE, TFSTATE_ENV), (TARGET_RG, TARGET_RG_ENV)],
                         ids=["tfstate", "target_rg"])
def test_no_required_input_has_a_default(script, required):
    text = script.read_text(encoding="utf-8")
    for name in required:
        assert not re.search(rf"\$\{{{name}:?-[^}}]", text), name
    assert not re.search(r"\$\{[12]:?-", text), "a positional argument has a default"


def test_the_bootstrap_sends_booleans_as_booleans():
    """`gh api -f` sends every value as a string, and the environments API
    rejects `"false"` where it wants a boolean -- with a 422 that only
    appears when you run it. The branch policy is the actual gate, so a
    bootstrap that fails there leaves the environment ungated.
    """
    script = (ROOT / "scripts" / "bootstrap_tfstate.sh").read_text(encoding="utf-8")
    policy = [ln for ln in script.splitlines() if "deployment_branch_policy[" in ln]
    assert policy, "the branch policy call disappeared"
    for line in policy:
        assert line.strip().startswith("-F "), f"-f sends a string here: {line.strip()}"


def _prose(path: Path) -> str:
    return " ".join(path.read_text(encoding="utf-8").replace("#", " ").split())


@pytest.mark.parametrize("path", [TFSTATE, TARGET_RG, ROOT / "deploy" / "terraform" / "README.md"],
                         ids=["tfstate", "target_rg", "terraform_readme"])
def test_nothing_says_the_infra_identity_cannot_reach_the_findings(path):
    """It holds User Access Administrator on the stack's group, which lets it
    grant itself a data role on the findings store."""
    text = _prose(path)
    for claim in ("must not be able to read", "alter the evidence", "altering the evidence"):
        assert claim not in text, claim


@pytest.mark.parametrize("path", [TARGET_RG, ROOT / "deploy" / "terraform" / "README.md"],
                         ids=["target_rg", "terraform_readme"])
def test_the_self_grant_is_stated_where_the_grant_is_made(path):
    text = _prose(path)
    assert "User Access Administrator lets it grant itself" in text
    assert "read or rewrite the findings" in text


# --- an existing grant is skipped, and a failed one stops the run --------------

AUTHORIZATION_FAILED = ("ERROR: (AuthorizationFailed) The client does not have authorization to perform "
                        "action 'Microsoft.Authorization/roleAssignments/write'\n")
NOT_HELD = {"tool": "az", "argv": ["role", "assignment", "list"], "out": "0\n"}
HELD = {"tool": "az", "argv": ["role", "assignment", "list"], "out": "1\n"}
CREATE_DENIED = {"tool": "az", "argv": ["role", "assignment", "create"], "code": 1, "err": AUTHORIZATION_FAILED}
SCRIPTS = [(TFSTATE, ["rg-state", "ststate"], TFSTATE_ENV), (TARGET_RG, ["rg-stack", "westeurope"], TARGET_RG_ENV)]
SCRIPT_IDS = ["tfstate", "target_rg"]


def _creates(calls: list[dict]) -> list[str]:
    return [c["argv"][c["argv"].index("--role") + 1] for c in calls
            if c["tool"] == "az" and c["argv"][:3] == ["role", "assignment", "create"]]


@pytest.mark.parametrize(("script", "args", "env"), SCRIPTS, ids=SCRIPT_IDS)
def test_a_denied_role_assignment_stops_the_run(bin_dir, script, args, env):
    proc, calls = _run(bin_dir, script, args, env, [NOT_HELD, CREATE_DENIED])
    assert proc.returncode != 0, proc.stdout
    assert "AuthorizationFailed" in proc.stderr
    assert "already held" not in proc.stdout
    assert _creates(calls) == ["Contributor"]


@pytest.mark.parametrize(("script", "args", "env"), SCRIPTS, ids=SCRIPT_IDS)
def test_a_held_role_assignment_is_not_created_again(bin_dir, script, args, env):
    proc, calls = _run(bin_dir, script, args, env, [HELD, CREATE_DENIED])
    assert proc.returncode == 0, proc.stderr
    assert _creates(calls) == []
    assert "already held: User Access Administrator" in proc.stdout


@pytest.mark.parametrize(("script", "args", "env"), SCRIPTS, ids=SCRIPT_IDS)
def test_a_missing_role_assignment_is_created(bin_dir, script, args, env):
    proc, calls = _run(bin_dir, script, args, env, [NOT_HELD])
    assert proc.returncode == 0, proc.stderr
    assert _creates(calls)[:2] == ["Contributor", "User Access Administrator"]
    lists = [c["argv"] for c in calls if c["argv"][:3] == ["role", "assignment", "list"]]
    assert lists and all("--scope" in a and "--role" in a for a in lists)


def _credential_rules(existing: dict[str, str], create_code: int = 0) -> list[dict]:
    listed = "".join(f"{name}\t{subject}\n" for name, subject in existing.items())
    return [NOT_HELD,
            {"tool": "gh", "argv": ["api", "orgs/example"], "out": "11\n"},
            {"tool": "gh", "argv": ["api", "repos/example/verdict"], "out": "22\n"},
            {"tool": "az", "argv": ["identity", "federated-credential", "list"], "out": listed},
            {"tool": "az", "argv": ["identity", "federated-credential", "create"], "code": create_code,
             "err": AUTHORIZATION_FAILED if create_code else ""}]


def _credentials_created(calls: list[dict]) -> list[str]:
    return [c["argv"][c["argv"].index("--name") + 1] for c in calls
            if c["argv"][:3] == ["identity", "federated-credential", "create"]]


CLASSIC = "repo:example/verdict:environment:acme-infra"
IMMUTABLE = "repo:example@11/verdict@22:environment:acme-infra"


def test_a_failed_federated_credential_stops_the_run(bin_dir):
    proc, calls = _run(bin_dir, TFSTATE, ["rg-state", "ststate"], TFSTATE_ENV, _credential_rules({}, create_code=1))
    assert proc.returncode != 0, proc.stdout
    assert "AuthorizationFailed" in proc.stderr
    assert "exists: gh-acme-infra" not in proc.stdout
    assert _credentials_created(calls) == ["gh-acme-infra"]


def test_existing_federated_credentials_are_not_created_again(bin_dir):
    rules = _credential_rules({"gh-acme-infra": CLASSIC, "gh-acme-infra-immutable": IMMUTABLE}, create_code=1)
    proc, calls = _run(bin_dir, TFSTATE, ["rg-state", "ststate"], TFSTATE_ENV, rules)
    assert proc.returncode == 0, proc.stderr
    assert _credentials_created(calls) == []


def test_missing_federated_credentials_are_created(bin_dir):
    proc, calls = _run(bin_dir, TFSTATE, ["rg-state", "ststate"], TFSTATE_ENV, _credential_rules({}))
    assert proc.returncode == 0, proc.stderr
    assert _credentials_created(calls) == ["gh-acme-infra", "gh-acme-infra-immutable"]


def test_a_federated_credential_with_another_subject_stops_the_run(bin_dir):
    rules = _credential_rules({"gh-acme-infra": "repo:someone/else:environment:acme-infra"})
    proc, calls = _run(bin_dir, TFSTATE, ["rg-state", "ststate"], TFSTATE_ENV, rules)
    assert proc.returncode != 0, proc.stdout
    assert "repo:someone/else:environment:acme-infra" in proc.stderr
    assert _credentials_created(calls) == []


def test_a_failed_branch_policy_stops_the_run(bin_dir):
    rules = [NOT_HELD, {"tool": "gh", "argv": ["api", "-X", "POST"], "code": 1, "err": "HTTP 403: Forbidden\n"}]
    proc, _ = _run(bin_dir, TFSTATE, ["rg-state", "ststate"], TFSTATE_ENV, rules)
    assert proc.returncode != 0, proc.stdout
    assert "HTTP 403" in proc.stderr
    assert "already set" not in proc.stdout


@pytest.mark.parametrize(("script", "args", "env"), SCRIPTS, ids=SCRIPT_IDS)
def test_an_assignment_the_list_missed_is_reported_as_held(bin_dir, script, args, env):
    """Assignments listed by scope can miss one that exists, and the create
    then fails with RoleAssignmentExists."""
    exists = {"tool": "az", "argv": ["role", "assignment", "create"], "code": 1,
              "err": "ERROR: (RoleAssignmentExists) The role assignment already exists.\n"}
    proc, calls = _run(bin_dir, script, args, env, [NOT_HELD, exists])
    assert proc.returncode == 0, proc.stderr
    assert "already held: Contributor" in proc.stdout
    assert "already held: User Access Administrator" in proc.stdout
    assert _creates(calls)[:2] == ["Contributor", "User Access Administrator"]


def test_the_summary_names_the_branch_the_environment_deploys_from(bin_dir):
    """In an unquoted heredoc a backticked `main` is run as a command, and
    the summary printed "deploys from  only"."""
    proc, _ = _run(bin_dir, TFSTATE, ["rg-state", "ststate"], TFSTATE_ENV, [NOT_HELD])
    assert proc.returncode == 0, proc.stderr
    assert "acme-infra deploys from 'main' only" in proc.stdout, proc.stdout


def _unquoted_heredoc_bodies(text: str) -> list[tuple[int, str]]:
    """(line number, line) for every line inside an unquoted heredoc, where
    the shell expands $ and backticks."""
    lines, out, i = text.split("\n"), [], 0
    while i < len(lines):
        m = re.search(r"<<(-?)\s*([A-Za-z_]\w*)\b", lines[i])
        if m and not re.search(r"<<-?\s*['\"]", lines[i]):
            strip, term = m.group(1), m.group(2)
            i += 1
            while i < len(lines) and (lines[i].lstrip("\t") if strip else lines[i]) != term:
                out.append((i + 1, lines[i]))
                i += 1
        i += 1
    return out


SHELL_SCRIPTS = sorted((ROOT / "scripts").glob("*.sh"))


def test_the_heredoc_scan_sees_the_unquoted_heredocs():
    assert any(_unquoted_heredoc_bodies(p.read_text(encoding="utf-8")) for p in SHELL_SCRIPTS)
    assert _unquoted_heredoc_bodies("cat <<OUT\na `b`\nOUT\ncat <<'Q'\n`c`\nQ\n") == [(2, "a `b`")]


@pytest.mark.parametrize("path", SHELL_SCRIPTS, ids=lambda p: p.name)
def test_no_unquoted_heredoc_holds_a_backtick(path):
    found = [(n, line) for n, line in _unquoted_heredoc_bodies(path.read_text(encoding="utf-8")) if "`" in line]
    assert found == [], found


ACCOUNT_ABSENT = {"tool": "az", "argv": ["storage", "account", "show"], "code": 3}


def _account_creates(calls: list[dict]) -> list[list[str]]:
    return [c["argv"] for c in calls if c["tool"] == "az" and c["argv"][:3] == ["storage", "account", "create"]]


def test_the_state_account_is_created_with_shared_keys_off(bin_dir):
    """The backend authenticates with Entra ID (use_azuread_auth), so a
    shared key on the account is only a second way in."""
    proc, calls = _run(bin_dir, TFSTATE, ["rg-state", "ststate"], TFSTATE_ENV, [ACCOUNT_ABSENT, NOT_HELD])
    assert proc.returncode == 0, proc.stderr
    (create,) = _account_creates(calls)
    assert create[create.index("--allow-shared-key-access") + 1] == "false"


def test_an_existing_state_account_is_left_alone_with_the_command_to_turn_shared_keys_off(bin_dir):
    proc, calls = _run(bin_dir, TFSTATE, ["rg-state", "ststate"], TFSTATE_ENV, [NOT_HELD])
    assert proc.returncode == 0, proc.stderr
    assert _account_creates(calls) == []
    assert not [c for c in calls if c["argv"][:3] == ["storage", "account", "update"]]
    assert "az storage account update -n ststate -g rg-state --allow-shared-key-access false" in proc.stdout


def _container_calls(calls: list[dict]) -> list[list[str]]:
    return [c["argv"] for c in calls if c["tool"] == "az" and c["argv"][:1] == ["storage"]
            and c["argv"][1].startswith("container")]


@pytest.mark.parametrize("rules", [[ACCOUNT_ABSENT, NOT_HELD], [NOT_HELD]], ids=["new-account", "existing-account"])
def test_the_state_container_is_created_through_the_control_plane(bin_dir, rules):
    """With shared keys off, a data-plane create needs Storage Blob Data
    Contributor, which Owner and Contributor do not carry."""
    proc, calls = _run(bin_dir, TFSTATE, ["rg-state", "ststate"], TFSTATE_ENV, rules)
    assert proc.returncode == 0, proc.stderr
    (create,) = _container_calls(calls)
    assert create[:3] == ["storage", "container-rm", "create"], create
    assert create[create.index("--name") + 1] == "tfstate"
    assert create[create.index("--storage-account") + 1] == "ststate"
    assert create[create.index("--resource-group") + 1] == "rg-state"
    assert create[create.index("--public-access") + 1] == "off"
    assert "--auth-mode" not in create and "--account-key" not in create


@pytest.mark.parametrize("rules", [[ACCOUNT_ABSENT, NOT_HELD], [NOT_HELD]], ids=["new-account", "existing-account"])
def test_the_state_account_keeps_deleted_blobs_versions_and_containers(bin_dir, rules):
    """Blob soft delete and versioning do not cover a container delete,
    which takes every state file in it."""
    proc, calls = _run(bin_dir, TFSTATE, ["rg-state", "ststate"], TFSTATE_ENV, rules)
    assert proc.returncode == 0, proc.stderr
    (update,) = [c["argv"] for c in calls
                 if c["tool"] == "az" and c["argv"][:4] == ["storage", "account", "blob-service-properties", "update"]]
    for flag, value in {"-n": "ststate", "-g": "rg-state",
                        "--enable-versioning": "true",
                        "--enable-delete-retention": "true", "--delete-retention-days": "30",
                        "--enable-container-delete-retention": "true",
                        "--container-delete-retention-days": "30"}.items():
        assert flag in update and update[update.index(flag) + 1] == value, (flag, update)


def test_the_tfstate_script_has_no_data_plane_container_call():
    text = TFSTATE.read_text(encoding="utf-8")
    for needle in ("az storage container create", "--auth-mode login", "--account-key"):
        assert needle not in text, needle
