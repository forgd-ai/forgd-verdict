"""Policy loading and the per-adapter profile mechanism."""

import pathlib

import pytest

# -- per-adapter profiles ------------------------------------------------
#
# One policy definition covers control points that do not share a
# latency budget. These tests pin the asymmetry, because getting it wrong in
# either direction is a real incident: T2 on the inference hook spends the
# org's verdict timeout and turns prompts into webhook failures, and T2
# missing from the post-hoc scanner is the silent gap that makes "0 findings"
# read as "nothing to find".


def _shipped():
    from forgd_verdict.policy import load_policy

    return load_policy("policy.yaml")


def test_inline_path_never_builds_the_t2_tier():
    names = [d.name for d in _shipped().build_detectors()]
    assert "presidio_pii" not in names
    assert "llmguard_pii" not in names


def test_post_hoc_profile_turns_presidio_on():
    cfgs = _shipped().for_profile("compliance").detector_configs()
    assert cfgs["presidio_pii"].enabled == "auto"
    # Post-hoc detection cannot deny anything, so severity only ranks.
    assert cfgs["presidio_pii"].severity == "warn"


def test_profile_merges_rather_than_replaces():
    """An override retunes one detector; it does not fork the policy."""
    base = _shipped()
    profile = base.for_profile("compliance")
    # The profile turns on Presidio and the behavioural checks, which
    # are off at the top level; every other detector is inherited as is.
    retuned = {"presidio_pii", "provenance", "taint"}
    for name, cfg in base.detector_configs().items():
        if name in retuned:
            continue
        assert profile.detector_configs()[name] == cfg, name


def test_post_hoc_profile_raises_the_scan_budget():
    base = _shipped()
    assert base.for_profile("compliance").budget_ms > base.budget_ms


def test_profile_with_no_overrides_is_the_same_policy():
    base = _shipped()
    assert base.for_profile("nonexistent") is base
    # A section with no `detectors:` or `scan:` key is not an override.
    assert base.for_profile("deny") is base


def test_the_hook_profile_carries_the_daemon():
    """It is the profile /scan builds from, in a pod that has the socket.

    Without it the detector shells out and the CLI recompiles its rule
    set per exec, which against the hook budget is a timeout rather than
    a slow scan.
    """
    base = _shipped()
    merged = base.for_profile("hook")
    assert merged is not base
    assert merged.raw["detectors"]["gitleaks"]["daemon"] == "$FORGD_GITLEAKS_SOCKET"
    # Merged, not replaced: the shared tiers are still there.
    assert merged.raw["detectors"]["t0_regex"]["enabled"] is True


def test_scanner_adopts_the_post_hoc_profile():
    """The adapter boundary applies the profile, not the CLI, so a library
    caller cannot get inline tiers by constructing the scanner directly."""
    from forgd_verdict.compliance.scanner import ComplianceScanner

    scanner = ComplianceScanner(_shipped(), client=object())
    assert scanner.policy.detector_configs()["presidio_pii"].enabled == "auto"
    assert scanner.policy.budget_ms == 60000


def test_presidio_entities_are_ner_only():
    """Presidio's structured recognizers are worse than T0 here, not better:
    its US_SSN recognizer carries a hardcoded blocklist of placeholder values,
    so it skips exactly the numbers a tester reaches for first. If one of
    those creeps back into the entity list, a finding T0 owns starts arriving
    twice and an SSN test still fails."""
    entities = set(
        _shipped().raw["compliance"]["detectors"]["presidio_pii"]["entities"]
    )
    structured = {
        "US_SSN", "CREDIT_CARD", "IBAN_CODE", "US_PASSPORT",
        "US_DRIVER_LICENSE", "US_BANK_NUMBER", "US_ITIN",
    }
    assert not entities & structured, entities & structured
    # Noise control: every timestamp and address in an engineering
    # transcript matches these, and noise is what stops people reading.
    assert not entities & {"DATE_TIME", "IP_ADDRESS"}


def test_build_time_assertion_uses_the_configured_score_threshold():
    """The assertion has to apply the same floor the detector applies, or it
    is weaker than the thing it checks. Without it the assertion passes
    while PHONE_NUMBER -- which Presidio scores 0.40 by construction --
    can never produce a finding in production."""
    import re

    src = pathlib.Path("deploy/assert_presidio.py").read_text()
    asserted = float(re.search(r"SCORE_THRESHOLD = ([\d.]+)", src).group(1))
    configured = float(
        _shipped().raw["compliance"]["detectors"]["presidio_pii"]["score_threshold"]
    )
    assert asserted == configured


def test_build_time_assertion_covers_the_configured_entities():
    """deploy/assert_presidio.py proves the tier works at image-build time.
    It can only do that for entities it actually asks for, so the two lists
    have to stay in step -- Presidio ignores an entity it does not recognise
    rather than raising, which would make a rename free at startup and
    expensive at scan time."""
    import re

    src = pathlib.Path("deploy/assert_presidio.py").read_text()
    listed = set(re.findall(r'"([A-Z_]+)"', src.split("ENTITIES = [")[1].split("]")[0]))
    configured = set(
        _shipped().raw["compliance"]["detectors"]["presidio_pii"]["entities"]
    )
    assert listed == configured, (listed ^ configured)


def test_every_configured_presidio_entity_has_a_description():
    """A finding with no description renders as a bare detector name on the
    findings page and would compose an empty clause in a deny reason. The
    entity list is policy, so the check belongs with the policy."""
    from forgd_verdict.core import DESCRIPTIONS

    for entity in _shipped().raw["compliance"]["detectors"]["presidio_pii"]["entities"]:
        key = f"presidio:{entity.lower()}"
        assert DESCRIPTIONS.get(key), key


def test_ship_mode_is_off_by_default_and_env_overridable_with_project_overrides(tmp_path):
    """Shipping local hook decisions records what developers typed, which is
    a different question from scanning prompts in flight. It stays opt-in.
    A per-project opt-in needs `hook.project_overrides: true`."""
    import os
    from unittest import mock

    import yaml

    from forgd_verdict.policy import load_policy

    assert _shipped().hook.get("ship_mode", "off") == "off"
    with mock.patch.dict(os.environ, {"FORGD_VERDICT_SHIP_MODE": "sessionend"}):
        assert load_policy("policy.yaml").hook.get("ship_mode", "off") == "off"
        opted = tmp_path / "policy.yaml"
        opted.write_text(yaml.safe_dump({"hook": {"project_overrides": True}}))
        assert load_policy(str(opted)).hook["ship_mode"] == "sessionend"


# -- a configured sidecar is required, not optional ----------------------


def test_the_server_profile_requires_the_gitleaks_daemon(monkeypatch):
    """`auto` means "run it if it happens to be there", which on the one
    latency-critical path would let a dead sidecar become a silently missing
    tier. Configuring `daemon` marks the tier required, so startup fails
    instead. Deliberately not `enabled: true`, which would also break
    `forgd-verdict serve` on any machine without a gitleaks binary."""
    from forgd_verdict.policy import load_policy

    monkeypatch.setenv("FORGD_GITLEAKS_SOCKET", "/nonexistent/forgd/gl.sock")
    with pytest.raises(RuntimeError, match="required here but unavailable"):
        load_policy("policy.yaml").for_profile("server").build_detectors()


def test_no_daemon_configured_leaves_gitleaks_optional(monkeypatch):
    """A laptop running `serve` has no sidecar and may have no gitleaks."""
    from forgd_verdict.policy import load_policy

    monkeypatch.delenv("FORGD_GITLEAKS_SOCKET", raising=False)
    names = [d.name for d in load_policy("policy.yaml").for_profile("server").build_detectors()]
    assert "regex" in names  # built without raising


def test_the_audit_profile_does_not_require_a_daemon(monkeypatch):
    """Adapter 3 is a cron job; the subprocess cost is irrelevant there, and
    requiring a sidecar would couple the two deployments."""
    from forgd_verdict.policy import load_policy

    monkeypatch.setenv("FORGD_GITLEAKS_SOCKET", "/nonexistent/forgd/gl.sock")
    names = [d.name for d in load_policy("policy.yaml").for_profile("compliance").build_detectors()]
    assert "regex" in names


# -- the daemon's gitleaks config ----------------------------------------


def _daemon_policy(tmp_path, config):
    from forgd_verdict.policy import DEFAULT_POLICY, Policy, _deep_merge

    gl = {"daemon": str(tmp_path / "gl.sock")}
    if config is not None:
        gl["config"] = config
    return Policy(raw=_deep_merge(DEFAULT_POLICY, {"detectors": {"gitleaks": gl}}))


@pytest.fixture
def live_daemon(monkeypatch):
    import forgd_verdict.detectors.gitleaks as gl

    monkeypatch.setattr(gl, "_daemon_alive", lambda *_a: True)


def test_a_daemon_config_matching_what_the_daemon_loaded_builds(
        tmp_path, monkeypatch, live_daemon):
    rules = tmp_path / "rules.toml"
    monkeypatch.setenv("FORGD_GITLEAKS_CONFIG", str(rules))
    names = [d.name for d in _daemon_policy(tmp_path, str(rules)).build_detectors()]
    assert "gitleaks" in names


def test_a_daemon_config_the_daemon_did_not_load_refuses(
        tmp_path, monkeypatch, live_daemon):
    rules, other = tmp_path / "rules.toml", tmp_path / "other.toml"
    monkeypatch.setenv("FORGD_GITLEAKS_CONFIG", str(other))
    with pytest.raises(RuntimeError) as exc:
        _daemon_policy(tmp_path, str(rules)).build_detectors()
    assert "detectors.gitleaks.config" in str(exc.value)
    assert str(rules.resolve()) in str(exc.value)
    assert str(other.resolve()) in str(exc.value)


def test_a_daemon_config_with_nothing_saying_what_the_daemon_loaded_refuses(
        tmp_path, monkeypatch, live_daemon):
    rules = tmp_path / "rules.toml"
    monkeypatch.delenv("FORGD_GITLEAKS_CONFIG", raising=False)
    with pytest.raises(RuntimeError, match="FORGD_GITLEAKS_CONFIG is unset") as exc:
        _daemon_policy(tmp_path, str(rules)).build_detectors()
    assert str(rules.resolve()) in str(exc.value)


def test_a_daemon_without_a_policy_config_is_not_compared(
        tmp_path, monkeypatch, live_daemon):
    monkeypatch.setenv("FORGD_GITLEAKS_CONFIG", str(tmp_path / "anything.toml"))
    names = [d.name for d in _daemon_policy(tmp_path, None).build_detectors()]
    assert "gitleaks" in names


def test_the_subprocess_transport_does_not_compare_configs(tmp_path, monkeypatch):
    from forgd_verdict.policy import DEFAULT_POLICY, Policy, _deep_merge

    monkeypatch.delenv("FORGD_GITLEAKS_CONFIG", raising=False)
    raw = {"detectors": {"gitleaks": {"config": str(tmp_path / "rules.toml")}}}
    Policy(raw=_deep_merge(DEFAULT_POLICY, raw)).build_detectors()


def _gl_policy(tmp_path, **profiles):
    """A policy whose named profiles scan through a daemon on `config`."""
    from forgd_verdict.policy import DEFAULT_POLICY, Policy, _deep_merge

    sock = str(tmp_path / "gl.sock")
    raw = {}
    for name, config in profiles.items():
        gl = {"daemon": sock}
        if config is not None:
            gl["config"] = str(config)
        raw[name] = {"detectors": {"gitleaks": gl}}
    return Policy(raw=_deep_merge(DEFAULT_POLICY, raw))


def test_a_server_and_an_otel_profile_on_different_configs_each_get_their_own(
        tmp_path, monkeypatch):
    from forgd_verdict.policy import gitleaks_daemon_config

    monkeypatch.delenv("FORGD_GITLEAKS_CONFIG", raising=False)
    a, b = tmp_path / "a.toml", tmp_path / "b.toml"
    policy = _gl_policy(tmp_path, server=a, otel=b)
    assert gitleaks_daemon_config(policy, "server") == str(a.resolve())
    assert gitleaks_daemon_config(policy, "collect") == str(b.resolve())


def test_intake_profiles_that_disagree_on_the_daemon_config_have_no_answer(
        tmp_path, monkeypatch):
    from forgd_verdict.policy import gitleaks_daemon_config

    monkeypatch.delenv("FORGD_GITLEAKS_CONFIG", raising=False)
    a, b = tmp_path / "a.toml", tmp_path / "b.toml"
    with pytest.raises(ValueError, match="The daemon loads one config") as exc:
        gitleaks_daemon_config(_gl_policy(tmp_path, server=a, hook=b), "intake")
    assert str(a.resolve()) in str(exc.value)
    assert str(b.resolve()) in str(exc.value)


def test_intake_ignores_an_otel_profile_on_another_config(tmp_path, monkeypatch):
    from forgd_verdict.policy import gitleaks_daemon_config

    monkeypatch.delenv("FORGD_GITLEAKS_CONFIG", raising=False)
    a, b = tmp_path / "a.toml", tmp_path / "b.toml"
    policy = _gl_policy(tmp_path, server=a, hook=a, otel=b)
    assert gitleaks_daemon_config(policy, "intake") == str(a.resolve())


def test_an_unknown_role_has_no_daemon_config(tmp_path, monkeypatch):
    from forgd_verdict.policy import gitleaks_daemon_config

    monkeypatch.delenv("FORGD_GITLEAKS_CONFIG", raising=False)
    with pytest.raises(ValueError, match="collect, intake") as exc:
        gitleaks_daemon_config(_gl_policy(tmp_path, server=None), "dashboard")
    assert "'dashboard'" in str(exc.value)


def test_a_profile_without_a_config_disagrees_with_one_that_names_one(
        tmp_path, monkeypatch):
    import forgd_verdict.detectors.gitleaks as gl
    from forgd_verdict.policy import gitleaks_daemon_config

    monkeypatch.delenv("FORGD_GITLEAKS_CONFIG", raising=False)
    policy = _gl_policy(tmp_path, server=tmp_path / "a.toml", hook=None)
    with pytest.raises(ValueError, match="hook profile is unset") as exc:
        gitleaks_daemon_config(policy, "intake")
    assert str(gl.BASELINE_CONFIG) in str(exc.value)


def test_relative_daemon_configs_resolve_against_the_working_directory(
        tmp_path, monkeypatch):
    from forgd_verdict.policy import gitleaks_daemon_config

    monkeypatch.delenv("FORGD_GITLEAKS_CONFIG", raising=False)
    monkeypatch.chdir(tmp_path)
    got = gitleaks_daemon_config(_gl_policy(tmp_path, server="./rules.toml"), "server")
    assert got == str((tmp_path / "rules.toml").resolve())


def test_the_gitleaks_config_command_requires_a_role(tmp_path, monkeypatch, capsys):
    from forgd_verdict.cli import main

    monkeypatch.delenv("FORGD_GITLEAKS_CONFIG", raising=False)
    path = tmp_path / "policy.yaml"
    path.write_text(f"otel:\n  detectors:\n    gitleaks:\n"
                    f"      daemon: {tmp_path / 'gl.sock'}\n"
                    f"      config: {tmp_path / 'b.toml'}\n")
    with pytest.raises(SystemExit) as exc:
        main(["--policy", str(path), "gitleaks-config"])
    assert exc.value.code == 2
    assert "--role" in capsys.readouterr().err
    assert main(["--policy", str(path), "gitleaks-config", "--role", "collect"]) == 0
    assert capsys.readouterr().out.strip() == str((tmp_path / "b.toml").resolve())


def test_a_policy_parse_error_in_gitleaks_config_never_prints_the_line(
        tmp_path, monkeypatch, capsys):
    import secrets

    from forgd_verdict.cli import main

    monkeypatch.delenv("FORGD_GITLEAKS_CONFIG", raising=False)
    canary = f"CANARY-{secrets.token_hex(8)}"
    path = tmp_path / "policy.yaml"
    path.write_text(f'privacy:\n  hash_salt: "{canary}\n')
    assert main(["--policy", str(path), "gitleaks-config", "--role", "server"]) == 2
    out, err = capsys.readouterr()
    assert "ScannerError" in err and "withheld" in err
    assert canary not in out
    assert canary not in err


def test_the_gitleaks_config_roles_are_the_ones_mapped_to_profiles(capsys):
    from forgd_verdict.cli import main
    from forgd_verdict.policy import GITLEAKS_ROLE_PROFILES

    with pytest.raises(SystemExit):
        main(["gitleaks-config", "--role", "nope"])
    err = capsys.readouterr().err
    choices = err.split("--role {", 1)[1].split("}", 1)[0]
    assert set(choices.split(",")) == set(GITLEAKS_ROLE_PROFILES)


# -- release identity ----------------------------------------------------


def test_the_tag_and_the_declared_version_cannot_drift():
    """`pyproject.toml` and `__version__` are bumped together by
    cut_release.sh. If they disagree, the artifact and its metadata disagree,
    and a finding cannot be attributed to a rule set."""
    import re

    import forgd_verdict

    declared = re.search(
        r'(?m)^version = "([^"]+)"', pathlib.Path("pyproject.toml").read_text()
    ).group(1)
    assert declared == forgd_verdict.__version__


HOOK_PYPROJECT = pathlib.Path("packaging/forgd-verdict-hook/pyproject.toml")


def test_the_hook_distribution_pins_the_core_exactly():
    """`forgd-verdict-hook` is a second distribution built from this tree:
    metadata, one console script and an exact pin on `forgd-verdict`. Its
    version and its pin both move with cut_release.sh, so the two wheels
    from one release install one copy of the detection code."""
    import importlib
    import tomllib

    from forgd_verdict import __version__
    from forgd_verdict.hook.cli import main as hook_main

    hook = tomllib.loads(HOOK_PYPROJECT.read_text())["project"]
    assert hook["name"] == "forgd-verdict-hook"
    assert hook["version"] == __version__
    assert hook["dependencies"] == [f"forgd-verdict=={__version__}"]

    module, func = hook["scripts"]["forgd-verdict-hook"].split(":")
    assert getattr(importlib.import_module(module), func) is hook_main


def test_build_id_names_the_commit_when_it_is_known(monkeypatch):
    """A version alone does not identify a running instance: deploys happen
    between releases, so one version covers many commits."""
    import importlib

    import forgd_verdict

    monkeypatch.setenv("FORGD_BUILD_COMMIT", "abc123def4567890")
    importlib.reload(forgd_verdict)
    try:
        assert forgd_verdict.build_id() == f"{forgd_verdict.__version__}+abc123def456"
        monkeypatch.delenv("FORGD_BUILD_COMMIT")
        importlib.reload(forgd_verdict)
        assert forgd_verdict.build_id() == forgd_verdict.__version__
    finally:
        importlib.reload(forgd_verdict)


def test_redaction_is_shared_by_the_cli_and_the_dashboard(monkeypatch):
    """One implementation, because the failure mode of two is printing a
    credential from whichever copy fell behind."""
    import inspect

    from forgd_verdict import cli
    from forgd_verdict.policy import load_policy, redacted

    assert "redacted" in inspect.getsource(cli._cmd_policy)
    assert "api_key" not in inspect.getsource(cli._cmd_policy)

    # Not "LEAK" as a sentinel: it is a substring of GITLEAKS, which appears
    # in the policy as $FORGD_GITLEAKS_SOCKET. A sentinel has to be absent
    # from the thing being searched or the test passes for the wrong reason.
    monkeypatch.setenv("ANTHROPIC_COMPLIANCE_ACCESS_KEY", "sk-ant-api01-ZQXJV")
    monkeypatch.setenv("FORGD_METRICS_TOKEN", "token-ZQXJV")

    blob = repr(redacted(load_policy("policy.yaml")))
    assert "ZQXJV" not in blob
    assert "<redacted>" in blob


def test_redaction_distinguishes_unset_from_hidden():
    """`<set>` and absent mean different things to someone debugging a 401.

    Built directly rather than through the environment: `privacy.hash_salt`
    has no env override -- it is a literal in the policy file -- so setting
    a variable would prove nothing.
    """
    from forgd_verdict.policy import Policy, redacted

    unset = redacted(Policy(raw={"privacy": {"hash_salt": ""},
                                 "compliance": {"api_key": ""}, "server": {}}))
    assert unset["privacy"]["hash_salt"] == ""
    assert unset["compliance"]["api_key"] == ""

    hidden = redacted(Policy(raw={"privacy": {"hash_salt": "s3cr3t"},
                                  "compliance": {"api_key": "sk-ant-api01-x"},
                                  "server": {}}))
    assert hidden["privacy"]["hash_salt"] == "<set>"
    assert hidden["compliance"]["api_key"] == "<redacted>"


def test_the_policy_flag_reaches_the_app_not_just_the_port(monkeypatch, tmp_path):
    """uvicorn imports the factory by string and the factory calls
    `load_policy()` with no argument.

    So `--policy` has to be put in the environment before that import, or
    the process runs on ./policy.yaml while reporting the host and port from
    the file the operator named. It looks honoured and is not -- and in the
    container it is invisible, because the image sets the variable anyway.
    """
    import os
    import sys

    policy_file = tmp_path / "other.yaml"
    policy_file.write_text("privacy:\n  allow_unsalted: true\n"
                           "server:\n  host: 10.0.0.1\n  port: 9999\n")

    seen: dict[str, str | None] = {}

    class FakeUvicorn:
        @staticmethod
        def run(*args, **kwargs):
            seen["policy"] = os.environ.get("FORGD_VERDICT_POLICY")

    # main() sets the variable itself, so monkeypatch records it here, before
    # the first main(); otherwise teardown restores the value main() set.
    monkeypatch.setenv("FORGD_VERDICT_POLICY", "")
    for module in ("forgd_verdict.server.__main__", "forgd_verdict.otel.__main__"):
        monkeypatch.delenv("FORGD_VERDICT_POLICY")
        monkeypatch.setitem(sys.modules, "uvicorn", FakeUvicorn)
        seen.clear()
        mod = __import__(module, fromlist=["main"])
        assert mod.main(["--policy", str(policy_file)]) == 0
        assert seen["policy"] == str(policy_file), module


# -- what the Policy tab may claim about the salt -------------------------


def _salt_policy(tmp_path, value="$FORGD_HASH_SALT"):
    import yaml

    from forgd_verdict.policy import load_policy

    path = tmp_path / "policy.yaml"
    path.write_text(yaml.safe_dump({"privacy": {"hash_salt": value}}))
    return load_policy(str(path))


def test_a_service_that_hashes_reports_an_unset_salt_loudly(tmp_path, monkeypatch):
    """There, an empty salt IS the alarm: excerpt_hash becomes a plain
    sha256 of the matched text, and an SSN is about a billion guesses."""
    from forgd_verdict.policy import redacted

    monkeypatch.delenv("FORGD_HASH_SALT", raising=False)
    out = redacted(_salt_policy(tmp_path))
    assert "UNSET" in out["privacy"]["hash_salt"]


def test_the_dashboard_does_not_claim_the_salt_is_unset(tmp_path, monkeypatch):
    """It is deliberately not given the salt, so it cannot know.

    Saying UNSET there reads as a deployment hashing unsalted, and the
    obvious remedy is to hand the dashboard the salt -- which is exactly
    what the separation forbids, since it reads every finding hash and the
    salt beside them is one compromise for both.
    """
    from forgd_verdict.policy import redacted

    monkeypatch.delenv("FORGD_HASH_SALT", raising=False)
    shown = redacted(_salt_policy(tmp_path), hashes_here=False)["privacy"]["hash_salt"]
    assert "UNSET" not in shown, shown
    assert "not given the salt" in shown, shown


def test_a_resolved_salt_still_reports_set_everywhere(tmp_path, monkeypatch):
    """The distinction is only about what an ABSENT value means."""
    from forgd_verdict.policy import redacted

    monkeypatch.setenv("FORGD_HASH_SALT", "a-real-salt")
    policy = _salt_policy(tmp_path)
    assert redacted(policy)["privacy"]["hash_salt"] == "<set>"
    assert redacted(policy, hashes_here=False)["privacy"]["hash_salt"] == "<set>"


def test_the_salt_value_never_appears_either_way(tmp_path, monkeypatch):
    import json

    from forgd_verdict.policy import redacted

    monkeypatch.setenv("FORGD_HASH_SALT", "super-secret-salt")
    policy = _salt_policy(tmp_path)
    for out in (redacted(policy), redacted(policy, hashes_here=False)):
        assert "super-secret-salt" not in json.dumps(out)


def test_every_credential_shaped_field_is_redacted():
    """A sweep, because the list in policy.py is what goes stale.

    Grepping `r"'token': '"` does not match `'ship_token': ...`, and the
    committed policy.yaml sets no `hook.*` keys and comments out the legacy
    `compliance.api_key`, so sweeping it alone cannot find the values it
    is looking for.

    So the policy is synthetic and fully populated, and the sweep matches
    any key that ends in a credential-shaped word.
    """
    import re

    from forgd_verdict.policy import Policy, redacted

    secrets = {
        "SALT": ("privacy", "hash_salt"),
        "SHIPBEARER": ("hook", "ship_token"),
        "SCANBEARER": ("hook", "scan_token"),
        "LEGACYKEY": ("compliance", "api_key"),
        "MULTIORGKEY": ("compliance", "orgs", "api_key"),
        "METRICSTOK": ("server", "metrics_token"),
        "OTELTOK": ("otel", "orgs", "token"),
        "SINKTOK": ("sinks", "token"),
        "INTAKETOK": ("intake", "clients", "token"),
        "SHAREDHEADER": ("server", "required_headers", "x-forgd-shared"),
        "FORMKEY": ("dashboard", "admins", "form_key"),
        "WORKSPACEKEY": ("managed_agents", "workspaces", "api_key"),
    }
    pol = Policy(raw={
        "privacy": {"hash_salt": "SALT"},
        "hook": {"ship_token": "SHIPBEARER", "scan_token": "SCANBEARER"},
        "compliance": {"api_key": "LEGACYKEY",
                       "orgs": [{"id": "o1", "api_key": "MULTIORGKEY"}]},
        "server": {"metrics_token": "METRICSTOK",
                   "required_headers": {"x-forgd-shared": "SHAREDHEADER"}},
        "dashboard": {"admins": {"form_key": "FORMKEY"}},
        "managed_agents": {"workspaces": [{"key": "w", "api_key": "WORKSPACEKEY"}]},
        "otel": {"orgs": [{"id": "o1", "token": "OTELTOK"}]},
        "sinks": [{"name": "s", "token": "SINKTOK"}],
        "intake": {"clients": [{"name": "dev", "token": "INTAKETOK"}]},
    })
    blob = repr(redacted(pol))

    leaked = sorted(v for v in secrets if v in blob)
    assert not leaked, (
        f"rendered verbatim on the Policy tab: {leaked}. Add the path to "
        "SECRET_PATHS, SECRET_LIST_PATHS or SECRET_MAP_PATHS in policy.py."
    )

    # And the sweep itself, so a NEW credential-shaped key is caught even
    # when nobody remembers to add it to the dict above.
    pattern = r"'(\w*(?:token|api_key|secret|salt|password))': '([^']*)'"
    # The markers `redacted()` uses. `<set>` is hash_salt's: the dashboard
    # is deliberately not given the salt, so it reports presence only.
    markers = ("<redacted>", "<set>", "<unset>", "")
    for key, value in re.findall(pattern, blob):
        assert value in markers or value.endswith(" resolved>"), (
            f"{key} rendered as {value!r}"
        )


def test_a_literal_required_header_value_is_not_rendered():
    import json

    from forgd_verdict.policy import Policy, redacted

    out = redacted(Policy(raw={"server": {"required_headers": {
        "X-Lit": "literal-secret-value"}}}))
    assert "literal-secret-value" not in json.dumps(out)
    assert out["server"]["required_headers"] == {"X-Lit": "<redacted>"}


def test_a_required_header_placeholder_renders_as_written(monkeypatch):
    from forgd_verdict.policy import Policy, redacted

    monkeypatch.setenv("FORGD_SHARED_HEADER", "resolved-header-value")
    out = redacted(Policy(raw={"server": {"required_headers": {
        "x-forgd-shared": "$FORGD_SHARED_HEADER", "x-empty": ""}}}))
    assert out["server"]["required_headers"] == {
        "x-forgd-shared": "$FORGD_SHARED_HEADER", "x-empty": ""}


# Keys read through env_or_literal or usable_secret whose names look like a
# credential but are not one.
NOT_CREDENTIALS = {
    # dashboard.auth.header: the NAME of the identity header a proxy sets.
    "header",
    # privacy.sealing.*.public_key: the public half of a KMS key.
    "public_key",
}
# Resolved as credentials and redacted outside the three tuples.
REDACTED_ELSEWHERE = {
    # server.secrets: a list of plain strings, reported as a count.
    "secrets",
}


def test_every_credential_shaped_key_the_code_resolves_is_redacted():
    """Every `.get("<key>")` passed to env_or_literal or usable_secret in the
    package, and every key passed to the hook's `destination`, with a
    credential-shaped name, is the last part of a path in SECRET_PATHS,
    SECRET_LIST_PATHS or SECRET_MAP_PATHS."""
    import re

    from forgd_verdict.policy import SECRET_LIST_PATHS, SECRET_MAP_PATHS, SECRET_PATHS

    src = pathlib.Path(__file__).resolve().parents[1] / "src" / "forgd_verdict"
    read = set()
    for path in src.rglob("*.py"):
        text = path.read_text(encoding="utf-8")
        read |= set(re.findall(
            r'(?:env_or_literal|usable_secret)\([^\n]*?\.get\(\s*"(\w+)"', text))
        read |= set(re.findall(r'\bdestination\([^,()]+,\s*"(\w+)"', text))
    shaped = {k for k in read
              if re.search(r"(token|key|secret|salt|password|header)s?$", k)}
    covered = ({p[-1] for p in SECRET_PATHS} | {k for _, k in SECRET_LIST_PATHS}
               | {p[-1] for p in SECRET_MAP_PATHS})
    assert {"api_key", "token", "form_key", "ship_token", "scan_token"} <= shaped
    assert sorted(shaped - covered - NOT_CREDENTIALS - REDACTED_ELSEWHERE) == []


def test_every_map_valued_secret_is_redacted_by_value():
    """Each SECRET_MAP_PATHS entry keeps its names and hides literal values."""
    import json

    from forgd_verdict.policy import SECRET_MAP_PATHS, Policy, redacted

    assert ("server", "required_headers") in SECRET_MAP_PATHS
    for path in SECRET_MAP_PATHS:
        raw: dict = {}
        node = raw
        for part in path[:-1]:
            node = node.setdefault(part, {})
        node[path[-1]] = {"name-stays": "value-goes"}
        blob = json.dumps(redacted(Policy(raw=raw)))
        assert "name-stays" in blob and "value-goes" not in blob, path


def test_the_sweep_would_actually_fail_on_a_missed_key():
    """A sweep with a narrower pattern passes against a policy that leaks.

    A test that cannot fail is worse than no test, so this asserts the
    regex matches the shape it is meant to catch.
    """
    import re

    pattern = r"'(\w*(?:token|api_key|secret|salt|password))': '([^']*)'"
    blob = "{'ship_token': 'SHIPBEARER', 'token': 'INTAKETOK'}"
    found = dict(re.findall(pattern, blob))
    assert found == {"ship_token": "SHIPBEARER", "token": "INTAKETOK"}

def test_the_endpoint_is_configurable_from_the_environment_like_the_store_is():
    """`ship_store` had an override and `ship_endpoint` did not.

    So the only shipping destination a project could set from its own
    .claude/settings.json was the direct-to-blob one -- the path that
    needs store credentials on every laptop and makes each one an
    unvalidated writer. The endpoint that exists to avoid that could only
    be reached by editing the shared policy file.
    """
    from forgd_verdict.policy import ENV_OVERRIDES

    for name in ("FORGD_VERDICT_SHIP_ENDPOINT", "FORGD_VERDICT_SHIP_TOKEN"):
        assert name in ENV_OVERRIDES, name
    assert ENV_OVERRIDES["FORGD_VERDICT_SHIP_ENDPOINT"][0] == ("hook", "ship_endpoint")
    assert ENV_OVERRIDES["FORGD_VERDICT_SHIP_TOKEN"][0] == ("hook", "ship_token")


def test_remote_scanning_is_configurable_per_project():
    """Same argument as the shipping pair above.

    policy.yaml is shared and committed, so a `$FORGD_VERDICT_SCAN_*`
    placeholder there turns remote scanning on for every project that
    loads the file. Without an override, one project could not choose it
    for itself.
    """
    from forgd_verdict.policy import ENV_OVERRIDES

    assert ENV_OVERRIDES["FORGD_VERDICT_SCAN_ENDPOINT"][0] == ("hook", "scan_endpoint")
    assert ENV_OVERRIDES["FORGD_VERDICT_SCAN_TOKEN"][0] == ("hook", "scan_token")
    assert ENV_OVERRIDES["FORGD_VERDICT_SCAN_TIMEOUT_MS"] == (("hook", "scan_timeout_ms"), int)


def test_no_env_override_reaches_detectors_or_privacy():
    """Restated next to the two just added. Detection behaviour is not
    environment-tunable, and a shipping override is exactly the kind of
    addition that would breach it by being filed in the same dict."""
    from forgd_verdict.policy import ENV_OVERRIDES

    for name, (path, _) in ENV_OVERRIDES.items():
        assert path[0] not in ("detectors", "privacy", "plugins"), (name, path)


# -- require_signature was a bare bool() ---------------------------------


@pytest.mark.parametrize("src,expected", [
    ("server: {require_signature: true}", True),
    ("server: {require_signature: false}", False),
    ("server: {}", True),
])
def test_require_signature_accepts_an_actual_boolean(src, expected):
    import yaml

    from forgd_verdict.policy import Policy

    assert Policy(raw=yaml.safe_load(src)).require_signature is expected


@pytest.mark.parametrize("src,label", [
    ("server:\n  require_signature:", "a bare key with no value"),
    ("server: {require_signature: 0}", "zero"),
    ('server: {require_signature: ""}', "an empty string"),
    ("server: {require_signature: []}", "an empty list"),
    ("server: {require_signature: {}}", "an empty map"),
])
def test_a_falsy_non_boolean_is_refused(src, label):
    """`bool()` turned every one of these into "off", silently.

    The bare key is the dangerous one: the line LOOKS present. `mode` is
    already validated against an allowlist one property above; this is
    the same treatment.
    """
    import yaml

    from forgd_verdict.policy import Policy

    with pytest.raises(ValueError, match="require_signature"):
        assert Policy(raw=yaml.safe_load(src)).require_signature


def test_a_quoted_false_is_refused_too():
    """Unvalidated in the safe direction as well -- `"false"` is truthy,
    so a plausible typo kept verification on. Both directions are wrong;
    only one was dangerous."""
    import yaml

    from forgd_verdict.policy import Policy

    with pytest.raises(ValueError):
        assert Policy(
            raw=yaml.safe_load('server: {require_signature: "false"}')
        ).require_signature


def test_a_budget_of_zero_is_refused():
    """Zero or less silently drops every tier past T0 on every frame, on
    every adapter. `FORGD_VERDICT_BUDGET_MS` reached it through a bare
    `int()` with nothing checking the result."""
    from forgd_verdict.policy import Policy

    for bad in (0, -1, "nope", None):
        with pytest.raises(ValueError, match="budget_ms"):
            assert Policy(raw={"scan": {"budget_ms": bad}}).budget_ms


def test_a_positive_budget_is_accepted():
    from forgd_verdict.policy import Policy

    assert Policy(raw={"scan": {"budget_ms": 1500}}).budget_ms == 1500


def test_the_committed_policy_holds_no_literal_credential():
    """`deploy/Dockerfile` bakes policy.yaml into a layer.

    Every secret-shaped key in the committed file is a `$VAR` reference,
    so the official image carries no credential -- and a layer survives
    any later edit, so this has to keep being true rather than happen to
    be. `tests/test_org_partition.py` does the same sweep for org UUIDs;
    nothing did it for credentials.
    """
    import re
    from pathlib import Path

    import yaml

    root = Path(__file__).resolve().parents[1]
    raw = yaml.safe_load((root / "policy.yaml").read_text())

    suspicious = []

    def walk(node, path=""):
        if isinstance(node, dict):
            for k, v in node.items():
                walk(v, f"{path}.{k}" if path else str(k))
        elif isinstance(node, list):
            for i, v in enumerate(node):
                walk(v, f"{path}[{i}]")
        elif isinstance(node, str):
            leaf = path.rsplit(".", 1)[-1].split("[")[0]
            # A `$VAR` reference is the only acceptable form. An empty
            # value means "not configured here", which is also fine.
            if (re.search(r"(token|api_key|secret|salt|password)$", leaf)
                    and node and not node.startswith("$")):
                suspicious.append((path, node))

    walk(raw)
    assert not suspicious, (
        f"policy.yaml holds a literal credential: {suspicious}. It is baked "
        "into the image by deploy/Dockerfile and a layer survives any later "
        "edit. Use $ENV_VAR and set it on the service."
    )


def test_policy_yaml_has_no_duplicate_keys():
    """A repeated mapping key is silently the last one.

    Adding `detectors:` to the top of the `otel:` section, where one
    already existed lower down, dropped the new block with no error from
    the loader and no visible difference in the file.
    """
    import yaml

    class _Strict(yaml.SafeLoader):
        pass

    def _no_duplicates(loader, node, deep=False):
        seen = set()
        for key_node, _ in node.value:
            key = loader.construct_object(key_node, deep=deep)
            assert key not in seen, (
                f"policy.yaml line {key_node.start_mark.line + 1}: "
                f"{key!r} is set twice in the same mapping; the first is "
                "discarded without a warning"
            )
            seen.add(key)
        return yaml.SafeLoader.construct_mapping(loader, node, deep)

    _Strict.add_constructor(
        yaml.resolver.BaseResolver.DEFAULT_MAPPING_TAG, _no_duplicates)
    path = pathlib.Path(__file__).resolve().parents[1] / "policy.yaml"
    yaml.load(path.read_text(), Loader=_Strict)


def test_an_env_override_does_not_change_the_module_default(tmp_path, monkeypatch):
    """`_deep_merge` shared DEFAULT_POLICY's nested dicts with every policy
    that did not mention the section, so FORGD_VERDICT_MODE written into
    one policy's `server` changed the default for all later ones."""
    from forgd_verdict.policy import DEFAULT_POLICY, load_policy

    before = DEFAULT_POLICY["server"].get("mode")
    (tmp_path / "policy.json").write_text("{}")
    monkeypatch.setenv("FORGD_VERDICT_MODE", "enforce")
    assert load_policy(tmp_path / "policy.json").mode == "enforce"
    assert DEFAULT_POLICY["server"].get("mode") == before


def test_ci_starts_the_intake_on_the_shipped_policy_unmodified(monkeypatch):
    """ci.yml's intake smoke test sets one variable and expects one
    credential. A rename of the policy's fleet would otherwise first fail in
    CI."""
    from forgd_verdict.intake.verify import verifiers
    from forgd_verdict.policy import load_policy

    root = pathlib.Path(__file__).resolve().parents[1]
    ci = (root / ".github" / "workflows" / "ci.yml").read_text(encoding="utf-8")
    assert '-e FORGD_INTAKE_FLEET_TOKEN="$TOK"' in ci
    assert 'FORGD_POLICY_INLINE_GZ="$(gzip -c policy.yaml | base64 -w0)"' in ci
    monkeypatch.setenv("FORGD_INTAKE_FLEET_TOKEN", "x7Kq2mNp9wRt4vZs8bLcQ3jH6fYd1gAe")  # gitleaks:allow
    monkeypatch.delenv("FORGD_INTAKE_FLEET_TOKEN_PREVIOUS", raising=False)
    assert "-e FORGD_ORG_ID_PRIMARY=" in ci
    monkeypatch.setenv("FORGD_ORG_ID_PRIMARY", "ci-org")
    found = [c.name for v in verifiers(load_policy(str(root / "policy.yaml")))
             for c in v.credentials()]
    assert found == ["laptops"]


def test_a_compliance_key_nothing_reads_is_refused(tmp_path):
    """`compliance.cors_origins` sat in the shipped policy, under a section
    that never reads it, while the collector read `otel.cors_origins`."""
    from forgd_verdict.policy import COMPLIANCE_KEYS, load_policy

    path = tmp_path / "p.yaml"
    path.write_text("compliance:\n  cors_origins: ['*']\n")
    with pytest.raises(ValueError, match=r"compliance has cors_origins.*otel"):
        load_policy(path)
    path.write_text("compliance:\n" + "".join(f"  {k}: null\n" for k in sorted(COMPLIANCE_KEYS)))
    load_policy(path)


def test_the_shipped_policy_has_no_unread_compliance_key():
    from forgd_verdict.policy import load_policy

    raw = load_policy("policy.yaml").raw
    assert "cors_origins" not in raw["compliance"]
    assert raw["otel"]["cors_origins"] == ["*"]


# -- metrics_token went through env_or_literal only ------------------------


@pytest.mark.parametrize("value", ["changeme", "REPLACE_ME", "placeholder-not-yet-issued"])
def test_a_placeholder_metrics_token_leaves_the_endpoint_off(value):
    from forgd_verdict.policy import Policy

    assert Policy(raw={"server": {"metrics_token": value}}).metrics_token is None


def test_a_short_metrics_token_is_refused():
    from forgd_verdict.policy import Policy

    with pytest.raises(ValueError, match="server.metrics_token is 6 characters"):
        _ = Policy(raw={"server": {"metrics_token": "s3kr1t"}}).metrics_token
