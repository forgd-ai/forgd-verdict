"""What the docs, examples and shipped policy say about the hook, the intake
and the chart matches what the code does."""

from __future__ import annotations

import re
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]


def _flat(path: str) -> str:
    return " ".join((ROOT / path).read_text(encoding="utf-8").split())


def test_platform_md_says_the_hook_does_not_take_gitleaks_from_path():
    platform = _flat("docs/PLATFORM.md")
    assert "earlier on the project's `PATH` replaces it" not in platform
    assert ("Set `hook.detectors.gitleaks.binary` to an absolute path. The hook does not "
            "look gitleaks up on `PATH`") in platform
    assert "does not exist, the hook does not run T1" in platform


def test_the_detectors_table_gives_the_hooks_exception_to_path():
    row = next(line for line in (ROOT / "docs/DETECTORS.md").read_text().splitlines()
               if line.startswith("| `binary` |"))
    assert "The hook does not look it up on `PATH`" in row
    assert "`hook.project_overrides: true`" in row


SWEPT = ("deploy", "docs", "README.md", "policy.yaml", "examples")


def _swept_files() -> list[Path]:
    import subprocess

    out = subprocess.run(["git", "ls-files", "--", *SWEPT], cwd=ROOT,
                         capture_output=True, text=True, check=True).stdout.split()
    return [ROOT / p for p in out if (ROOT / p).is_file()]


def test_scan_and_intake_urls_name_an_intake_host():
    """`/scan` and `/intake` are routes of the intake service, not the
    verdict server."""
    wrong = []
    for path in _swept_files():
        try:
            text = path.read_text(encoding="utf-8")
        except UnicodeDecodeError:
            continue
        for m in re.finditer(r"https?://([A-Za-z0-9.-]+)(?::\d+)?/(?:scan|intake)\b", text):
            if not m.group(1).startswith("intake.") and m.group(1) not in ("127.0.0.1", "localhost"):
                wrong.append(f"{path.relative_to(ROOT)}: {m.group(0)}")
    assert not wrong, wrong


def test_platform_md_keeps_the_scan_token_out_of_a_committed_settings_file():
    platform = _flat("docs/PLATFORM.md")
    section = platform[platform.index("### Scanning on the service instead of the laptop"):]
    section = section[:section.index("**A failure is never a decision.**")]
    before_example = section[:section.index('"FORGD_VERDICT_SCAN_TOKEN"')]
    assert "`.claude/settings.local.json`" in before_example
    assert "`.claude/settings.json`" not in before_example
    assert "`hook.project_overrides: true`" in before_example
    assert "deploy/MDM.md#the-fleet-token" in before_example


def test_the_shipped_policy_calls_the_scan_token_the_fleet_token():
    policy = (ROOT / "policy.yaml").read_text(encoding="utf-8")
    [line] = [x for x in policy.splitlines() if x.lstrip("# ").startswith("scan_token:")]
    assert "fleet token" in line and "per-device" not in line, line


def test_the_device_id_format_is_stated_as_the_code_checks_it():
    from forgd_verdict.models import DEVICE_ID

    assert DEVICE_ID.pattern == "d[0-9a-f]{12}"
    for path in ("docs/OVERRIDES.md", "docs/POLICY.md"):
        assert "`d` and 12 lowercase hex characters" in _flat(path), path
    examples = []
    for path in _swept_files():
        if path.suffix in (".md", ".yaml", ".yml"):
            examples += re.findall(r"(?:deny-device|undeny-device|X-Forgd-Device:)\s+(\S+)",
                                   path.read_text(encoding="utf-8"))
    examples = [e for e in examples if not e.startswith("<")]
    assert examples
    for e in examples:
        assert DEVICE_ID.fullmatch(e), e


def test_intake_client_examples_are_agents_and_laptops_go_on_the_fleet():
    values = (ROOT / "deploy/helm/forgd-verdict/values.yaml").read_text(encoding="utf-8")
    assert "#   clients: [invoice-bot]\n" in values
    block = values[values.index("  # NAMES, not tokens. One per intake client"):values.index("  clients: []")]
    assert "`fleet`" in block
    named = []
    for path in _swept_files():
        try:
            text = path.read_text(encoding="utf-8")
        except UnicodeDecodeError:
            continue
        for m in re.finditer(r"clients: \[([^\]]*)\]", text):
            named += [f"{path.relative_to(ROOT)}: {n.strip()}" for n in m.group(1).split(",")
                      if re.search(r"laptop|developer|alice|bob", n)]
    assert not named, named


def _rotation_row(secret: str) -> str:
    table = (ROOT / "docs/OPERATIONS.md").read_text(encoding="utf-8")
    table = table[table.index("## Rotate secrets"):table.index("**Do not rotate the signing secret")]
    [row] = [line for line in table.splitlines() if line.startswith(f"| {secret}")]
    return row


def test_the_rotation_table_rotates_the_fleet_token_through_its_previous_slot():
    row = _rotation_row("fleet token")
    for needle in ("`FORGD_INTAKE_FLEET_TOKEN_PREVIOUS`", "`FORGD_INTAKE_FLEET_TOKEN`",
                   "`secrets.intakeFleetTokenPrevious`", "MDM", "../deploy/MDM.md"):
        assert needle in row, needle
    steps = [row.index(f"{n}. ") for n in (1, 2, 3)]
    assert steps == sorted(steps)
    assert row.index("_PREVIOUS") < row.index("MDM") < row.rindex("Remove")


def test_the_rotation_table_gives_the_otel_overlap_as_a_second_org_name():
    row = _rotation_row("per-org OTel token")
    for needle in ("`orgIds.<name>-next`", "the same UUID", "`secrets.otelTokens.<name>-next`",
                   "$FORGD_OTEL_TOKEN_<NAME>_NEXT", "in one roll", "`org_ids`"):
        assert needle in row, needle


def test_an_otel_alias_renders_a_second_token_for_the_same_org():
    import test_helm_chart

    if test_helm_chart.helm is None:
        pytest.skip("helm is not installed")
    uuid = "00000000-0000-0000-0000-000000000000"
    docs = test_helm_chart.render("--set", f"orgIds.primary-next={uuid}",
                                  "--set", "secrets.otelTokens.primary-next=otok-next")
    [collector] = [d for d in docs if d.get("kind") == "Deployment"
                   and d["metadata"]["name"].endswith("-collector")]
    env = {e["name"]: e for c in collector["spec"]["template"]["spec"]["containers"]
           for e in c.get("env", [])}
    assert env["FORGD_OTEL_TOKEN_PRIMARY"]["valueFrom"]["secretKeyRef"]["key"] == "otel-token-primary"
    assert (env["FORGD_OTEL_TOKEN_PRIMARY_NEXT"]["valueFrom"]["secretKeyRef"]["key"]
            == "otel-token-primary-next")
    ids = {d["name"]: d.get("value") for d in env.values() if d["name"].startswith("FORGD_ORG_ID_")}
    assert ids == {"FORGD_ORG_ID_PRIMARY": uuid, "FORGD_ORG_ID_PRIMARY_NEXT": uuid}


def test_two_otel_entries_for_one_org_both_authenticate_and_one_token_twice_is_refused():
    from forgd_verdict.otel.app import _token_map

    uuid = "00000000-0000-0000-0000-000000000000"
    old, new = "o" * 43, "n" * 43
    orgs = [{"label": "primary", "id": uuid, "token": old},
            {"label": "primary-next", "id": uuid, "token": new}]
    tokens = _token_map({"orgs": orgs})
    assert {t: v["id"] for t, v in tokens.items()} == {old: uuid, new: uuid}
    orgs[0]["token"] = new
    with pytest.raises(ValueError, match="have the same token"):
        _token_map({"orgs": orgs})


KEY_SCOPE = "#which-organizations-a-compliance-access-key-reads"
KEY_SCOPE_URL = "https://platform.claude.com/docs/en/manage-claude/compliance-api-access"
WRONG_SCOPE = re.compile(r"(?i)\*is\* the organi[sz]ation|minted\s+inside\s+one\s+org"
                         r"|reads\s+only\s+that\s+(?:one|org)")


def _key_scope_section() -> str:
    platform = (ROOT / "docs/PLATFORM.md").read_text(encoding="utf-8")
    start = platform.index("### Which organizations a Compliance Access Key reads")
    return " ".join(platform[start:platform.index("\n### ", start + 1)].split())


def test_the_key_scope_has_one_home_that_states_both_scopes_and_what_ingest_does():
    section = _key_scope_section()
    assert KEY_SCOPE_URL in section
    for needle in ("parent organization", "single organization", "cannot be changed",
                   "one single-organization key per `compliance.orgs` entry",
                   "under the entry's `id`", "once under each entry's org"):
        assert needle in section, needle


def test_no_file_says_a_compliance_key_reads_exactly_one_org():
    found = []
    for path in _swept_files():
        try:
            text = path.read_text(encoding="utf-8")
        except UnicodeDecodeError:
            continue
        found += [f"{path.relative_to(ROOT)}: {m.group(0)}" for m in WRONG_SCOPE.finditer(text)]
    assert not found, found


def test_every_other_scope_mention_links_to_the_home():
    for path, count in (("policy.yaml", 1), ("docs/CREDENTIALS.md", 1),
                        ("docs/SECURITY-MODEL.md", 2), ("docs/DESIGN.md", 1),
                        ("docs/OPERATIONS.md", 1)):
        text = (ROOT / path).read_text(encoding="utf-8")
        assert text.count(f"PLATFORM.md{KEY_SCOPE}") >= count, path
    for path in [p for p in _swept_files() if p.suffix == ".md"]:
        text = " ".join(path.read_text(encoding="utf-8").split())
        if path.name != "PLATFORM.md" and "every linked organization" in text:
            assert f"PLATFORM.md{KEY_SCOPE}" in text, path


CLOUD_RUN_NO_DENY = "not available on Cloud Run"


def _paragraph_with(path: str, needle: str) -> str:
    text = (ROOT / path).read_text(encoding="utf-8")
    for block in re.split(r"\n\s*\n", text):
        if needle in block:
            return " ".join(block.split())
    raise AssertionError(f"{needle!r} not in {path}")


@pytest.mark.parametrize(("path", "needle"), [
    ("docs/OVERRIDES.md", "| denied devices (`denied_devices`)"),
    ("docs/PLATFORM.md", "One device is cut off with `forgd-verdict overrides deny-device`"),
    ("docs/PLATFORM.md", "IAP tokens carry no"),
    ("docs/POLICY.md", "`forgd-verdict overrides deny-device`"),
    ("deploy/terraform/README.md", "**Only the dashboard signs in.** Verdict, collector and intake grant"),
])
def test_each_device_deny_mention_says_cloud_run_has_none(path, needle):
    paragraph = _paragraph_with(path, needle)
    assert CLOUD_RUN_NO_DENY in paragraph, paragraph
    assert "rotat" in paragraph and "fleet token" in paragraph, paragraph
    assert "`FORGD_INTAKE_FLEET_TOKEN_PREVIOUS`" in paragraph, paragraph


def test_cloud_run_has_runtime_overrides_off_which_device_deny_needs():
    """The wording above holds only while app-cloudrun refuses dashboard
    admins, so FORGD_OVERRIDES_ENABLED is never set and the intake never
    reads the overrides object."""
    main = (ROOT / "deploy/terraform/modules/app-cloudrun/main.tf").read_text(encoding="utf-8")
    assert "condition     = !var.dashboard_admins_enabled" in main
    assert '"FORGD_OVERRIDES_ENABLED"' not in main and "FORGD_OVERRIDES_ENABLED =" not in main
